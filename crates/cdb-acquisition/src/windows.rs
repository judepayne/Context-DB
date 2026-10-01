// Adapted from hmem-runtime/src/fragmenter.rs at
// 16a3e6ebf482b852dd539887292b335a7eb7728a. The deterministic Markdown,
// plain-text, code/config, PDF-text boundary and small-block coalescing behavior
// is retained. CTXQL uses configured limits, document-relative byte windows,
// and no persisted fragment DTOs or neighbor IDs.

use cdb_core::evidence::Utf8Span;
use cdb_core::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowMode {
    Off,
    Auto,
    Always,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentKind {
    Markdown,
    Plain,
    Code,
    Config,
    PdfText,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowConfig {
    pub mode: WindowMode,
    pub target_bytes: usize,
    pub max_bytes: usize,
    pub overlap_bytes: usize,
    pub small_block_bytes: usize,
    pub whole_document_threshold: usize,
    pub hard_document_bytes: usize,
    pub max_blocks: usize,
    pub max_unicode_scalars: usize,
    pub max_lines: usize,
    pub max_windows: usize,
    pub max_total_provider_bytes: usize,
    pub code_lines_per_block: usize,
}

impl WindowConfig {
    pub fn validate(&self) -> Result<()> {
        if self.target_bytes == 0
            || self.max_bytes == 0
            || self.target_bytes > self.max_bytes
            || self.overlap_bytes >= self.max_bytes
            || self.small_block_bytes > self.target_bytes
            || self.whole_document_threshold > self.hard_document_bytes
            || self.whole_document_threshold > self.max_bytes
            || self.max_blocks == 0
            || self.max_unicode_scalars == 0
            || self.max_lines == 0
            || self.max_windows == 0
            || self.code_lines_per_block == 0
        {
            return Err(Error::invalid("invalid window configuration"));
        }
        Ok(())
    }
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            mode: WindowMode::Auto,
            target_bytes: 1024,
            max_bytes: 2048,
            overlap_bytes: 0,
            small_block_bytes: 256,
            whole_document_threshold: 1024,
            hard_document_bytes: 8 * 1024 * 1024,
            max_blocks: 100_000,
            max_unicode_scalars: 4_000_000,
            max_lines: 1_000_000,
            max_windows: 100_000,
            max_total_provider_bytes: 32 * 1024 * 1024,
            code_lines_per_block: 40,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Window {
    pub ordinal: usize,
    pub span: Utf8Span,
    pub kind: DocumentKind,
    pub heading_path: Vec<String>,
    pub block_kind: &'static str,
}

impl Window {
    pub fn text<'a>(&self, document: &'a str) -> Result<&'a str> {
        self.span.select(document)
    }
}

#[derive(Clone)]
struct Line<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

#[derive(Clone)]
struct Block {
    start_line: usize,
    end_line: usize,
    heading_path: Vec<String>,
    kind: &'static str,
    barrier_before: bool,
}

pub fn plan_windows(text: &str, kind: DocumentKind, config: &WindowConfig) -> Result<Vec<Window>> {
    config.validate()?;
    if text.is_empty() {
        return Err(Error::invalid("empty extraction text"));
    }
    if text.len() > config.hard_document_bytes || text.chars().count() > config.max_unicode_scalars
    {
        return Err(Error::limit());
    }
    let lines = line_index(text);
    if lines.len() > config.max_lines {
        return Err(Error::limit());
    }
    if config.mode == WindowMode::Off
        || (config.mode == WindowMode::Auto && text.len() <= config.whole_document_threshold)
    {
        if text.len() > config.max_bytes && config.mode == WindowMode::Off {
            return Err(Error::limit());
        }
        return finish(
            vec![Window {
                ordinal: 0,
                span: Utf8Span::new(0, text.len())?,
                kind,
                heading_path: Vec::new(),
                block_kind: "whole_document",
            }],
            text,
            config,
        );
    }

    let raw = match kind {
        DocumentKind::Markdown => markdown_blocks(text, &lines),
        DocumentKind::Code => line_blocks(&lines, config.code_lines_per_block, "code_block"),
        DocumentKind::Config => line_blocks(&lines, config.code_lines_per_block, "config_section"),
        DocumentKind::Plain | DocumentKind::PdfText => paragraph_blocks(&lines),
    };
    if raw.len() > config.max_blocks {
        return Err(Error::limit());
    }
    let groups = if matches!(kind, DocumentKind::Code | DocumentKind::Config) {
        raw
    } else {
        coalesce(text, &lines, raw, config)
    };
    let mut windows = Vec::new();
    for block in groups {
        let (start, end) = block_span(text, &lines, block.start_line, block.end_line);
        if start == end {
            continue;
        }
        for (piece_start, piece_end) in split_span(text, &lines, start, end, config) {
            windows.push(Window {
                ordinal: windows.len(),
                span: Utf8Span::new(piece_start, piece_end)?,
                kind,
                heading_path: block.heading_path.clone(),
                block_kind: block.kind,
            });
        }
    }
    if windows.is_empty() {
        return Err(Error::invalid("extraction text has no semantic content"));
    }
    finish(windows, text, config)
}

fn finish(windows: Vec<Window>, text: &str, config: &WindowConfig) -> Result<Vec<Window>> {
    if windows.len() > config.max_windows {
        return Err(Error::limit());
    }
    let mut total = 0usize;
    for window in &windows {
        let selected = window.span.select(text)?;
        if selected.len() > config.max_bytes {
            return Err(Error::limit());
        }
        total = total.checked_add(selected.len()).ok_or_else(Error::limit)?;
    }
    if total > config.max_total_provider_bytes {
        return Err(Error::limit());
    }
    Ok(windows)
}

fn line_index(text: &str) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut start = 0;
    for segment in text.split_inclusive('\n') {
        let end = start + segment.len();
        out.push(Line {
            text: segment,
            start,
            end,
        });
        start = end;
    }
    if start < text.len() {
        out.push(Line {
            text: &text[start..],
            start,
            end: text.len(),
        });
    }
    out
}

fn paragraph_blocks(lines: &[Line<'_>]) -> Vec<Block> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, line) in lines.iter().enumerate() {
        if line.text.trim().is_empty() {
            if let Some(s) = start.take() {
                out.push(Block {
                    start_line: s,
                    end_line: i,
                    heading_path: vec![],
                    kind: "paragraph",
                    barrier_before: false,
                });
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push(Block {
            start_line: s,
            end_line: lines.len(),
            heading_path: vec![],
            kind: "paragraph",
            barrier_before: false,
        });
    }
    out
}

fn line_blocks(lines: &[Line<'_>], count: usize, kind: &'static str) -> Vec<Block> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < lines.len() {
        while start < lines.len() && lines[start].text.trim().is_empty() {
            start += 1;
        }
        if start == lines.len() {
            break;
        }
        let mut end = (start + count).min(lines.len());
        while end < lines.len() && !lines[end].text.trim().is_empty() && end - start < count + 10 {
            end += 1;
        }
        out.push(Block {
            start_line: start,
            end_line: end,
            heading_path: vec![],
            kind,
            barrier_before: false,
        });
        start = end;
    }
    out
}

fn markdown_blocks(text: &str, lines: &[Line<'_>]) -> Vec<Block> {
    let mut out = Vec::new();
    let mut headings: Vec<(usize, String)> = Vec::new();
    let mut start = None;
    let mut kind = "paragraph";
    let mut fence = false;
    let mut barrier = false;
    let close = |out: &mut Vec<Block>,
                 start: &mut Option<usize>,
                 end: usize,
                 headings: &[(usize, String)],
                 kind,
                 barrier_before: &mut bool| {
        if let Some(s) = start.take() {
            let (a, b) = block_span(text, lines, s, end);
            if a < b {
                if markdown_has_semantic_text(&text[a..b]) {
                    out.push(Block {
                        start_line: s,
                        end_line: end,
                        heading_path: headings.iter().map(|x| x.1.clone()).collect(),
                        kind,
                        barrier_before: *barrier_before,
                    });
                    *barrier_before = false;
                } else {
                    *barrier_before = true;
                }
            }
        }
    };
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.text.trim();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            if start.is_none() {
                start = Some(i);
                kind = "code_block";
            }
            fence = !fence;
            if !fence {
                close(&mut out, &mut start, i + 1, &headings, kind, &mut barrier);
            }
            continue;
        }
        if fence {
            continue;
        }
        if let Some((level, title)) = markdown_heading(trimmed) {
            close(&mut out, &mut start, i, &headings, kind, &mut barrier);
            while headings.last().is_some_and(|x| x.0 >= level) {
                headings.pop();
            }
            headings.push((level, title));
        } else if trimmed.is_empty() {
            close(&mut out, &mut start, i, &headings, kind, &mut barrier);
        } else if start.is_none() {
            start = Some(i);
            kind = if trimmed.starts_with('|') {
                "table"
            } else if trimmed.starts_with('-')
                || trimmed.starts_with('*')
                || trimmed.starts_with("<li")
            {
                "list_item"
            } else if trimmed.starts_with('<') {
                "html_block"
            } else {
                "paragraph"
            };
        }
    }
    close(
        &mut out,
        &mut start,
        lines.len(),
        &headings,
        kind,
        &mut barrier,
    );
    out
}

fn coalesce(
    text: &str,
    lines: &[Line<'_>],
    blocks: Vec<Block>,
    config: &WindowConfig,
) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    for block in blocks {
        let (start, end) = block_span(text, lines, block.start_line, block.end_line);
        if let Some(prev) = out.last_mut().filter(|_| !block.barrier_before) {
            let (ps, pe) = block_span(text, lines, prev.start_line, prev.end_line);
            let (_, merged_end) = block_span(text, lines, prev.start_line, block.end_line);
            let same = prev.heading_path == block.heading_path;
            let wants = (same && pe - ps < config.target_bytes)
                || pe - ps < config.small_block_bytes
                || end - start < config.small_block_bytes;
            if wants && merged_end - ps <= config.max_bytes {
                prev.end_line = block.end_line;
                if !same {
                    prev.heading_path = common_prefix(&prev.heading_path, &block.heading_path);
                }
                if prev.kind != block.kind {
                    prev.kind = "section";
                }
                continue;
            }
        }
        out.push(block);
    }
    out
}

fn split_span(
    text: &str,
    lines: &[Line<'_>],
    start: usize,
    end: usize,
    config: &WindowConfig,
) -> Vec<(usize, usize)> {
    if end - start <= config.max_bytes {
        return vec![(start, end)];
    }
    let mut out = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let desired = cursor.saturating_add(config.target_bytes).min(end);
        let hard = cursor.saturating_add(config.max_bytes).min(end);
        let mut cut = lines
            .iter()
            .filter(|l| l.end > cursor && l.end <= hard && l.end <= desired)
            .map(|l| l.end)
            .next_back()
            .unwrap_or(desired);
        while cut > cursor && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == cursor {
            cut = hard;
            while cut > cursor && !text.is_char_boundary(cut) {
                cut -= 1;
            }
        }
        if cut == cursor {
            break;
        }
        let piece_start = if out.is_empty() {
            cursor
        } else {
            let floor = cut.saturating_sub(config.max_bytes).max(start);
            let wanted = cursor.saturating_sub(config.overlap_bytes).max(floor);
            next_boundary(text, wanted, cursor)
        };
        out.push((piece_start, cut));
        cursor = cut;
    }
    out
}

fn next_boundary(text: &str, mut pos: usize, ceiling: usize) -> usize {
    while pos < ceiling && !text.is_char_boundary(pos) {
        pos += 1;
    }
    pos
}

fn block_span(
    text: &str,
    lines: &[Line<'_>],
    start_line: usize,
    end_line: usize,
) -> (usize, usize) {
    if start_line >= end_line || start_line >= lines.len() {
        return (0, 0);
    }
    let mut start = lines[start_line].start;
    let mut end = lines[end_line.min(lines.len()) - 1].end;
    while start < end && text.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && text.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

fn common_prefix(a: &[String], b: &[String]) -> Vec<String> {
    a.iter()
        .zip(b)
        .take_while(|(x, y)| x == y)
        .map(|x| x.0.clone())
        .collect()
}

fn markdown_heading(line: &str) -> Option<(usize, String)> {
    let n = line.chars().take_while(|c| *c == '#').count();
    if n == 0 || n > 6 || !line.chars().nth(n).is_some_and(char::is_whitespace) {
        return None;
    }
    let title = line[n..].trim().trim_matches('#').trim();
    (!title.is_empty()).then(|| (n, title.to_owned()))
}

fn markdown_has_semantic_text(text: &str) -> bool {
    let mut cleaned = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        cleaned.push_str(&rest[..start]);
        rest = rest[start + 4..].split_once("-->").map_or("", |x| x.1);
    }
    cleaned.push_str(rest);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    let mut visible = String::new();
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let end = cleaned[i..]
                .find('>')
                .map(|x| i + x + 1)
                .unwrap_or(bytes.len());
            let tag = cleaned[i..end].to_ascii_lowercase();
            if !tag.starts_with("<img") {
                visible.push(' ');
            }
            i = end;
        } else if cleaned[i..].starts_with("![") {
            i += cleaned[i..].find(')').map(|x| x + 1).unwrap_or(2);
        } else {
            let ch = cleaned[i..].chars().next().expect("valid char boundary");
            visible.push(ch);
            i += ch.len_utf8();
        }
    }
    visible.chars().any(char::is_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always() -> WindowConfig {
        WindowConfig {
            mode: WindowMode::Always,
            ..WindowConfig::default()
        }
    }

    #[test]
    fn modes_are_strict() {
        let text = "x".repeat(100);
        let mut c = WindowConfig {
            target_bytes: 32,
            max_bytes: 64,
            small_block_bytes: 16,
            hard_document_bytes: 200,
            whole_document_threshold: 64,
            ..WindowConfig::default()
        };
        c.mode = WindowMode::Off;
        assert!(plan_windows(&text, DocumentKind::Plain, &c).is_err());
        c.mode = WindowMode::Auto;
        assert!(plan_windows(&text, DocumentKind::Plain, &c).unwrap().len() > 1);
        assert_eq!(
            plan_windows(&"x".repeat(50), DocumentKind::Plain, &c).unwrap()[0].span,
            Utf8Span::new(0, 50).unwrap()
        );
        c.mode = WindowMode::Always;
        assert!(plan_windows(&text, DocumentKind::Plain, &c)
            .unwrap()
            .iter()
            .all(|w| w.text(&text).unwrap().len() <= 64));
    }

    #[test]
    fn markdown_coalesces_and_keeps_cross_section_heading() {
        let text =
            "# Title\n\n## Features\n\nA paragraph describing features.\n\n## License\n\nMIT\n";
        let windows = plan_windows(text, DocumentKind::Markdown, &always()).unwrap();
        assert_eq!(windows.len(), 1);
        assert!(windows[0].text(text).unwrap().contains("## License"));
        assert_eq!(windows[0].heading_path, vec!["Title"]);
    }

    #[test]
    fn markdown_image_only_is_barrier() {
        let text = "# T\n\nBefore.\n\n<p><img src=\"x\"></p>\n\nAfter.\n";
        let windows = plan_windows(text, DocumentKind::Markdown, &always()).unwrap();
        assert_eq!(
            windows
                .iter()
                .map(|w| w.text(text).unwrap())
                .collect::<Vec<_>>(),
            vec!["Before.", "After."]
        );
    }

    #[test]
    fn plain_pdf_code_and_config_are_deterministic() {
        let c = always();
        let plain = "one\n\ntwo\n\nthree\n";
        assert_eq!(
            plan_windows(plain, DocumentKind::Plain, &c).unwrap(),
            plan_windows(plain, DocumentKind::PdfText, &c)
                .unwrap()
                .into_iter()
                .map(|mut w| {
                    w.kind = DocumentKind::Plain;
                    w
                })
                .collect::<Vec<_>>()
        );
        let source = (0..90).map(|i| format!("line {i}\n")).collect::<String>();
        assert_eq!(
            plan_windows(&source, DocumentKind::Code, &c).unwrap().len(),
            2
        );
        assert_eq!(
            plan_windows(&source, DocumentKind::Config, &c)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn utf8_overlap_never_splits_scalar_and_windows_are_exact_slices() {
        let text = "é".repeat(100);
        let c = WindowConfig {
            mode: WindowMode::Always,
            target_bytes: 31,
            max_bytes: 40,
            overlap_bytes: 7,
            small_block_bytes: 4,
            whole_document_threshold: 1,
            hard_document_bytes: 1000,
            ..WindowConfig::default()
        };
        let windows = plan_windows(&text, DocumentKind::Plain, &c).unwrap();
        assert!(windows.len() > 1);
        for w in windows {
            assert!(w.text(&text).is_ok());
            assert!(w.text(&text).unwrap().len() <= 40);
        }
    }

    #[test]
    fn literal_crlf_is_not_normalized() {
        let text = "alpha\r\n\r\nbeta\r\n";
        let windows = plan_windows(text, DocumentKind::Plain, &always()).unwrap();
        assert!(windows[0].text(text).unwrap().contains("\r\n\r\n"));
    }
}
