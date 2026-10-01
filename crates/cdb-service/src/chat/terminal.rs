//! Small line-oriented terminal helpers; no Pi TUI or persisted transcript.
use std::io::{self, BufRead};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum InputEvent {
    Line(String),
    Oversized,
    InvalidEncoding,
    End,
}

/// Drain an oversized line without ever retaining it. EOF after an unterminated
/// final line still delivers that line once; the next call reports End.
pub(crate) fn read_line(reader: &mut impl BufRead, limit: usize) -> io::Result<InputEvent> {
    let mut bytes = Vec::with_capacity(limit.min(1024));
    let mut oversized = false;
    let mut saw_bytes = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if !saw_bytes {
                return Ok(InputEvent::End);
            }
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let length = newline.unwrap_or(available.len());
        saw_bytes |= length != 0 || newline.is_some();
        if !oversized {
            if bytes.len().saturating_add(length) > limit {
                oversized = true;
                bytes.clear();
            } else {
                bytes.extend_from_slice(&available[..length]);
            }
        }
        reader.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
            break;
        }
    }
    if oversized {
        return Ok(InputEvent::Oversized);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(match String::from_utf8(bytes) {
        Ok(line) => InputEvent::Line(line),
        Err(_) => InputEvent::InvalidEncoding,
    })
}

#[derive(Clone, Copy, Default)]
enum Escape {
    #[default]
    None,
    Start,
    Intermediate,
    Csi,
    String,
    StringTerminator,
}

/// Stateful across model chunks, so split OSC/CSI payloads cannot reach the
/// terminal. Only ordinary text, tabs and newlines survive control filtering.
#[derive(Default)]
pub(crate) struct Sanitizer {
    escape: Escape,
}

impl Sanitizer {
    pub(crate) fn push(&mut self, text: &str) -> String {
        let mut output = String::new();
        for ch in text.chars() {
            match self.escape {
                Escape::None => match ch {
                    '\u{1b}' => self.escape = Escape::Start,
                    '\u{9b}' => self.escape = Escape::Csi,
                    '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => {
                        self.escape = Escape::String;
                    }
                    '\n' | '\t' => output.push(ch),
                    ch if !ch.is_control() => output.push(ch),
                    _ => {}
                },
                Escape::Start => {
                    self.escape = match ch {
                        '[' => Escape::Csi,
                        ']' | 'P' | 'X' | '^' | '_' => Escape::String,
                        '\u{1b}' => Escape::Start,
                        ' '..='/' => Escape::Intermediate,
                        _ => Escape::None,
                    };
                }
                Escape::Intermediate => {
                    if ch == '\u{1b}' {
                        self.escape = Escape::Start;
                    } else if ('0'..='~').contains(&ch) {
                        self.escape = Escape::None;
                    }
                }
                Escape::Csi => {
                    if ch == '\u{1b}' {
                        self.escape = Escape::Start;
                    } else if ('@'..='~').contains(&ch) {
                        self.escape = Escape::None;
                    }
                }
                Escape::String => match ch {
                    '\u{7}' | '\u{9c}' => self.escape = Escape::None,
                    '\u{1b}' => self.escape = Escape::StringTerminator,
                    _ => {}
                },
                Escape::StringTerminator => {
                    self.escape = match ch {
                        '\\' | '\u{7}' | '\u{9c}' => Escape::None,
                        '\u{1b}' => Escape::StringTerminator,
                        _ => Escape::String,
                    };
                }
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn input_is_bounded_and_recovers_after_oversize_or_invalid_utf8() {
        let mut reader = BufReader::with_capacity(2, Cursor::new(b"123456\nok\r\n\xff\nlast"));
        assert_eq!(read_line(&mut reader, 4).unwrap(), InputEvent::Oversized);
        assert_eq!(
            read_line(&mut reader, 4).unwrap(),
            InputEvent::Line("ok".into())
        );
        assert_eq!(
            read_line(&mut reader, 4).unwrap(),
            InputEvent::InvalidEncoding
        );
        assert_eq!(
            read_line(&mut reader, 4).unwrap(),
            InputEvent::Line("last".into())
        );
        assert_eq!(read_line(&mut reader, 4).unwrap(), InputEvent::End);
    }

    #[test]
    fn streaming_controls_cannot_escape_across_chunk_boundaries() {
        let mut sanitizer = Sanitizer::default();
        assert_eq!(sanitizer.push("Hi\u{1b}]52;secret"), "Hi");
        assert_eq!(sanitizer.push("\u{1b}"), "");
        assert_eq!(sanitizer.push("\\ Ω\u{1b}["), " Ω");
        assert_eq!(sanitizer.push("31mred\u{1b}[0m\n\t\u{8}"), "red\n\t");
        assert_eq!(sanitizer.push("\u{9d}hidden\u{9c}safe"), "safe");
        assert_eq!(sanitizer.push("\u{1b}("), "");
        assert_eq!(sanitizer.push("Bvisible"), "visible");
    }
}
