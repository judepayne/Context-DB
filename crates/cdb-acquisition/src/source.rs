use cdb_core::id::{ContentHash, Iri};
use cdb_core::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceMediaType {
    PlainText,
    Markdown,
    Pdf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConverterDeclaration {
    pub executable_hash: ContentHash,
    pub version_probe: String,
    pub arguments: Vec<String>,
    pub timeout_millis: u64,
    pub output_byte_limit: usize,
    pub encoding: String,
    pub normalization: String,
}
impl ConverterDeclaration {
    pub fn validate(&self, max_arguments: usize, max_argument_bytes: usize) -> Result<()> {
        if self.version_probe.is_empty()
            || self.version_probe.len() > 1024
            || self.arguments.len() > max_arguments
            || self
                .arguments
                .iter()
                .any(|x| x.len() > max_argument_bytes || x.chars().any(char::is_control))
            || self.timeout_millis == 0
            || self.output_byte_limit == 0
            || self.encoding != "UTF-8"
            || self.normalization.is_empty()
            || self.normalization.len() > 128
        {
            return Err(Error::invalid("invalid converter declaration"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionText {
    pub locator: Iri,
    pub original_object: ContentHash,
    pub text_version: ContentHash,
    pub media_type: SourceMediaType,
    text: String,
    pub converter: Option<ConverterDeclaration>,
}
impl ExtractionText {
    pub fn exact_text(locator: Iri, media_type: SourceMediaType, bytes: Vec<u8>) -> Result<Self> {
        if !matches!(
            media_type,
            SourceMediaType::PlainText | SourceMediaType::Markdown
        ) {
            return Err(Error::invalid("PDF requires distinct converter output"));
        }
        let original_object = ContentHash::of_bytes(&bytes);
        let text = String::from_utf8(bytes).map_err(|_| Error::invalid("source is not UTF-8"))?;
        if text.is_empty() {
            return Err(Error::invalid("empty extraction text"));
        }
        Ok(Self {
            locator,
            original_object: original_object.clone(),
            text_version: original_object,
            media_type,
            text,
            converter: None,
        })
    }

    pub fn converted_pdf_text(
        locator: Iri,
        original: &[u8],
        text: String,
        converter: ConverterDeclaration,
    ) -> Result<Self> {
        let text_version = ContentHash::of_bytes(text.as_bytes());
        Self::converted_pdf_text_with_version(locator, original, text, text_version, converter)
    }

    pub fn converted_pdf_text_with_version(
        locator: Iri,
        original: &[u8],
        text: String,
        text_version: ContentHash,
        converter: ConverterDeclaration,
    ) -> Result<Self> {
        converter.validate(128, 4096)?;
        if text.is_empty() {
            return Err(Error::invalid("empty PDF converter output"));
        }
        if text.len() > converter.output_byte_limit {
            return Err(Error::limit());
        }
        Ok(Self {
            locator,
            original_object: ContentHash::of_bytes(original),
            text_version,
            media_type: SourceMediaType::Pdf,
            text,
            converter: Some(converter),
        })
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_and_markdown_preserve_exact_bytes() {
        let bytes = b"a\r\nb\n".to_vec();
        let source = ExtractionText::exact_text(
            Iri::new("file:///x.md").unwrap(),
            SourceMediaType::Markdown,
            bytes.clone(),
        )
        .unwrap();
        assert_eq!(source.text().as_bytes(), bytes);
        assert_eq!(source.original_object, source.text_version);
    }

    #[test]
    fn pdf_keeps_original_and_text_versions_distinct() {
        let converter = ConverterDeclaration {
            executable_hash: ContentHash::of_bytes(b"exe"),
            version_probe: "tool 1".into(),
            arguments: vec!["--layout".into()],
            timeout_millis: 1000,
            output_byte_limit: 100,
            encoding: "UTF-8".into(),
            normalization: "none".into(),
        };
        let source = ExtractionText::converted_pdf_text(
            Iri::new("file:///x.pdf").unwrap(),
            b"%PDF original",
            "exact output\n".into(),
            converter,
        )
        .unwrap();
        assert_ne!(source.original_object, source.text_version);

        let declared_version = ContentHash::of_bytes(b"converter-bound-text-version");
        let versioned = ExtractionText::converted_pdf_text_with_version(
            Iri::new("file:///x.pdf").unwrap(),
            b"%PDF original",
            "exact output\n".into(),
            declared_version.clone(),
            source.converter.unwrap(),
        )
        .unwrap();
        assert_eq!(versioned.text_version, declared_version);
    }
}
