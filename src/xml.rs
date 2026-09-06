//! Thin XML helpers shared by the XML readers and writers.
//!
//! Reading goes through `quick-xml`, which does **not** resolve external DTDs
//! or entities. That is a deliberate choice, not an accident: Cobertura reports
//! carry a `<!DOCTYPE … SYSTEM "http://cobertura.sourceforge.net/…">` and a
//! resolving parser would turn every conversion into a network call, and every
//! untrusted report into an XXE / entity-expansion vector.
//!
//! Writing is done by hand rather than through an event writer: the output
//! shapes are small, fixed, and easier to keep readable this way.

use std::io::Write;

use quick_xml::events::{BytesEnd, BytesStart};
use quick_xml::name::QName;

use crate::error::{Error, Result};

/// Attribute list for [`XmlWriter`]. Values are owned because most of them are
/// formatted numbers.
pub type Attrs<'a> = Vec<(&'a str, String)>;

/// Convenience for building an [`Attrs`] entry.
pub fn attr(name: &str, value: impl std::fmt::Display) -> (&str, String) {
    (name, value.to_string())
}

/// Read an attribute of a start/empty tag, with entities unescaped.
pub fn get_attr(element: &BytesStart, name: &str) -> Option<String> {
    element
        .try_get_attribute(name)
        .ok()
        .flatten()
        .and_then(|a| a.unescape_value().ok())
        .map(|v| v.into_owned())
}

/// Same as [`get_attr`], parsed into `T`. A malformed value is treated as
/// absent: reports in the wild carry `line="?"` and `hits=""`, and refusing the
/// whole file over one bad attribute helps nobody.
pub fn get_parsed<T: std::str::FromStr>(element: &BytesStart, name: &str) -> Option<T> {
    get_attr(element, name)?.trim().parse().ok()
}

/// Anything that names an element. Implemented for both tag ends so readers
/// can use one helper for `Start`/`Empty` and `End` events.
pub trait Named {
    fn qname(&self) -> QName<'_>;
}

impl Named for BytesStart<'_> {
    fn qname(&self) -> QName<'_> {
        self.name()
    }
}

impl Named for BytesEnd<'_> {
    fn qname(&self) -> QName<'_> {
        self.name()
    }
}

/// Local name of an element, namespace prefix stripped.
pub fn local_name<N: Named + ?Sized>(element: &N) -> String {
    String::from_utf8_lossy(element.qname().local_name().as_ref()).into_owned()
}

/// Escape a run of text for use in an attribute value or element body, and drop
/// characters XML 1.0 cannot represent at all. Captured stdout in a JUnit
/// report routinely contains raw control bytes; emitting them verbatim produces
/// a file no parser will accept.
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(ch),
            c if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) => {}
            c => out.push(c),
        }
    }
    out
}

/// Minimal indenting XML writer.
pub struct XmlWriter<W: Write> {
    inner: W,
    depth: usize,
}

impl<W: Write> XmlWriter<W> {
    pub fn new(inner: W) -> Self {
        XmlWriter { inner, depth: 0 }
    }

    pub fn declaration(&mut self) -> Result<()> {
        self.line(r#"<?xml version="1.0" encoding="UTF-8"?>"#)
    }

    /// Emit a raw line at the current depth (doctypes, comments).
    pub fn line(&mut self, raw: &str) -> Result<()> {
        self.indent()?;
        writeln!(self.inner, "{raw}")?;
        Ok(())
    }

    pub fn open(&mut self, name: &str, attrs: &Attrs) -> Result<()> {
        self.indent()?;
        write!(self.inner, "<{name}")?;
        self.write_attrs(attrs)?;
        writeln!(self.inner, ">")?;
        self.depth += 1;
        Ok(())
    }

    pub fn empty(&mut self, name: &str, attrs: &Attrs) -> Result<()> {
        self.indent()?;
        write!(self.inner, "<{name}")?;
        self.write_attrs(attrs)?;
        writeln!(self.inner, "/>")?;
        Ok(())
    }

    /// `<name attrs>escaped text</name>` on a single line.
    pub fn text_element(&mut self, name: &str, attrs: &Attrs, text: &str) -> Result<()> {
        self.indent()?;
        write!(self.inner, "<{name}")?;
        self.write_attrs(attrs)?;
        writeln!(self.inner, ">{}</{name}>", escape(text))?;
        Ok(())
    }

    pub fn close(&mut self, name: &str) -> Result<()> {
        self.depth = self.depth.saturating_sub(1);
        self.indent()?;
        writeln!(self.inner, "</{name}>")?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.inner.flush()?;
        Ok(())
    }

    fn write_attrs(&mut self, attrs: &Attrs) -> Result<()> {
        for (name, value) in attrs {
            write!(self.inner, r#" {name}="{}""#, escape(value))?;
        }
        Ok(())
    }

    fn indent(&mut self) -> Result<()> {
        for _ in 0..self.depth {
            self.inner.write_all(b"  ")?;
        }
        Ok(())
    }
}

/// Wrap a `quick-xml` failure into a parse error naming the format, so the user
/// learns *what* we were trying to read, not just that XML broke.
pub fn xml_error(format: &str, err: quick_xml::Error) -> Error {
    Error::parse(format, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_and_drops_control_characters() {
        assert_eq!(escape("a<b>&\"c\'"), "a&lt;b&gt;&amp;&quot;c&apos;");
        assert_eq!(
            escape("keep\ttabs\nand\rnewlines"),
            "keep\ttabs\nand\rnewlines"
        );
        assert_eq!(escape("bell\u{7}here"), "bellhere");
    }

    #[test]
    fn writes_indented_elements() {
        let mut buffer = Vec::new();
        {
            let mut writer = XmlWriter::new(&mut buffer);
            writer.declaration().unwrap();
            writer.open("root", &vec![attr("n", 1)]).unwrap();
            writer.empty("leaf", &vec![attr("v", "x")]).unwrap();
            writer.close("root").unwrap();
            writer.finish().unwrap();
        }
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root n=\"1\">\n  <leaf v=\"x\"/>\n</root>\n"
        );
    }
}
