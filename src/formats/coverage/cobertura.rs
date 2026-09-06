//! Cobertura XML — the only coverage format GitLab CI has historically
//! ingested, which makes it the project's primary coverage *sink*.
//!
//! Shape:
//!
//! ```xml
//! <coverage line-rate="…" branch-rate="…" lines-covered="…" …>
//!   <sources><source>.</source></sources>
//!   <packages>
//!     <package name="src">
//!       <classes>
//!         <class name="src.main" filename="src/main.rs">
//!           <methods><method name="f" signature=""><lines>…</lines></method></methods>
//!           <lines><line number="1" hits="1" branch="true" condition-coverage="50% (1/2)"/></lines>
//!         </class>
//!       </classes>
//!     </package>
//!   </packages>
//! </coverage>
//! ```
//!
//! `coverage.py`'s dialect is the same document with a couple of extra
//! attributes, so it is read by this module too.

use std::io::Write;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::{Error, Result};
use crate::model::coverage::{rate, Branch, CoverageDoc, FileCoverage, Function, Line};
use crate::registry::Doc;
use crate::warn::FormatCtx;
use crate::xml::{attr, get_attr, get_parsed, local_name, xml_error, Attrs, XmlWriter};

const FORMAT: &str = "cobertura";

pub fn read(input: &[u8], _ctx: &mut FormatCtx) -> Result<Doc> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);

    let mut doc = CoverageDoc::default();
    let mut buffer = Vec::new();
    let mut current: Option<FileCoverage> = None;
    // `<method>` carries its own `<lines>` block duplicating the class-level
    // one; entering a method suppresses line collection until we leave it.
    let mut method: Option<Function> = None;
    let mut in_source = false;
    let mut saw_root = false;

    loop {
        match reader
            .read_event_into(&mut buffer)
            .map_err(|e| xml_error(FORMAT, e))?
        {
            Event::Eof => break,
            Event::Start(ref element) => match local_name(element).as_str() {
                "coverage" => {
                    saw_root = true;
                    doc.timestamp = get_parsed(element, "timestamp");
                }
                "source" => in_source = true,
                "class" => {
                    let path = get_attr(element, "filename")
                        .map(|p| crate::paths::normalize(&p))
                        .filter(|p| !p.is_empty())
                        .ok_or_else(|| {
                            Error::parse(FORMAT, "<class> element without a `filename`")
                        })?;
                    current = Some(FileCoverage::new(path));
                }
                "method" => {
                    method = Some(Function {
                        name: get_attr(element, "name").unwrap_or_default(),
                        signature: get_attr(element, "signature").filter(|s| !s.is_empty()),
                        line: None,
                        hits: 0,
                    });
                }
                "line" => collect_line(element, &mut method, &mut current),
                _ => {}
            },
            Event::Empty(ref element) => match local_name(element).as_str() {
                "coverage" => saw_root = true,
                "line" => collect_line(element, &mut method, &mut current),
                _ => {}
            },
            Event::End(ref element) => match local_name(element).as_str() {
                "source" => in_source = false,
                "method" => {
                    if let (Some(file), Some(function)) = (current.as_mut(), method.take()) {
                        file.functions.push(function);
                    }
                }
                "class" => {
                    if let Some(file) = current.take() {
                        doc.files.push(file);
                    }
                }
                _ => {}
            },
            Event::Text(text) if in_source => {
                let value = text
                    .unescape()
                    .map_err(|e| xml_error(FORMAT, e))?
                    .trim()
                    .to_string();
                if !value.is_empty() {
                    doc.source_roots.push(value);
                }
            }
            _ => {}
        }
        buffer.clear();
    }

    if !saw_root {
        return Err(Error::parse(
            FORMAT,
            "no <coverage> root element — this does not look like a Cobertura report",
        ));
    }

    // The same file may be split across several <class> elements (inner
    // classes, partial classes); fold them.
    let split = std::mem::take(&mut doc.files);
    for file in split {
        match doc.files.iter().position(|f| f.path == file.path) {
            Some(index) => {
                let mut merged = CoverageDoc {
                    files: vec![doc.files.remove(index)],
                    ..Default::default()
                };
                merged.merge(CoverageDoc {
                    files: vec![file],
                    ..Default::default()
                });
                doc.files.insert(index, merged.files.remove(0));
            }
            None => doc.files.push(file),
        }
    }

    doc.sort();
    Ok(Doc::Coverage(doc))
}

/// Record a `<line>`. Inside a `<method>` the element locates the method
/// instead: Cobertura repeats the class' lines there, and counting them twice
/// would double every file's totals.
fn collect_line(
    element: &quick_xml::events::BytesStart,
    method: &mut Option<Function>,
    current: &mut Option<FileCoverage>,
) {
    let Some(number) = get_parsed::<u32>(element, "number") else {
        return;
    };
    let hits = get_parsed::<u64>(element, "hits").unwrap_or(0);

    match method.as_mut() {
        Some(function) if function.line.is_none() => {
            function.line = Some(number);
            function.hits = hits;
        }
        Some(_) => {}
        None => {
            if let Some(file) = current.as_mut() {
                file.lines.push(Line {
                    number,
                    hits,
                    branch: parse_condition_coverage(element),
                });
            }
        }
    }
}

/// `condition-coverage="50% (1/2)"` → `Branch { covered: 1, total: 2 }`.
/// Falls back to `branch="true"` with no detail, which some producers emit.
fn parse_condition_coverage(element: &quick_xml::events::BytesStart) -> Option<Branch> {
    let is_branch = get_attr(element, "branch")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let raw = get_attr(element, "condition-coverage");

    if let Some(raw) = raw {
        if let Some(fraction) = raw
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
        {
            if let Some((covered, total)) = fraction.0.split_once('/') {
                if let (Ok(covered), Ok(total)) =
                    (covered.trim().parse::<u32>(), total.trim().parse::<u32>())
                {
                    return Some(Branch { covered, total });
                }
            }
        }
    }
    // `branch="true"` alone tells us a branch exists but not how many arms it
    // has: model it as a single condition so the line is not counted as
    // branch-free.
    is_branch.then_some(Branch {
        covered: 0,
        total: 1,
    })
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_coverage()?;

    if doc.has_extra_counters() {
        ctx.lossy(
            "cobertura: JaCoCo instruction/complexity/method counters have no Cobertura equivalent and were dropped",
        );
    }

    let branches = doc.branches();
    let mut writer = XmlWriter::new(out);
    writer.declaration()?;
    writer.line(
        r#"<!DOCTYPE coverage SYSTEM "http://cobertura.sourceforge.net/xml/coverage-04.dtd">"#,
    )?;
    writer.open(
        "coverage",
        &vec![
            attr("line-rate", fmt_rate(doc.line_rate())),
            attr("branch-rate", fmt_rate(doc.branch_rate())),
            attr("lines-covered", doc.lines_covered()),
            attr("lines-valid", doc.lines_valid()),
            attr("branches-covered", branches.covered),
            attr("branches-valid", branches.total),
            attr("complexity", 0),
            attr("version", concat!("udc-", env!("CARGO_PKG_VERSION"))),
            attr("timestamp", doc.timestamp.unwrap_or(0)),
        ],
    )?;

    writer.open("sources", &Attrs::new())?;
    if doc.source_roots.is_empty() {
        writer.text_element("source", &Attrs::new(), ".")?;
    } else {
        for root in &doc.source_roots {
            writer.text_element("source", &Attrs::new(), root)?;
        }
    }
    writer.close("sources")?;

    writer.open("packages", &Attrs::new())?;
    // `doc.sort()` groups files by path, so equal packages are contiguous.
    let mut index = 0;
    while index < doc.files.len() {
        let package = doc.files[index].package();
        let end = doc.files[index..]
            .iter()
            .position(|f| f.package() != package)
            .map_or(doc.files.len(), |offset| index + offset);
        write_package(&mut writer, &package, &doc.files[index..end])?;
        index = end;
    }
    writer.close("packages")?;
    writer.close("coverage")?;
    writer.finish()
}

fn write_package<W: Write>(
    writer: &mut XmlWriter<W>,
    package: &str,
    files: &[FileCoverage],
) -> Result<()> {
    let lines_valid: u64 = files.iter().map(FileCoverage::lines_valid).sum();
    let lines_covered: u64 = files.iter().map(FileCoverage::lines_covered).sum();
    let branches =
        files
            .iter()
            .map(FileCoverage::branches)
            .fold(Branch::default(), |mut acc, b| {
                acc.covered += b.covered;
                acc.total += b.total;
                acc
            });

    writer.open(
        "package",
        &vec![
            attr("name", package),
            attr("line-rate", fmt_rate(rate(lines_covered, lines_valid))),
            attr(
                "branch-rate",
                fmt_rate(rate(u64::from(branches.covered), u64::from(branches.total))),
            ),
            attr("complexity", 0),
        ],
    )?;
    writer.open("classes", &Attrs::new())?;
    for file in files {
        write_class(writer, package, file)?;
    }
    writer.close("classes")?;
    writer.close("package")
}

fn write_class<W: Write>(
    writer: &mut XmlWriter<W>,
    package: &str,
    file: &FileCoverage,
) -> Result<()> {
    let class_name = if package.is_empty() {
        file.stem().to_string()
    } else {
        format!("{package}.{}", file.stem())
    };
    let branches = file.branches();

    writer.open(
        "class",
        &vec![
            attr("name", class_name),
            attr("filename", &file.path),
            attr(
                "line-rate",
                fmt_rate(rate(file.lines_covered(), file.lines_valid())),
            ),
            attr(
                "branch-rate",
                fmt_rate(rate(u64::from(branches.covered), u64::from(branches.total))),
            ),
            attr("complexity", 0),
        ],
    )?;

    if file.functions.is_empty() {
        // The DTD requires the element; keep it self-closing rather than
        // emitting an empty pair.
        writer.empty("methods", &Attrs::new())?;
    } else {
        writer.open("methods", &Attrs::new())?;
        for function in &file.functions {
            writer.open(
                "method",
                &vec![
                    attr("name", &function.name),
                    attr("signature", function.signature.as_deref().unwrap_or("")),
                    attr("line-rate", if function.hits > 0 { "1.0" } else { "0.0" }),
                    attr("branch-rate", "1.0"),
                    // #REQUIRED by coverage-04.dtd, and the pivot has no
                    // complexity to report.
                    attr("complexity", 0),
                ],
            )?;
            writer.open("lines", &Attrs::new())?;
            if let Some(line) = function.line {
                writer.empty(
                    "line",
                    &vec![attr("number", line), attr("hits", function.hits)],
                )?;
            }
            writer.close("lines")?;
            writer.close("method")?;
        }
        writer.close("methods")?;
    }

    writer.open("lines", &Attrs::new())?;
    for line in &file.lines {
        let mut attrs = vec![attr("number", line.number), attr("hits", line.hits)];
        if let Some(branch) = line.branch {
            let percent =
                (rate(u64::from(branch.covered), u64::from(branch.total)) * 100.0).round();
            attrs.push(attr("branch", "true"));
            attrs.push(attr(
                "condition-coverage",
                format!("{percent}% ({}/{})", branch.covered, branch.total),
            ));
        }
        writer.empty("line", &attrs)?;
    }
    writer.close("lines")?;
    writer.close("class")
}

/// Four decimals: enough precision for any realistic file, and stable across
/// runs (no locale, no float noise in the last digits).
fn fmt_rate(value: f64) -> String {
    format!("{value:.4}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<!DOCTYPE coverage SYSTEM "http://cobertura.sourceforge.net/xml/coverage-04.dtd">
<coverage line-rate="0.66" branch-rate="0.5" timestamp="1700000000">
  <sources><source>/builds/acme</source></sources>
  <packages>
    <package name="src">
      <classes>
        <class name="src.main" filename="src/main.rs" line-rate="0.66">
          <methods>
            <method name="main" signature="()V">
              <lines><line number="10" hits="3"/></lines>
            </method>
          </methods>
          <lines>
            <line number="10" hits="3"/>
            <line number="11" hits="0"/>
            <line number="12" hits="3" branch="true" condition-coverage="50% (1/2)"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
"#;

    fn parse(input: &str) -> CoverageDoc {
        let mut ctx = FormatCtx::new(None);
        match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Coverage(doc) => doc,
            _ => panic!("expected a coverage document"),
        }
    }

    #[test]
    fn reads_lines_branches_methods_and_sources() {
        let doc = parse(SAMPLE);
        assert_eq!(doc.timestamp, Some(1_700_000_000));
        assert_eq!(doc.source_roots, vec!["/builds/acme".to_string()]);

        let file = &doc.files[0];
        assert_eq!(file.path, "src/main.rs");
        assert_eq!(file.lines_valid(), 3);
        assert_eq!(file.lines_covered(), 2);
        assert_eq!(
            file.branches(),
            Branch {
                covered: 1,
                total: 2
            }
        );
        assert_eq!(file.functions.len(), 1);
        assert_eq!(file.functions[0].line, Some(10));
        assert_eq!(file.functions[0].hits, 3);
        assert_eq!(file.functions[0].signature.as_deref(), Some("()V"));
    }

    #[test]
    fn method_lines_do_not_leak_into_the_class_line_set() {
        // The method block repeats line 10; it must be counted once.
        assert_eq!(parse(SAMPLE).files[0].lines.len(), 3);
    }

    #[test]
    fn branch_true_without_detail_becomes_a_single_uncovered_condition() {
        let doc = parse(
            r#"<coverage><packages><package name="p"><classes>
                 <class filename="a.rs"><lines>
                   <line number="1" hits="1" branch="true"/>
                 </lines></class></classes></package></packages></coverage>"#,
        );
        assert_eq!(
            doc.files[0].lines[0].branch,
            Some(Branch {
                covered: 0,
                total: 1
            })
        );
    }

    #[test]
    fn rejects_input_without_a_coverage_root() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"<report/>", &mut ctx).is_err());
    }

    #[test]
    fn round_trips_through_the_writer() {
        let doc = parse(SAMPLE);
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        write(&Doc::Coverage(doc.clone()), &mut buffer, &mut ctx).unwrap();

        let again = parse(&String::from_utf8(buffer).unwrap());
        assert_eq!(again.files, doc.files);
    }

    #[test]
    fn groups_files_into_packages_by_directory() {
        let mut doc = CoverageDoc::default();
        doc.files.push(FileCoverage::new("src/a.rs"));
        doc.files.push(FileCoverage::new("src/b.rs"));
        doc.files.push(FileCoverage::new("tests/c.rs"));
        doc.sort();

        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        write(&Doc::Coverage(doc), &mut buffer, &mut ctx).unwrap();
        let xml = String::from_utf8(buffer).unwrap();

        assert_eq!(xml.matches("<package ").count(), 2);
        assert!(xml.contains(r#"<package name="src""#));
        assert!(xml.contains(r#"<package name="tests""#));
    }
}
