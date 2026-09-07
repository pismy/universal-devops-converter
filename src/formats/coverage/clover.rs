//! Clover XML — what PHPUnit (`--coverage-clover`) and Jest's `clover` reporter
//! produce, and the usual coverage format in the PHP world.
//!
//! ```xml
//! <coverage generated="1719410000" clover="3.2.0">
//!   <project timestamp="1719410000" name="All files">
//!     <package name="App">
//!       <file name="Main.php" path="/src/App/Main.php">
//!         <line num="12" type="method" name="run" count="4"/>
//!         <line num="14" type="stmt" count="4"/>
//!         <line num="18" type="cond" truecount="1" falsecount="0"/>
//!         <metrics statements="2" coveredstatements="2" …/>
//!       </file>
//!     </package>
//!   </project>
//! </coverage>
//! ```
//!
//! Two things to know:
//!
//! - The root element is `<coverage>`, **the same as Cobertura**. Detection
//!   tells them apart by the `clover` attribute; getting it wrong is silent,
//!   which is why `detect.rs` special-cases it rather than relying on order.
//! - A `cond` line has exactly two outcomes, true and false. The pivot stores
//!   covered/total, so a line with more than two branches — routine in LCOV —
//!   cannot be written back faithfully and is reported as degraded.

use std::io::Write;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::error::{Error, Result};
use crate::model::coverage::{Branch, CoverageDoc, FileCoverage, Function, Line};
use crate::registry::Doc;
use crate::warn::FormatCtx;
use crate::xml::{attr, get_attr, get_parsed, local_name, xml_error, Attrs, XmlWriter};

const FORMAT: &str = "clover";

pub fn read(input: &[u8], _ctx: &mut FormatCtx) -> Result<Doc> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);

    let mut doc = CoverageDoc::default();
    let mut buffer = Vec::new();
    let mut current: Option<FileCoverage> = None;
    let mut saw_root = false;

    loop {
        match reader
            .read_event_into(&mut buffer)
            .map_err(|e| xml_error(FORMAT, e))?
        {
            Event::Eof => break,
            Event::Start(ref element) | Event::Empty(ref element) => {
                match local_name(element).as_str() {
                    "coverage" => {
                        saw_root = true;
                        // Cobertura roots at <coverage> too. Without this the
                        // file parses to an empty report and exits 0, which is
                        // the one failure mode this project refuses to have.
                        if get_attr(element, "clover").is_none()
                            && get_attr(element, "line-rate").is_some()
                        {
                            return Err(Error::parse(
                                FORMAT,
                                "this is a Cobertura report, not a Clover one (the root has \
                                 `line-rate` and no `clover` attribute)",
                            ));
                        }
                        doc.timestamp = get_parsed(element, "generated");
                    }
                    "project" => {
                        if doc.timestamp.is_none() {
                            doc.timestamp = get_parsed(element, "timestamp");
                        }
                    }
                    "file" => {
                        // Jest puts the basename in `name` and the real path in
                        // `path`; PHPUnit puts the path in `name`.
                        let path = get_attr(element, "path")
                            .or_else(|| get_attr(element, "name"))
                            .map(|p| crate::paths::normalize(&p))
                            .filter(|p| !p.is_empty())
                            .ok_or_else(|| {
                                Error::parse(FORMAT, "<file> element without a name or path")
                            })?;
                        if let Some(previous) = current.replace(FileCoverage::new(path)) {
                            doc.files.push(previous);
                        }
                    }
                    "line" => {
                        if let Some(file) = current.as_mut() {
                            collect_line(element, file);
                        }
                    }
                    _ => {}
                }
            }
            // <file> may be empty or wrap children; close on either.
            Event::End(ref element) if local_name(element) == "file" => {
                if let Some(file) = current.take() {
                    doc.files.push(file);
                }
            }
            _ => {}
        }
        buffer.clear();
    }

    if let Some(file) = current.take() {
        doc.files.push(file);
    }
    if !saw_root {
        return Err(Error::parse(
            FORMAT,
            "no <coverage> root element — this does not look like a Clover report",
        ));
    }

    doc.sort();
    Ok(Doc::Coverage(doc))
}

fn collect_line(element: &BytesStart, file: &mut FileCoverage) {
    let Some(number) = get_parsed::<u32>(element, "num") else {
        return;
    };
    let kind = get_attr(element, "type").unwrap_or_else(|| "stmt".into());

    let (hits, branch) = if kind == "cond" {
        let taken = get_parsed::<u64>(element, "truecount").unwrap_or(0);
        let not_taken = get_parsed::<u64>(element, "falsecount").unwrap_or(0);
        (
            taken + not_taken,
            Some(Branch {
                covered: u32::from(taken > 0) + u32::from(not_taken > 0),
                total: 2,
            }),
        )
    } else {
        (get_parsed::<u64>(element, "count").unwrap_or(0), None)
    };

    if kind == "method" {
        file.functions.push(Function {
            name: get_attr(element, "name").unwrap_or_default(),
            signature: None,
            line: Some(number),
            hits,
        });
    }

    // A method's declaration line is executable too, and consumers count it.
    file.lines.push(Line {
        number,
        hits,
        branch,
    });
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_coverage()?;

    if doc.has_extra_counters() {
        ctx.lossy(
            "clover: JaCoCo instruction/complexity/method counters have no Clover equivalent and \
             were dropped",
        );
    }
    if doc
        .files
        .iter()
        .flat_map(|f| &f.lines)
        .any(|l| l.branch.is_some_and(|b| b.total != 2))
    {
        ctx.degraded(
            "clover: a conditional line has exactly two outcomes, so branches beyond the second \
             were folded into them",
        );
    }

    let mut writer = XmlWriter::new(out);
    writer.declaration()?;
    let timestamp = doc.timestamp.unwrap_or(0);
    writer.open(
        "coverage",
        &vec![
            attr("generated", timestamp),
            attr("clover", concat!("udc-", env!("CARGO_PKG_VERSION"))),
        ],
    )?;
    writer.open(
        "project",
        &vec![attr("timestamp", timestamp), attr("name", "All files")],
    )?;

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

    write_metrics(&mut writer, doc.files.iter(), true)?;
    writer.close("project")?;
    writer.close("coverage")?;
    writer.finish()
}

fn write_package<W: Write>(
    writer: &mut XmlWriter<W>,
    package: &str,
    files: &[FileCoverage],
) -> Result<()> {
    writer.open("package", &vec![attr("name", package)])?;
    for file in files {
        writer.open(
            "file",
            &vec![attr("name", file.file_name()), attr("path", &file.path)],
        )?;
        for line in &file.lines {
            writer.empty("line", &line_attrs(file, line))?;
        }
        write_metrics(writer, std::slice::from_ref(file).iter(), false)?;
        writer.close("file")?;
    }
    write_metrics(writer, files.iter(), false)?;
    writer.close("package")
}

fn line_attrs<'a>(file: &'a FileCoverage, line: &Line) -> Attrs<'a> {
    let mut attrs = vec![attr("num", line.number)];

    if let Some(branch) = line.branch {
        // Two outcomes, and the pivot only knows how many were covered.
        attrs.push(attr("type", "cond"));
        attrs.push(attr("truecount", u32::from(branch.covered >= 1)));
        attrs.push(attr("falsecount", u32::from(branch.covered >= 2)));
        return attrs;
    }

    match file.functions.iter().find(|f| f.line == Some(line.number)) {
        Some(function) => {
            attrs.push(attr("type", "method"));
            attrs.push(attr("name", &function.name));
            attrs.push(attr("count", line.hits));
        }
        None => {
            attrs.push(attr("type", "stmt"));
            attrs.push(attr("count", line.hits));
        }
    }
    attrs
}

/// Clover's `<metrics>`. Consumers read the totals from here rather than
/// recomputing them, so they have to agree with the lines above.
fn write_metrics<'a, W: Write>(
    writer: &mut XmlWriter<W>,
    files: impl Iterator<Item = &'a FileCoverage> + Clone,
    project_level: bool,
) -> Result<()> {
    let (mut statements, mut covered_statements) = (0u64, 0u64);
    let (mut conditionals, mut covered_conditionals) = (0u64, 0u64);
    let (mut methods, mut covered_methods) = (0u64, 0u64);
    let mut classes = 0u64;
    let mut loc = 0u64;

    for file in files.clone() {
        classes += 1;
        loc += file
            .lines
            .iter()
            .map(|l| u64::from(l.number))
            .max()
            .unwrap_or(0);
        methods += file.functions.len() as u64;
        covered_methods += file.functions.iter().filter(|f| f.hits > 0).count() as u64;

        for line in &file.lines {
            match line.branch {
                Some(branch) => {
                    conditionals += u64::from(branch.total);
                    covered_conditionals += u64::from(branch.covered);
                }
                None if file.functions.iter().any(|f| f.line == Some(line.number)) => {}
                None => {
                    statements += 1;
                    covered_statements += u64::from(line.hits > 0);
                }
            }
        }
    }

    let elements = statements + conditionals + methods;
    let covered = covered_statements + covered_conditionals + covered_methods;

    let mut attrs = vec![
        attr("statements", statements),
        attr("coveredstatements", covered_statements),
        attr("conditionals", conditionals),
        attr("coveredconditionals", covered_conditionals),
        attr("methods", methods),
        attr("coveredmethods", covered_methods),
        attr("elements", elements),
        attr("coveredelements", covered),
    ];
    if project_level {
        attrs.insert(0, attr("files", classes));
    }
    attrs.insert(0, attr("classes", classes));
    attrs.insert(0, attr("loc", loc));
    attrs.insert(1, attr("ncloc", loc));

    writer.empty("metrics", &attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHPUNIT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<coverage generated="1719410000" clover="3.2.0">
  <project timestamp="1719410000" name="All files">
    <package name="App">
      <file name="/home/runner/work/acme/src/App/Main.php">
        <class name="Main" namespace="App">
          <metrics complexity="3" methods="1" coveredmethods="1" statements="2" coveredstatements="2"/>
        </class>
        <line num="12" type="method" name="run" visibility="public" complexity="2" crap="2" count="4"/>
        <line num="14" type="stmt" count="4"/>
        <line num="16" type="stmt" count="0"/>
        <line num="18" type="cond" truecount="1" falsecount="0"/>
        <metrics loc="20" ncloc="18" classes="1" methods="1" coveredmethods="1" conditionals="2" coveredconditionals="1" statements="2" coveredstatements="1" elements="5" coveredelements="3"/>
      </file>
    </package>
  </project>
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
    fn reads_statements_methods_and_conditionals() {
        let doc = parse(PHPUNIT);
        assert_eq!(doc.timestamp, Some(1_719_410_000));
        assert_eq!(doc.files.len(), 1);

        let file = &doc.files[0];
        assert_eq!(file.path, "/home/runner/work/acme/src/App/Main.php");
        // The method line counts as an executable line too.
        assert_eq!(file.lines_valid(), 4);
        assert_eq!(file.lines_covered(), 3);
        assert_eq!(
            file.branches(),
            Branch {
                covered: 1,
                total: 2
            }
        );
        assert_eq!(file.functions.len(), 1);
        assert_eq!(file.functions[0].name, "run");
        assert_eq!(file.functions[0].hits, 4);
    }

    #[test]
    fn prefers_the_path_attribute_that_jest_emits() {
        let doc = parse(
            r#"<coverage clover="3.2.0"><project><file name="index.js" path="/abs/src/index.js">
                 <line num="1" type="stmt" count="2"/>
               </file></project></coverage>"#,
        );
        assert_eq!(doc.files[0].path, "/abs/src/index.js");
    }

    #[test]
    fn a_file_may_sit_directly_under_the_project() {
        let doc = parse(
            r#"<coverage clover="3.2.0"><project><file name="a.js">
                 <line num="1" type="stmt" count="1"/>
               </file></project></coverage>"#,
        );
        assert_eq!(doc.files.len(), 1);
    }

    #[test]
    fn rejects_input_without_a_coverage_root() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"<report/>", &mut ctx).is_err());
    }

    #[test]
    fn round_trips_through_the_writer() {
        let doc = parse(PHPUNIT);
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        write(&Doc::Coverage(doc.clone()), &mut buffer, &mut ctx).unwrap();

        let again = parse(&String::from_utf8(buffer).unwrap());
        assert_eq!(again.files[0].lines, doc.files[0].lines);
        assert_eq!(again.files[0].functions, doc.files[0].functions);
        assert_eq!(again.timestamp, doc.timestamp);
    }

    #[test]
    fn reports_branches_that_do_not_fit_two_outcomes() {
        let mut doc = CoverageDoc::default();
        let mut file = FileCoverage::new("a.rs");
        file.lines.push(Line {
            number: 1,
            hits: 3,
            branch: Some(Branch {
                covered: 1,
                total: 4,
            }),
        });
        doc.files.push(file);

        let mut ctx = FormatCtx::new(None);
        write(&Doc::Coverage(doc), &mut Vec::new(), &mut ctx).unwrap();
        assert!(ctx
            .warnings()
            .messages()
            .any(|m| m.contains("two outcomes")));
    }

    #[test]
    fn metrics_agree_with_the_lines_above_them() {
        let doc = parse(PHPUNIT);
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        write(&Doc::Coverage(doc), &mut buffer, &mut ctx).unwrap();
        let xml = String::from_utf8(buffer).unwrap();

        // 2 stmt lines (one covered), 1 method (covered), 1 cond (1 of 2).
        assert!(xml.contains(r#"statements="2""#), "{xml}");
        assert!(xml.contains(r#"coveredstatements="1""#), "{xml}");
        assert!(xml.contains(r#"methods="1""#), "{xml}");
        assert!(xml.contains(r#"conditionals="2""#), "{xml}");
        assert!(xml.contains(r#"coveredconditionals="1""#), "{xml}");
    }
}
