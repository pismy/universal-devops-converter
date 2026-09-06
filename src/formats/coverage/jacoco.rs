//! JaCoCo XML report.
//!
//! JaCoCo's model is bytecode-oriented and does not match the line-hit model of
//! LCOV/Cobertura on two points, both of which the conversion must be honest
//! about:
//!
//! - **No hit counts.** A line is covered or it is not (`ci` > 0). Converting
//!   *from* JaCoCo therefore yields hits of 0 or 1; converting *to* it drops
//!   real hit counts.
//! - **Instruction / complexity / method / class counters** come from bytecode
//!   analysis and cannot be derived from line data. They are carried through a
//!   JaCoCo → JaCoCo conversion and approximated (with a warning) otherwise.
//!
//! ```xml
//! <report name="…">
//!   <package name="com/acme">
//!     <class name="com/acme/App" sourcefilename="App.java">
//!       <method name="main" desc="([Ljava/lang/String;)V" line="10">
//!         <counter type="INSTRUCTION" missed="0" covered="4"/>
//!       </method>
//!     </class>
//!     <sourcefile name="App.java">
//!       <line nr="10" mi="0" ci="4" mb="0" cb="2"/>
//!     </sourcefile>
//!   </package>
//! </report>
//! ```

use std::collections::BTreeMap;
use std::io::Write;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::error::{Error, Result};
use crate::model::coverage::{Branch, Counter, CoverageDoc, FileCoverage, Function, Line};
use crate::registry::Doc;
use crate::warn::FormatCtx;
use crate::xml::{attr, get_attr, get_parsed, local_name, xml_error, Attrs, XmlWriter};

const FORMAT: &str = "jacoco";

/// Where the next `<counter>` element belongs.
#[derive(Clone, PartialEq)]
enum CounterTarget {
    None,
    /// A method, addressed as (file path, index in `functions`).
    Method(String, usize),
    /// A class, whose counters are attributed to its source file.
    Class(String),
}

pub fn read(input: &[u8], _ctx: &mut FormatCtx) -> Result<Doc> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);

    let mut files: BTreeMap<String, FileCoverage> = BTreeMap::new();
    let mut buffer = Vec::new();
    let mut package = String::new();
    let mut source_file: Option<String> = None;
    let mut target = CounterTarget::None;
    let mut saw_root = false;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|e| xml_error(FORMAT, e))?;

        match event {
            Event::Eof => break,
            Event::Start(ref element) | Event::Empty(ref element) => {
                match local_name(element).as_str() {
                    "report" => saw_root = true,
                    "package" => {
                        package = get_attr(element, "name")
                            .unwrap_or_default()
                            .replace('\\', "/");
                    }
                    "class" => {
                        target = match class_path(element, &package) {
                            Some(path) => {
                                files
                                    .entry(path.clone())
                                    .or_insert_with(|| FileCoverage::new(path.clone()));
                                CounterTarget::Class(path)
                            }
                            None => CounterTarget::None,
                        };
                    }
                    "method" => {
                        if let CounterTarget::Class(path) | CounterTarget::Method(path, _) =
                            target.clone()
                        {
                            let file = files
                                .entry(path.clone())
                                .or_insert_with(|| FileCoverage::new(path.clone()));
                            file.functions.push(Function {
                                name: get_attr(element, "name").unwrap_or_default(),
                                signature: get_attr(element, "desc").filter(|s| !s.is_empty()),
                                line: get_parsed(element, "line"),
                                hits: 0,
                            });
                            target = CounterTarget::Method(path, file.functions.len() - 1);
                        }
                    }
                    "sourcefile" => {
                        source_file = get_attr(element, "name").map(|name| {
                            let path = join(&package, &name);
                            files
                                .entry(path.clone())
                                .or_insert_with(|| FileCoverage::new(path.clone()));
                            path
                        });
                        target = CounterTarget::None;
                    }
                    "line" => {
                        if let Some(path) = source_file.as_deref() {
                            if let (Some(file), Some(line)) =
                                (files.get_mut(path), parse_line(element))
                            {
                                file.lines.push(line);
                            }
                        }
                    }
                    "counter" => apply_counter(element, &target, &mut files),
                    _ => {}
                }
            }
            Event::End(ref element) => match local_name(element).as_str() {
                // Leaving a method returns counters to its enclosing class.
                "method" => {
                    if let CounterTarget::Method(path, _) = target.clone() {
                        target = CounterTarget::Class(path);
                    }
                }
                "class" => target = CounterTarget::None,
                "sourcefile" => source_file = None,
                _ => {}
            },
            _ => {}
        }
        buffer.clear();
    }

    if !saw_root {
        return Err(Error::parse(
            FORMAT,
            "no <report> root element — this does not look like a JaCoCo report",
        ));
    }

    let mut doc = CoverageDoc {
        files: files.into_values().collect(),
        ..Default::default()
    };
    doc.sort();
    Ok(Doc::Coverage(doc))
}

/// Path of the source file a `<class>` belongs to. Prefers `sourcefilename`;
/// falls back to the class' own binary name for reports produced without
/// source information.
fn class_path(element: &BytesStart, package: &str) -> Option<String> {
    if let Some(name) = get_attr(element, "sourcefilename") {
        return Some(join(package, &name));
    }
    let binary = get_attr(element, "name")?.replace('\\', "/");
    // `com/acme/App$Inner` → `com/acme/App`
    let outer = binary.split('$').next().unwrap_or(&binary).to_string();
    Some(crate::paths::normalize(&outer))
}

fn join(package: &str, name: &str) -> String {
    let joined = if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}/{name}")
    };
    crate::paths::normalize(&joined)
}

/// `<line nr="10" mi="0" ci="4" mb="0" cb="2"/>`. `ci` is covered instructions,
/// `mb`/`cb` missed/covered branches.
fn parse_line(element: &BytesStart) -> Option<Line> {
    let number = get_parsed::<u32>(element, "nr")?;
    let covered_instructions = get_parsed::<u64>(element, "ci").unwrap_or(0);
    let missed_branches = get_parsed::<u32>(element, "mb").unwrap_or(0);
    let covered_branches = get_parsed::<u32>(element, "cb").unwrap_or(0);

    let total = missed_branches + covered_branches;
    Some(Line {
        number,
        // JaCoCo counts instructions, not executions: the best we can say is
        // "reached at least once".
        hits: u64::from(covered_instructions > 0),
        branch: (total > 0).then_some(Branch {
            covered: covered_branches,
            total,
        }),
    })
}

fn apply_counter(
    element: &BytesStart,
    target: &CounterTarget,
    files: &mut BTreeMap<String, FileCoverage>,
) {
    let Some(kind) = get_attr(element, "type") else {
        return;
    };
    let counter = Counter {
        missed: get_parsed(element, "missed").unwrap_or(0),
        covered: get_parsed(element, "covered").unwrap_or(0),
    };

    match target {
        CounterTarget::Method(path, index) => {
            // A method's own INSTRUCTION counter is the only signal JaCoCo
            // gives about whether it ran.
            if kind == "INSTRUCTION" {
                if let Some(function) = files
                    .get_mut(path)
                    .and_then(|f| f.functions.get_mut(*index))
                {
                    function.hits = u64::from(counter.covered > 0);
                }
            }
        }
        CounterTarget::Class(path) => {
            if let Some(file) = files.get_mut(path) {
                let slot = match kind.as_str() {
                    "INSTRUCTION" => &mut file.counters.instruction,
                    "COMPLEXITY" => &mut file.counters.complexity,
                    "METHOD" => &mut file.counters.method,
                    "CLASS" => &mut file.counters.class,
                    // LINE and BRANCH are recomputed from the lines themselves.
                    _ => return,
                };
                let entry = slot.get_or_insert(Counter::default());
                entry.missed += counter.missed;
                entry.covered += counter.covered;
            }
        }
        CounterTarget::None => {}
    }
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_coverage()?;

    if doc.files.iter().any(|f| f.lines.iter().any(|l| l.hits > 1)) {
        ctx.degraded(
            "jacoco: execution counts were flattened to covered/not-covered (JaCoCo has no hit counter)",
        );
    }
    if !doc.has_extra_counters() && !doc.files.is_empty() {
        ctx.degraded(
            "jacoco: instruction counters were approximated as one instruction per line; complexity, method and class counters are omitted",
        );
    }

    let mut writer = XmlWriter::new(out);
    writer.declaration()?;
    writer.line(r#"<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">"#)?;
    writer.open("report", &vec![attr("name", "udc")])?;

    let mut index = 0;
    while index < doc.files.len() {
        let package = doc.files[index].directory().to_string();
        let end = doc.files[index..]
            .iter()
            .position(|f| f.directory() != package)
            .map_or(doc.files.len(), |offset| index + offset);
        write_package(&mut writer, &package, &doc.files[index..end])?;
        index = end;
    }

    write_counters(&mut writer, doc.files.iter(), true)?;
    writer.close("report")?;
    writer.finish()
}

fn write_package<W: Write>(
    writer: &mut XmlWriter<W>,
    package: &str,
    files: &[FileCoverage],
) -> Result<()> {
    writer.open("package", &vec![attr("name", package)])?;

    // The DTD orders a package as (class*, sourcefile*, counter*).
    for file in files {
        if file.functions.is_empty() {
            continue;
        }
        let class_name = if package.is_empty() {
            file.stem().to_string()
        } else {
            format!("{package}/{}", file.stem())
        };
        writer.open(
            "class",
            &vec![
                attr("name", class_name),
                attr("sourcefilename", file.file_name()),
            ],
        )?;
        for function in &file.functions {
            let mut attrs = vec![
                attr("name", &function.name),
                attr("desc", function.signature.as_deref().unwrap_or("()V")),
            ];
            if let Some(line) = function.line {
                attrs.push(attr("line", line));
            }
            writer.open("method", &attrs)?;
            writer.empty(
                "counter",
                &counter_attrs(
                    "METHOD",
                    Counter {
                        missed: u64::from(function.hits == 0),
                        covered: u64::from(function.hits > 0),
                    },
                ),
            )?;
            writer.close("method")?;
        }
        // Bytecode counters live on <class>: that is where the reader picks
        // them up, so a JaCoCo → JaCoCo conversion keeps them intact.
        write_counters(writer, std::slice::from_ref(file).iter(), false)?;
        writer.close("class")?;
    }

    for file in files {
        writer.open("sourcefile", &vec![attr("name", file.file_name())])?;
        for line in &file.lines {
            let branch = line.branch.unwrap_or_default();
            let covered = line.hits > 0;
            writer.empty(
                "line",
                &vec![
                    attr("nr", line.number),
                    attr("mi", u32::from(!covered)),
                    attr("ci", u32::from(covered)),
                    attr("mb", branch.total - branch.covered),
                    attr("cb", branch.covered),
                ],
            )?;
        }
        write_counters(writer, std::slice::from_ref(file).iter(), true)?;
        writer.close("sourcefile")?;
    }

    write_counters(writer, files.iter(), true)?;
    writer.close("package")
}

/// Emit the counters a consumer needs, recomputing LINE and BRANCH from the
/// pivot and passing through the bytecode counters when the source had them.
///
/// `synthesize_instruction` fills in an INSTRUCTION counter (one instruction
/// per line) when the source had none, because consumers key off it for the
/// overall percentage. It is left off at `<class>` level so that a re-read does
/// not mistake the approximation for real bytecode data.
fn write_counters<'a, W: Write>(
    writer: &mut XmlWriter<W>,
    files: impl Iterator<Item = &'a FileCoverage> + Clone,
    synthesize_instruction: bool,
) -> Result<()> {
    let mut instruction: Option<Counter> = None;
    let mut complexity: Option<Counter> = None;
    let mut method: Option<Counter> = None;
    let mut class: Option<Counter> = None;
    let mut line = Counter::default();
    let mut branch = Counter::default();
    let mut synthetic_instruction = Counter::default();

    for file in files {
        let covered = file.lines_covered();
        let valid = file.lines_valid();
        line.covered += covered;
        line.missed += valid - covered;
        synthetic_instruction.covered += covered;
        synthetic_instruction.missed += valid - covered;

        let file_branch = file.branches();
        branch.covered += u64::from(file_branch.covered);
        branch.missed += u64::from(file_branch.total - file_branch.covered);

        accumulate(&mut instruction, file.counters.instruction);
        accumulate(&mut complexity, file.counters.complexity);
        accumulate(&mut method, file.counters.method);
        accumulate(&mut class, file.counters.class);
    }

    if let Some(instruction) =
        instruction.or(synthesize_instruction.then_some(synthetic_instruction))
    {
        writer.empty("counter", &counter_attrs("INSTRUCTION", instruction))?;
    }
    if branch.total() > 0 {
        writer.empty("counter", &counter_attrs("BRANCH", branch))?;
    }
    writer.empty("counter", &counter_attrs("LINE", line))?;
    if let Some(complexity) = complexity {
        writer.empty("counter", &counter_attrs("COMPLEXITY", complexity))?;
    }
    if let Some(method) = method {
        writer.empty("counter", &counter_attrs("METHOD", method))?;
    }
    if let Some(class) = class {
        writer.empty("counter", &counter_attrs("CLASS", class))?;
    }
    Ok(())
}

fn accumulate(target: &mut Option<Counter>, extra: Option<Counter>) {
    if let Some(extra) = extra {
        let slot = target.get_or_insert(Counter::default());
        slot.missed += extra.missed;
        slot.covered += extra.covered;
    }
}

fn counter_attrs(kind: &'static str, counter: Counter) -> Attrs<'static> {
    vec![
        attr("type", kind),
        attr("missed", counter.missed),
        attr("covered", counter.covered),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="acme">
  <package name="com/acme">
    <class name="com/acme/App" sourcefilename="App.java">
      <method name="main" desc="([Ljava/lang/String;)V" line="10">
        <counter type="INSTRUCTION" missed="0" covered="4"/>
      </method>
      <counter type="INSTRUCTION" missed="2" covered="4"/>
      <counter type="COMPLEXITY" missed="1" covered="1"/>
      <counter type="METHOD" missed="0" covered="1"/>
      <counter type="CLASS" missed="0" covered="1"/>
    </class>
    <sourcefile name="App.java">
      <line nr="10" mi="0" ci="4" mb="0" cb="0"/>
      <line nr="11" mi="2" ci="0" mb="0" cb="0"/>
      <line nr="12" mi="0" ci="3" mb="1" cb="1"/>
    </sourcefile>
  </package>
</report>
"#;

    fn parse(input: &str) -> CoverageDoc {
        let mut ctx = FormatCtx::new(None);
        match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Coverage(doc) => doc,
            _ => panic!("expected a coverage document"),
        }
    }

    #[test]
    fn maps_package_and_sourcefile_to_a_path() {
        let doc = parse(SAMPLE);
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.files[0].path, "com/acme/App.java");
    }

    #[test]
    fn instruction_coverage_becomes_binary_hits() {
        let file = &parse(SAMPLE).files[0];
        assert_eq!(file.lines[0].hits, 1);
        assert_eq!(file.lines[1].hits, 0);
        assert_eq!(
            file.branches(),
            Branch {
                covered: 1,
                total: 2
            }
        );
    }

    #[test]
    fn carries_bytecode_counters_and_method_hits() {
        let file = &parse(SAMPLE).files[0];
        assert_eq!(
            file.counters.instruction,
            Some(Counter {
                missed: 2,
                covered: 4
            })
        );
        assert_eq!(
            file.counters.complexity,
            Some(Counter {
                missed: 1,
                covered: 1
            })
        );
        assert_eq!(file.functions[0].name, "main");
        assert_eq!(file.functions[0].hits, 1);
    }

    #[test]
    fn round_trips_lines_and_counters() {
        let doc = parse(SAMPLE);
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        write(&Doc::Coverage(doc.clone()), &mut buffer, &mut ctx).unwrap();

        let again = parse(&String::from_utf8(buffer).unwrap());
        assert_eq!(again.files[0].lines, doc.files[0].lines);
        assert_eq!(again.files[0].counters, doc.files[0].counters);
        assert!(ctx.warnings().is_empty(), "a JaCoCo source loses nothing");
    }

    #[test]
    fn warns_when_hit_counts_have_to_be_flattened() {
        let mut doc = CoverageDoc::default();
        let mut file = FileCoverage::new("a.rs");
        file.lines.push(Line {
            number: 1,
            hits: 7,
            branch: None,
        });
        doc.files.push(file);

        let mut ctx = FormatCtx::new(None);
        write(&Doc::Coverage(doc), &mut Vec::new(), &mut ctx).unwrap();
        assert!(ctx.warnings().messages().any(|w| w.contains("hit counter")));
    }

    #[test]
    fn rejects_input_without_a_report_root() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"<coverage/>", &mut ctx).is_err());
    }
}
