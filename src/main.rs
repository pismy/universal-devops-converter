mod cli;

use std::io::{IsTerminal, Read, Write};

use clap::Parser;

use universal_devops_converter::error::{Error, Result};
use universal_devops_converter::paths::PathMapper;
use universal_devops_converter::registry::{Category, Doc, Selection, FORMATS};
use universal_devops_converter::warn::Warnings;
use universal_devops_converter::{detect, registry};

use cli::{Cli, Command, ConvertArgs, FormatsArgs};

/// stdin/stdout sentinel, per the CLI contract.
const STDIO: &str = "-";

/// `--input-format` value asking for content-based detection.
const AUTO: &str = "auto";

fn main() {
    let cli = Cli::parse();
    let style = Style::detect(cli.no_color);
    init_logging(cli.verbose, style);

    let result = match &cli.command {
        Some(Command::Formats(args)) => list_formats(args, style),
        None => convert(&cli.convert, style),
    };

    if let Err(error) = result {
        eprintln!("{} {error}", style.paint(RED_BOLD, "error:"));
        std::process::exit(1);
    }
}

fn init_logging(verbose: bool, style: Style) {
    let default = if verbose { "debug" } else { "warn" };
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default));
    builder.format_target(false).format_timestamp(None);
    if !style.color {
        builder.write_style(env_logger::WriteStyle::Never);
    }
    builder.init();
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

fn convert(args: &ConvertArgs, style: Style) -> Result<()> {
    let target = resolve_output_format(args)?;
    let writer = target.spec.writer()?;
    let mapper = PathMapper::new(args.source_root.as_deref(), &args.strip_prefix);
    let mut warnings = Warnings::new();

    // Resolve an explicit --input-format up front: a bad selector is a usage
    // error and must be reported before any file is read.
    let declared_input = match args.input_format.eq_ignore_ascii_case(AUTO) {
        true => None,
        false => Some(registry::resolve(&args.input_format)?),
    };

    let mut document: Option<Doc> = None;
    for source in &args.input_file {
        let bytes = read_input(source)?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Err(Error::config(format!("{} is empty", describe(source))));
        }

        let origin = match declared_input {
            Some(selection) => selection,
            // Detection yields a format but never a version: the version an
            // input claims is the document's business, and the readers are
            // tolerant across versions by design.
            None => {
                let spec = detect::detect(&bytes, &describe(source))?;
                Selection {
                    spec,
                    version: spec.default_version,
                    explicit_version: false,
                }
            }
        };
        if origin.spec.shared_category(target.spec).is_none() {
            return Err(Error::config(format!(
                "cannot convert a {} report ('{}') into a {} report ('{}'): \
                 conversion is only defined within a category",
                origin.spec.primary_category(),
                origin.spec.id,
                target.spec.primary_category(),
                target.spec.id
            )));
        }
        log::debug!(
            "reading {} as '{}'",
            describe(source),
            describe_selection(&origin)
        );

        let mut ctx = origin.ctx();
        // Readers whose paths are not repository-relative by nature need to
        // know whether the user has already asked for a rewrite.
        ctx.set_path_rewriting(!mapper.is_noop());
        let parsed = (origin.spec.reader()?)(&bytes, &mut ctx)?;
        warnings.absorb(ctx.into_warnings());

        match document.as_mut() {
            Some(existing) => existing.merge(parsed)?,
            None => document = Some(parsed),
        }
    }

    let mut document = document.ok_or_else(|| Error::config("no input file given"))?;
    document.normalize_paths(&mapper);
    document.sort();

    log::debug!("writing as '{}'", describe_selection(&target));

    // Render into memory first: a failure halfway through must not leave a
    // truncated report behind, and the output path may be one of the inputs.
    let mut rendered = Vec::new();
    let mut ctx = target.ctx();
    writer(&document, &mut rendered, &mut ctx)?;
    warnings.absorb(ctx.into_warnings());
    write_output(&args.output_file, &rendered)?;

    report_warnings(&warnings, style);
    if args.strict && !warnings.is_empty() {
        return Err(Error::Strict {
            count: warnings.len(),
        });
    }
    Ok(())
}

fn resolve_output_format(args: &ConvertArgs) -> Result<Selection> {
    let requested = args.output_format.as_deref().ok_or_else(|| {
        Error::config(
            "--output-format is required. Run `udc formats` to list the supported formats.",
        )
    })?;
    if requested.eq_ignore_ascii_case(AUTO) {
        return Err(Error::config(
            "--output-format cannot be 'auto': the target format must be stated explicitly",
        ));
    }
    registry::resolve(requested)
}

fn describe_selection(selection: &Selection) -> String {
    match selection.version {
        Some(version) => format!(
            "{}{}{version}",
            selection.spec.id,
            registry::VERSION_SEPARATOR
        ),
        None => selection.spec.id.to_string(),
    }
}

fn read_input(source: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if source == STDIO {
        std::io::stdin().lock().read_to_end(&mut bytes)?;
    } else {
        bytes = std::fs::read(source)
            .map_err(|e| Error::config(format!("cannot read '{source}': {e}")))?;
    }
    Ok(bytes)
}

fn write_output(destination: &str, bytes: &[u8]) -> Result<()> {
    if destination == STDIO {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(bytes)?;
        handle.flush()?;
    } else {
        std::fs::write(destination, bytes)
            .map_err(|e| Error::config(format!("cannot write '{destination}': {e}")))?;
    }
    Ok(())
}

fn describe(source: &str) -> String {
    if source == STDIO {
        "stdin".to_string()
    } else {
        format!("'{source}'")
    }
}

/// Notices go to stderr, never stdout: stdout may be carrying the report.
fn report_warnings(warnings: &Warnings, style: Style) {
    for note in warnings.notes() {
        eprintln!(
            "{} {}",
            style.paint(YELLOW_BOLD, note.kind.label()),
            note.message
        );
    }
}

// ---------------------------------------------------------------------------
// `udc formats`
// ---------------------------------------------------------------------------

fn list_formats(args: &FormatsArgs, style: Style) -> Result<()> {
    let categories: Vec<Category> = Category::ALL
        .iter()
        .copied()
        .filter(|c| args.category.is_none_or(|wanted| *c == wanted))
        .filter(|c| FORMATS.iter().any(|f| f.is_in(*c)))
        .collect();

    if categories.is_empty() {
        return Err(Error::config(format!(
            "no format in category '{}'",
            args.category.expect("an empty listing implies a filter")
        )));
    }

    println!(
        "Any format readable in a category can be converted to any writable format of the same\n\
         category. `r` = can be read (input), `w` = can be written (output).\n\
         A versioned format accepts a `{sep}<version>` suffix, e.g. `-t sarif{sep}2.1.0`.\n",
        sep = registry::VERSION_SEPARATOR,
    );

    let width = FORMATS.iter().map(|f| f.id.len()).max().unwrap_or(0);

    for (index, category) in categories.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!(
            "{}",
            style.paint(BOLD, &category.to_string().to_uppercase())
        );

        for format in FORMATS.iter().filter(|f| f.is_in(*category)) {
            let capability = format!(
                "{}{}",
                if format.read.is_some() { "r" } else { "-" },
                if format.write.is_some() { "w" } else { "-" }
            );
            println!(
                "  {:<width$}  {}  {}",
                style.paint(CYAN, format.id),
                capability,
                format.description,
            );

            // A format in several categories is listed under each; say so, so
            // the repetition reads as deliberate.
            let others: Vec<&str> = format
                .categories
                .iter()
                .filter(|c| *c != category)
                .map(|c| c.as_str())
                .collect();
            if !others.is_empty() {
                println!(
                    "  {:<width$}      also a {} format",
                    "",
                    others.join(" and a ")
                );
            }
            if let Some(default) = format.default_version {
                let versions: Vec<String> = format
                    .versions
                    .iter()
                    .map(|v| {
                        if *v == default {
                            format!("{v} (default)")
                        } else {
                            (*v).to_string()
                        }
                    })
                    .collect();
                println!(
                    "  {:<width$}      versions: {} — pin one with `{}{}<version>`",
                    "",
                    versions.join(", "),
                    format.id,
                    registry::VERSION_SEPARATOR,
                );
            }
            if !format.aliases.is_empty() {
                println!(
                    "  {:<width$}      aliases: {}",
                    "",
                    format.aliases.join(", ")
                );
            }
            for (kind, note) in format.write_notes {
                println!(
                    "  {:<width$}      {} {note}",
                    "",
                    style.paint(YELLOW, kind.label())
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal styling
// ---------------------------------------------------------------------------

const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const YELLOW_BOLD: &str = "\x1b[1;33m";
const RED_BOLD: &str = "\x1b[1;31m";

#[derive(Clone, Copy)]
struct Style {
    color: bool,
}

impl Style {
    fn detect(no_color_flag: bool) -> Self {
        Style {
            color: !no_color_flag
                && std::env::var_os("NO_COLOR").is_none()
                && std::io::stderr().is_terminal(),
        }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.color {
            format!("{code}{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}
