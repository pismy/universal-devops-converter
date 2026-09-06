use clap::{Args, Parser, Subcommand};

use universal_devops_converter::registry::Category;

#[derive(Parser, Debug)]
#[command(
    name = "udc",
    version,
    about = "Convert DevOps tool reports between equivalent formats.",
    long_about = "udc converts a report produced by one tool into the format another platform \
        expects — a recurring need because CI/CD platforms typically accept a single format per \
        report type, while the ecosystem produces dozens.\n\n\
        Conversion always goes through a canonical model for the report's category (coverage, \
        tests, quality…), so a format is never converted into a format of another category. \
        Whatever a target format cannot express is reported on stderr, and `--strict` turns those \
        losses into a failure.\n\n\
        Examples:\n  \
        udc -i lcov.info -t cobertura -o coverage.xml\n  \
        udc -i report.xml -f jacoco -t cobertura --source-root \"$PWD\"\n  \
        eslint -f checkstyle . | udc -f checkstyle -t codeclimate-gitlab -o gl-code-quality.json\n  \
        udc -i shard1.xml -i shard2.xml -t junit -o merged.xml"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub convert: ConvertArgs,

    /// Enable verbose (debug-level) logging. Overridden by `RUST_LOG` when set.
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Disable ANSI colors. Also respects `NO_COLOR` and auto-disables when
    /// stderr is not a terminal.
    #[arg(long, global = true)]
    pub no_color: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List the supported formats, what they can be read from / written to,
    /// and the information each one loses.
    Formats(FormatsArgs),
}

#[derive(Args, Debug)]
pub struct FormatsArgs {
    /// Restrict the listing to one report category.
    #[arg(long, value_enum)]
    pub category: Option<Category>,
}

#[derive(Args, Debug)]
pub struct ConvertArgs {
    /// Input file, or `-` for stdin. Repeat to merge several reports into one.
    #[arg(
        short = 'i',
        long,
        value_name = "PATH",
        env = "UDC_INPUT_FILE",
        default_value = "-"
    )]
    pub input_file: Vec<String>,

    /// Output file, or `-` for stdout.
    #[arg(
        short = 'o',
        long,
        value_name = "PATH",
        env = "UDC_OUTPUT_FILE",
        default_value = "-"
    )]
    pub output_file: String,

    /// Input format, or `auto` to detect it from the content. Detection never
    /// guesses: an ambiguous input is an error, not a coin flip.
    #[arg(
        short = 'f',
        long,
        value_name = "FORMAT",
        env = "UDC_INPUT_FORMAT",
        default_value = "auto"
    )]
    pub input_format: String,

    /// Output format. Required for a conversion; `auto` is not accepted here.
    #[arg(short = 't', long, value_name = "FORMAT", env = "UDC_OUTPUT_FORMAT")]
    pub output_format: Option<String>,

    /// Root the source paths are relative to. Absolute paths under it are made
    /// relative — the usual fix for LCOV files carrying build-machine paths.
    #[arg(long, value_name = "PATH", env = "UDC_SOURCE_ROOT")]
    pub source_root: Option<String>,

    /// Literal path prefix to strip. Repeatable (or comma-separated); the first
    /// prefix that matches on a path-segment boundary wins.
    #[arg(
        long,
        value_name = "PREFIX",
        env = "UDC_STRIP_PREFIX",
        value_delimiter = ','
    )]
    pub strip_prefix: Vec<String>,

    /// Fail when the conversion loses information instead of warning about it.
    #[arg(long, env = "UDC_STRICT")]
    pub strict: bool,
}
