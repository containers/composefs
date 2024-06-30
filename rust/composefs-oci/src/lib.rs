use std::ffi::OsString;

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;
use pull::cli_pull;

mod fileutils;
pub mod pull;
pub mod repo;

/// Options for specifying the repository
#[derive(Debug, Parser)]
pub(crate) struct RepoOpts {
    /// Path to the repository
    #[clap(long, value_parser)]
    repo: Utf8PathBuf,
}

/// Options for importing a tar archive.
#[derive(Debug, Parser)]
pub(crate) struct PullOpts {
    #[clap(flatten)]
    repo_opts: RepoOpts,

    /// Image reference
    image: String,
}

/// Toplevel options
#[derive(Debug, Parser)]
#[clap(name = "composefs")]
#[clap(rename_all = "kebab-case")]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Opt {
    /// Pull an image
    Pull(PullOpts),
}

/// Parse the provided arguments and execute.
/// Calls [`clap::Error::exit`] on failure, printing the error message and aborting the program.
pub async fn run_from_iter<I>(args: I) -> Result<()>
where
    I: IntoIterator,
    I::Item: Into<OsString> + Clone,
{
    run_from_opt(Opt::parse_from(args)).await
}

async fn run_from_opt(opt: Opt) -> Result<()> {
    match opt {
        Opt::Pull(opts) => cli_pull(opts).await,
    }
}
