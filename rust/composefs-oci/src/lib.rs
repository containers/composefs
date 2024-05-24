use std::ffi::OsString;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use cap_std_ext::dirext::CapStdExtDirExt;
use clap::Parser;
use ocidir::cap_std::{
    self,
    fs::{Dir, DirBuilder},
};
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

impl RepoOpts {
    pub(crate) fn open(&self) -> Result<crate::repo::Repo> {
        let repo = self.repo.as_path();
        let d = Dir::open_ambient_dir(repo, cap_std::ambient_authority())
            .with_context(|| format!("Opening {repo}"))?;
        crate::repo::Repo::open(d)
    }
}

/// Options for importing container.
#[derive(Debug, Parser)]
pub(crate) struct PullOpts {
    #[clap(flatten)]
    repo_opts: RepoOpts,

    /// Image reference
    image: String,
}

/// Options for creating a repo
#[derive(Debug, Parser)]
pub(crate) struct CreateOpts {
    #[clap(flatten)]
    repo_opts: RepoOpts,

    /// Require fsverity
    #[clap(long)]
    require_verity: bool,
}

/// Toplevel options
#[derive(Debug, Parser)]
#[clap(name = "composefs")]
#[clap(rename_all = "kebab-case")]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Opt {
    /// Pull an image
    Create(CreateOpts),
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
        Opt::Create(opts) => {
            let repopath = opts.repo_opts.repo.as_path();
            std::fs::create_dir_all(repopath)
                .with_context(|| format!("Creating target dir: {repopath}"))?;
            let repodir = Dir::open_ambient_dir(repopath, cap_std::ambient_authority())?;
            let repo = crate::repo::Repo::init(&repodir, opts.require_verity)?;
            drop(repo);
            Ok(())
        }
        Opt::Pull(opts) => cli_pull(opts).await,
    }
}
