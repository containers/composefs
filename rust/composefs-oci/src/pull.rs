use std::{io::Cursor, sync::Arc};

use anyhow::{Context, Result};
use ocidir::{cap_std::fs::Dir, oci_spec::image::Descriptor, BlobWriter, OciDir};

use crate::PullOpts;

pub(crate) async fn cli_pull(opts: PullOpts) -> Result<()> {
    let repo = opts.repo_opts.open()?;
    let proxy = containers_image_proxy::ImageProxy::new().await?;

    let descriptor = repo.pull(&proxy, &opts.image).await?;
    println!("Imported: {}", descriptor.digest());

    Ok(())
}
