use anyhow::Result;

use crate::PullOpts;

pub async fn pull(
    proxy: &containers_image_proxy::ImageProxy,
    img: &containers_image_proxy::OpenedImage,
) -> Result<()> {
    todo!()
}

pub(crate) async fn cli_pull(opts: PullOpts) -> Result<()> {
    let proxy = containers_image_proxy::ImageProxy::new().await?;
    let img = proxy.open_image(&opts.image).await?;

    todo!()
}
