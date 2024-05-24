//! # Bindings for libcomposefs
//!
//! This crate contains a few manually maintained system bindings for libcomposefs.
pub const LCFS_SHA256_DIGEST_LEN: usize = 32;

extern "C" {
    pub fn lcfs_compute_fsverity_from_fd(
        digest: *mut u8,
        fd: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
    #[cfg(feature = "v1_0_4")]
    pub fn lcfs_fd_enable_fsverity(fd: std::os::raw::c_int) -> std::os::raw::c_int;
}

/// Convert an integer return value into a `Result`.
pub fn map_result(r: std::os::raw::c_int) -> std::io::Result<()> {
    match r {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::io::{Seek, Write};
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    #[cfg(feature = "v1_0_4")]
    fn test_fd_enable_fsverity() -> Result<()> {
        // We can't require fsverity in our test suite, so just verify we can call the
        // function.
        let mut tf = tempfile::NamedTempFile::new()?;
        tf.write_all(b"hello")?;
        let tf = std::fs::File::open(tf.path())?;
        let _ = unsafe { lcfs_fd_enable_fsverity(tf.as_raw_fd()) };
        Ok(())
    }

    #[test]
    fn test_digest() -> Result<()> {
        unsafe {
            let mut tf = tempfile::tempfile()?;
            tf.write_all(b"hello world")?;
            let mut buf = [0u8; LCFS_SHA256_DIGEST_LEN];
            tf.seek(std::io::SeekFrom::Start(0))?;
            let r = lcfs_compute_fsverity_from_fd(buf.as_mut_ptr(), tf.as_raw_fd());
            assert_eq!(r, 0);
            assert_eq!(
                buf,
                [
                    30, 46, 170, 66, 2, 215, 80, 164, 17, 116, 238, 69, 73, 112, 185, 44, 27, 194,
                    249, 37, 177, 227, 80, 118, 216, 199, 213, 245, 99, 98, 186, 100
                ]
            );
            Ok(())
        }
    }
}
