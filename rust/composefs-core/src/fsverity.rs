//! # Bindings for computing fsverity
//!
//! This collection of APIs is for computing fsverity digests as
//! used by composefs.

use std::os::fd::{AsRawFd, BorrowedFd};

use composefs_sys::{map_result, LCFS_SHA256_DIGEST_LEN};

/// The binary composefs digest
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Digest([u8; LCFS_SHA256_DIGEST_LEN]);

impl Digest {
    /// Create an uninitialized digest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Retrieve the digest bytes
    pub fn get(&self) -> &[u8; LCFS_SHA256_DIGEST_LEN] {
        &self.0
    }
}

/// Compute the composefs fsverity digest from the provided file descriptor.
#[allow(unsafe_code)]
pub fn fsverity_digest_from_fd(fd: BorrowedFd, digest: &mut Digest) -> std::io::Result<()> {
    unsafe {
        map_result(composefs_sys::lcfs_compute_fsverity_from_fd(
            digest.0.as_mut_ptr(),
            fd.as_raw_fd(),
        ))
    }
}

/// Enable fsverity on the provided file descriptor.  This function is not idempotent;
/// it is an error if fsverity is already enabled.
#[allow(unsafe_code)]
#[cfg(feature = "v1_0_4")]
pub fn fsverity_enable(fd: BorrowedFd) -> std::io::Result<()> {
    unsafe { map_result(composefs_sys::lcfs_fd_enable_fsverity(fd.as_raw_fd())) }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::io::{Seek, Write};
    use std::os::fd::AsFd;

    use super::*;

    #[test]
    fn test_digest() -> Result<()> {
        let mut tf = tempfile::tempfile()?;
        tf.write_all(b"hello world")?;
        let mut digest = Digest::new();
        tf.seek(std::io::SeekFrom::Start(0))?;
        fsverity_digest_from_fd(tf.as_fd(), &mut digest)?;
        assert_eq!(
            digest.get(),
            &[
                30, 46, 170, 66, 2, 215, 80, 164, 17, 116, 238, 69, 73, 112, 185, 44, 27, 194, 249,
                37, 177, 227, 80, 118, 216, 199, 213, 245, 99, 98, 186, 100
            ]
        );
        Ok(())
    }
}
