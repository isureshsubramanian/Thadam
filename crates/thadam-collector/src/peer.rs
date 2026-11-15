#![allow(unsafe_code)]
//! Kernel sender identity: std's `peer_cred` is unstable in Rust 1.99
//! (ADR-011 Decision 3). Keep the socket calls confined to this module.

use std::io;
use std::os::unix::net::UnixStream;

use crate::source::agent::Peer;

#[cfg(target_os = "macos")]
pub fn peer_of(stream: &UnixStream) -> io::Result<Peer> {
    use std::mem::size_of;
    use std::os::fd::AsRawFd;

    // audit_token_t from mach/message.h: eight unsigned 32-bit words. libc has no type.
    #[repr(C)]
    struct AuditToken {
        val: [u32; 8],
    }

    let mut pid: libc::pid_t = 0;
    let mut len = size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: pid and len are initialized, writable, correctly sized socket-option buffers.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<libc::pid_t>() || pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer pid",
        ));
    }
    let mut token = AuditToken { val: [0; 8] };
    let mut len = size_of::<AuditToken>() as libc::socklen_t;
    // SAFETY: token has the C audit_token_t layout; len describes its writable storage.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            (&mut token as *mut AuditToken).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<AuditToken>() || token.val[5] != pid as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer audit token",
        ));
    }
    Ok(Peer {
        pid: pid as u32,
        pidversion: token.val[7],
    })
}

#[cfg(not(target_os = "macos"))]
pub fn peer_of(_stream: &UnixStream) -> io::Result<Peer> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer audit tokens require macOS",
    ))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn accepted_peer_is_this_process() {
        let dir =
            std::env::temp_dir().join(format!("tp-{:08x}", uuid::Uuid::now_v7().as_u128() as u32));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("peer.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let peer = peer_of(&stream).unwrap();
        assert_eq!(peer.pid, std::process::id());
        assert_ne!(peer.pidversion, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
