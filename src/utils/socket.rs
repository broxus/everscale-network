use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;

pub fn make_udp_socket(port: u16) -> Result<Arc<UdpSocket>> {
    let udp_socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let fd = udp_socket.as_raw_fd();
        let size: libc::c_int = 1 << 20;

        let payload = &size as *const libc::c_int as *const libc::c_void;
        let res = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                payload,
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        };
        if res == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    Ok(Arc::new(UdpSocket::from_std(udp_socket)?))
}
