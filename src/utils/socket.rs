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

        let size: usize = 1 << 20;
        unsafe { setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size as libc::c_int)? };

        unsafe {
            setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                true as libc::c_int,
            )?
        };
    }

    Ok(Arc::new(UdpSocket::from_std(udp_socket)?))
}

unsafe fn setsockopt<T>(
    socket: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: T,
) -> std::io::Result<()>
where
    T: Copy,
{
    let value = &value as *const T as *const libc::c_void;
    cvt(libc::setsockopt(
        socket,
        level,
        name,
        value,
        std::mem::size_of::<T>() as libc::socklen_t,
    ))
}

fn cvt(res: libc::c_int) -> std::io::Result<()> {
    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
