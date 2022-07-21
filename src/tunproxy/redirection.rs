use std::{
    io,
    net::SocketAddr,
    os::unix::io::AsRawFd,
};

use log::{error, trace};

use tokio::{
    net::{TcpSocket},
    io::{AsyncRead, AsyncWrite, copy_bidirectional, AsyncWriteExt}
};

use super::tun_sockets::Connection;

pub async fn handle_redir_client(tun_stream : Connection, peer_addr: SocketAddr, dst_addr: SocketAddr) -> io::Result<()> {
    // Get forward address from socket
    //
    // Try to convert IPv4 mapped IPv6 address for dual-stack mode.
    // if let SocketAddr::V6(ref a) = daddr {
    //     if let Some(v4) = to_ipv4_mapped(a.ip()) {
    //         daddr = SocketAddr::new(IpAddr::from(v4), a.port());
    //     }
    // }
    //let traget_addr = SocketAddr::from(dst_addr);
    return establish_client_tcp_redir(tun_stream, peer_addr, dst_addr).await;
}


/// Established Client Transparent Proxy
///
/// This method must be called after handshaking with client (for example, socks5 handshaking)
async fn establish_client_tcp_redir<'a>(
    mut stream: Connection,
    peer_addr: SocketAddr,
    addr: SocketAddr,
) -> io::Result<()> {
    // let socket = match addr {
    //     SocketAddr::V4(..) => TcpSocket::new_v4()?,
    //     SocketAddr::V6(..) => TcpSocket::new_v6()?,
    // };

    let socket = TcpSocket::new_v4()?;
    set_bindtodevice(&socket, "ens160".as_ref())?;

    let mut remote = socket.connect(addr).await?;
    return establish_tcp_tunnel_bypassed(&mut stream, &mut remote, peer_addr, addr).await;
}

async fn establish_tcp_tunnel_bypassed<P, S>(
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    trace!("established tcp tunnel {} <-> {} bypassed", peer_addr, target_addr);

    match copy_bidirectional(plain, shadow).await {
        Ok((rn, wn)) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed, L2R {} bytes, R2L {} bytes",
                peer_addr,
                target_addr,
                rn,
                wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed with error: {}",
                peer_addr,
                target_addr,
                err
            );
        }
    }

    Ok(())
}

fn set_bindtodevice<S: AsRawFd>(socket: &S, iface: &str) -> io::Result<()> {
    let iface_bytes = iface.as_bytes();

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_bytes.as_ptr() as *const _ as *const libc::c_void,
            iface_bytes.len() as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_BINDTODEVICE error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}


pub async fn write_packet_with_pi<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet).await
}
