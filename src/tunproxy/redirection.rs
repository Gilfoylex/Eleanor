use std::{
    io,
    net::SocketAddr,
};

use log::{error, trace};

use tokio::{
    net::{TcpSocket},
    io::{AsyncRead, AsyncWrite, copy_bidirectional, AsyncWriteExt, AsyncReadExt}
};

use super::tun_sockets::TunConnector;
use crate::outbound_connectors::{trojan, tls, Address};

pub async fn handle_redir_client(tun_stream : TunConnector, peer_addr: SocketAddr, dst_addr: SocketAddr) -> io::Result<()> {
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
    mut stream: TunConnector,
    peer_addr: SocketAddr,
    addr: SocketAddr,
) -> io::Result<()> {
    // let socket = match addr {
    //     SocketAddr::V4(..) => TcpSocket::new_v4()?,
    //     SocketAddr::V6(..) => TcpSocket::new_v6()?,
    // };

    //let socket = TcpSocket::new_v4()?;
    //set_bindtodevice(&socket, "ens160".as_ref())?;

    let con = tls::TlsConfig {
        addr: Address::DomainNameAddress(String::from("gilfoylex.tk"), 443),
        sni: String::from("gilfoylex.tk"),
        cipher: None,
        cert: None
    };
    let tls = tls::TlsConnector::new(con)?;
    let con2 = trojan::TrojanConfig { password: String::from("yjxfire")};
    let trojan = trojan::TrojanConnector::new(&con2, tls);
    let mut remote = trojan.connect_tcp(Address::SocketAddress(addr)).await?;
    //let mut remote = socket.connect(addr).await?;

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




pub async fn write_packet_with_pi<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet).await
}
