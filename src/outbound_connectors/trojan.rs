use sha2::{Digest, Sha224};
use bytes::{Buf, BufMut};
use std::{fmt::Write, io::{self, Error}};
use tokio::{net::{TcpStream as TokioTcpStream},
                io::{AsyncWriteExt, AsyncWrite}};
use tokio_rustls::{client::TlsStream};

use super::{Address, tls::TlsConnector};

pub struct TrojanConfig {
    pub password: String,
}

const HASH_STR_LEN: usize = 56;
const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

fn passwd_to_hash<T: ToString>(s: T) -> String {
    let mut hasher = Sha224::new();
    hasher.update(&s.to_string().into_bytes());
    let h = hasher.finalize();
    let mut s = String::with_capacity(HASH_STR_LEN);
    for i in h {
        write!(s, "{:02x}", i).unwrap();
    }
    s
}

/// ```plain
/// +-----------------------+---------+----------------+---------+----------+
/// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
/// +-----------------------+---------+----------------+---------+----------+
/// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
/// +-----------------------+---------+----------------+---------+----------+
///
/// where Trojan Request is a SOCKS5-like request:
///
/// +-----+------+----------+----------+
/// | CMD | ATYP | DST.ADDR | DST.PORT |
/// +-----+------+----------+----------+
/// |  1  |  1   | Variable |    2     |
/// +-----+------+----------+----------+
///
/// where:
///
/// o  CMD
/// o  CONNECT X'01'
/// o  UDP ASSOCIATE X'03'
/// o  ATYP address type of following address
/// o  IP V4 address: X'01'
/// o  DOMAINNAME: X'03'
/// o  IP V6 address: X'04'
/// o  DST.ADDR desired destination address
/// o  DST.PORT desired destination port in network octet order
/// ```

enum RequestHeader {
    TcpConnect([u8; HASH_STR_LEN], Address),
    UdpAssociate([u8; HASH_STR_LEN]),
}

impl RequestHeader {
    async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let udp_dummy_addr = Address::new_dummy_address();
        let (hash, addr, cmd) = match self {
            RequestHeader::TcpConnect(hash, addr) => (hash, addr, CMD_TCP_CONNECT),
            RequestHeader::UdpAssociate(hash) => (hash, &udp_dummy_addr, CMD_UDP_ASSOCIATE),
        };

        let header_len = HASH_STR_LEN + 2 + 1 + addr.serialized_len() + 2;
        let mut buf = Vec::with_capacity(header_len);

        let cursor = &mut buf;
        let crlf = b"\r\n";
        cursor.put_slice(hash);
        cursor.put_slice(crlf);
        cursor.put_u8(cmd);
        addr.write_to_buf(cursor);
        cursor.put_slice(crlf);

        w.write(&buf).await?;
        Ok(())
    }
}

pub struct TrojanUdpStream {
    tcp_stream: TlsStream<TokioTcpStream>
}

impl TrojanUdpStream {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> std::io::Result<()> {
        Ok(())
    }

    // async fn read_from(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, Address)> {
    //     Ok(())
    // }
}

pub struct TrojanConnector {
    tls_connector: TlsConnector,
    hash: [u8; HASH_STR_LEN],
}

impl TrojanConnector {
    pub fn new(config: &TrojanConfig, tls_connector: TlsConnector) -> Self {
        let mut hash = [0u8; HASH_STR_LEN];
        passwd_to_hash(&config.password).as_bytes().copy_to_slice(&mut hash);

        Self { tls_connector, hash }
    }

    pub async fn connect_tcp(&self, addr: Address) -> io::Result<TlsStream<TokioTcpStream>> {
        let mut stream = self.tls_connector.connect().await?;
        let header = RequestHeader::TcpConnect(self.hash.clone(), addr);
        header.write_to(&mut stream).await?;
        Ok(stream)
    }

    pub async fn connect_udp(&self, addr: Address) -> io::Result<TrojanUdpStream> {
        let stream = self.tls_connector.connect().await?;
        
        Ok(TrojanUdpStream {
            tcp_stream: stream
        })
    }
}