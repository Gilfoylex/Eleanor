use std::{io, 
    net::{SocketAddr, TcpStream, IpAddr, Ipv4Addr},
    sync::Arc
};

use tokio::{net::{TcpStream as TokioTcpStream, TcpSocket}};
use tokio_rustls::{TlsConnector as TL,
     rustls::{ClientConfig, RootCertStore, OwnedTrustAnchor, ServerName},
     client::TlsStream,
     webpki};
use super::Address;
use super::set_bindtodevice;
use log::debug;


pub struct TlsConfig {
    pub addr: Address,
    pub sni: String,
    pub cipher: Option<Vec<String>>,
    pub cert: Option<String>,
}

pub struct TlsConnector
{
    addr: Address,
    sni: String,
    //tls_connector: TlsConnector
    tls_config: Arc<ClientConfig>,
}

impl TlsConnector {
    pub fn new(config: TlsConfig) -> io::Result<Self> {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                })
        );
        let build = ClientConfig::builder()
                                    .with_safe_defaults()
                                    .with_root_certificates(root_cert_store)
                                    .with_no_client_auth(); // i guess this was previously the default?
        Ok(Self {
            addr: config.addr.clone(),
            sni: config.sni.clone(),
            tls_config: Arc::new(build)
        })
    }

    pub async fn connect(&self) -> io::Result<TlsStream<TokioTcpStream>> {    
        let config = self.tls_config.clone();
        let connector = TL::from(config);
        let socket = TcpSocket::new_v4()?;
        set_bindtodevice(&socket, "ens160".as_ref())?;
        let adr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(199,101,171,149)), 443);
        let t_stream = socket.connect(adr).await?;
        let domain = ServerName::try_from(String::from("gilfoylex.tk").as_ref())
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

        let stream = connector.connect(domain, t_stream).await?;
        // let socket = TcpSocket::new_v4()?;
        // set_bindtodevice(&socket, "ens160".as_ref())?;
        // let adr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(199,101,171,149)), 443);
        // let t_stream = socket.connect(adr).await?;
        // let ret = 
         Ok(stream)
    }
}

