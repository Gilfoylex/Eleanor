use tun::{Device, AsyncDevice, Configuration as TunConfiguration, Layer};
use smoltcp::{
    iface::{Interface, InterfaceBuilder, Routes, SocketHandle},
    phy::{DeviceCapabilities, Medium},
    socket::{TcpSocket, UdpSocket},
    wire::{IpAddress, IpCidr, Ipv4Address, Ipv6Address, TcpPacket, UdpPacket, IpProtocol},
    time::{Duration as SmolDuration, Instant as SmolInstant},
};
use ipnet::IpNet;
use log::{debug, error, trace};
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::{
    io::{self, ErrorKind},
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    thread,
    time::Duration,
    sync::{atomic::{AtomicBool, Ordering}, Arc}
};

use tokio::{
    io::AsyncReadExt,
    sync::mpsc
};

use byte_string::ByteStr;

mod ip_packet;
mod tcp;
mod virt_device;
mod tun_sockets;
mod redirection;
use tun_sockets::{SocketCreation, TunSocket, TunTransfer, ManagerNotify};
use tcp::TcpTun;
use ip_packet::IpPacket;
use redirection::write_packet_with_pi;

pub struct TunBuilder {
    tun_config: TunConfiguration
}

impl TunBuilder {
    pub fn new() -> TunBuilder {
        TunBuilder {
            tun_config: TunConfiguration::default()
        }
    }

    pub fn address(mut self, addr: IpNet) -> TunBuilder {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
        self
    }

    pub fn name(mut self, name: &str) -> TunBuilder {
        self.tun_config.name(name);
        self
    }

    #[cfg(unix)]
    pub fn file_descriptor(mut self, fd: RawFd) -> TunBuilder {
        self.tun_config.raw_fd(fd);
        self
    }

    pub fn build(mut self) -> io::Result<Tun> {
        let device = match self.build_device() {
            Ok(d) => d,
            Err(tun::Error::Io(err)) => return Err(err),
            Err(err) => return Err(io::Error::new(ErrorKind::Other, err)),
        };

        Ok(
            Tun::new(
                device
            )
        )
    }

    fn build_device(mut self) -> Result<AsyncDevice, tun::Error> {
        self.tun_config.layer(Layer::L3).up();

        #[cfg(target_os = "linux")]
        self.tun_config.platform(|tun_config| {
            tun_config.packet_information(false);
        });

        tun::create_as_async(&self.tun_config)
    }

}

struct SocketManager {
    iface: Interface<'static, virt_device::VirtTunDevice>,
    sockets_map: HashMap<SocketHandle, TunTransfer>,
    socket_creation_rx: mpsc::UnboundedReceiver<SocketCreation>
}

pub struct Tun {
    device: AsyncDevice,
    iface_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    iface_tx: mpsc::UnboundedSender<Vec<u8>>,
    manager_notify: Arc<tun_sockets::ManagerNotify>,
    manager_socket_creation_tx: mpsc::UnboundedSender<SocketCreation>,
    manager_running: Arc<AtomicBool>,
    tcp_tun: TcpTun
}

impl Tun {
    pub fn new(device: AsyncDevice) -> Tun {

        let mtu = device.get_ref().mtu().unwrap_or(1500) as usize;
        let (iface, iface_rx, iface_tx) = Tun::build_iface(mtu);

        let (manager_socket_creation_tx, manager_socket_creation_rx) = mpsc::unbounded_channel();

        let mut manager = SocketManager {
            iface,
            sockets_map: HashMap::new(),
            socket_creation_rx: manager_socket_creation_rx
        };

        let manager_running = Arc::new(AtomicBool::new(true));
        let manager_handle = {
            let manager_running = manager_running.clone();
            
            thread::spawn(move || {
                
                let SocketManager { 
                    ref mut iface, 
                    ref mut sockets_map, 
                    ref mut socket_creation_rx, 
                } = manager;

                while manager_running.load(Ordering::Relaxed) {
                    while let Ok(SocketCreation { control, tun_socket }) = socket_creation_rx.try_recv() {
                        let (handle, tun_transfer) = match tun_socket {
                            TunSocket::TunTcpSocket(tcp_socket) => {
                                let handle = iface.add_socket(tcp_socket);
                                (handle, TunTransfer {
                                    protocol: IpProtocol::Tcp,
                                    control
                                })
                            }
                            TunSocket::TunUdpSocket(udp_socket) => {
                                let handle = iface.add_socket(udp_socket);
                                (handle, TunTransfer {
                                    protocol: IpProtocol::Udp,
                                    control
                                })
                            }
                        };

                        sockets_map.insert(handle, tun_transfer);
                    }

                    let before_poll = SmolInstant::now();
                    let updated_sockets = match iface.poll(before_poll) {
                        Ok(u)=> u,
                        Err(err) => {
                            error!("VirtDevice::poll error: {}", err);
                            false
                        }
                    };

                    if updated_sockets {
                        trace!("VirtDevice::poll costed {}", SmolInstant::now() - before_poll);
                    }

                    // Check all the sockets' status
                    let mut sockets_to_remove = Vec::new();

                    for (socket_handle, tun_transfer) in sockets_map.iter() {
                        match tun_transfer.protocol {
                            //IpProtocol::HopByHop => todo!(),
                            //IpProtocol::Icmp => todo!(),
                            //IpProtocol::Igmp => todo!(),
                            IpProtocol::Tcp => {
                                let handle = socket_handle.clone();
                                let socket = iface.get_socket::<TcpSocket>(handle);
                                //let control = &tun_transfer.control;
                                TcpTun::hanlde_tun_socket(
                                    &mut sockets_to_remove,
                                    handle,
                                     socket, &tun_transfer.control);
                            },
                            IpProtocol::Udp => {

                            },
                            //IpProtocol::Ipv6Route => todo!(),
                            //IpProtocol::Ipv6Frag => todo!(),
                            //IpProtocol::Icmpv6 => todo!(),
                            //IpProtocol::Ipv6NoNxt => todo!(),
                            //IpProtocol::Ipv6Opts => todo!(),
                            //IpProtocol::Unknown(_) => todo!(),
                            _ => {}
                        }
                    }
                
                    for socket_handle in sockets_to_remove {
                        sockets_map.remove(&socket_handle);
                        iface.remove_socket(socket_handle);
                    }
    
                    let next_duration = iface.poll_delay(before_poll).unwrap_or(SmolDuration::from_millis(5));
                    if next_duration != SmolDuration::ZERO {
                        thread::park_timeout(Duration::from(next_duration));
                    }
                }

                trace!("VirtDevice::poll thread exited");
            })
        };

        let manager_notify = Arc::new(ManagerNotify::new(manager_handle.thread().clone()));
        let tcp_tun = TcpTun{
            
        };

        Tun { device, iface_rx, iface_tx, manager_notify, manager_socket_creation_tx, manager_running, tcp_tun}
    }

    pub async fn run(mut self) -> io::Result<()> {
        if let Ok(mtu) = self.device.get_ref().mtu() {
            assert!(mtu > 0 && mtu as usize > 0);
        }

        let mut packet_buffer = vec![0u8; 65536].into_boxed_slice();

        loop {
            tokio::select! {
                n = self.device.read(&mut packet_buffer) => {
                    let n = n?;
                    if n <=0 {
                        continue;
                    }

                    let packet = &mut packet_buffer[..n];
                    if let Err(err) = self.handle_tun_frame(packet).await {
                        error!("[TUN] handle IP frame failed, error: {}", err);
                    }
                }

                packet = self.iface_rx.recv() => {
                    let packet = packet.expect("channel closed unexpectedly");
                    if let Err(err) = write_packet_with_pi(&mut self.device, &packet).await {
                        error!("[TUN] failed to set packet information, error: {}, {:?}", err, ByteStr::new(&packet));
                    } else {
                        trace!("[TUN] sent IP packet (TCP) {:?}", ByteStr::new(&packet));
                    }
                }
            }
        }
    }

    pub async fn drive_interface_state(&mut self, frame: &[u8]) {
        if let Err(..) = self.iface_tx.send(frame.to_vec()) {
            panic!("interface send channel closed unexpectly");
        }

        // Wake up and poll the interface.
        self.manager_notify.notify();
    }

    pub async fn recv_packet(&mut self) -> Vec<u8> {
        match self.iface_rx.recv().await {
            Some(v) => v,
            None => unreachable!("channel closed unexpectedly"),
        }
    }

    async fn handle_tun_frame(&mut self, frame: &[u8]) -> smoltcp::Result<()> {
        let packet = match IpPacket::new_checked(frame)? {
            Some(packet) => packet,
            None => {
                return Ok(());
            }
        };

        match packet.protocol() {
            IpProtocol::Tcp => {
                let tcp_packet = match TcpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        return Ok(());
                    }
                };

                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();

                let src_addr = SocketAddr::new(packet.src_addr(), src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                trace!("[TUN] TCP packet {} -> {} {}", src_addr, dst_addr, tcp_packet);

                // TCP first handshake packet.
                if let Err(err) = TcpTun::handle_packet(self.manager_notify.clone(), &self.manager_socket_creation_tx, src_addr, dst_addr, &tcp_packet).await {
                    error!(
                        "handle TCP packet failed, error: {}, {} <-> {}, packet: {:?}",
                        err, src_addr, dst_addr, tcp_packet
                    );
                }
            },
            IpProtocol::Udp => {
                // let udp_packet = match UdpPacket::new_checked(packet.payload()) {
                //     Ok(p) => p,
                //     Err(err) => {
                //                         error!(
                //                             "invalid UDP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                //                             err,
                //                             packet.src_addr(),
                //                             packet.dst_addr(),
                //                             ByteStr::new(packet.payload())
                //                         );
                //                         return Ok(());
                //                     }
                // };

                // let src_port = udp_packet.src_port();
                // let dst_port = udp_packet.dst_port();

                // let src_addr = SocketAddr::new(packet.src_addr(), src_port);
                // let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                // //let payload = udp_packet.payload();
                // trace!("[TUN] UDP packet {} -> {} {}", src_addr, dst_addr, udp_packet);
            },
            _ => {
                return Ok(());
            }
        }

        // 数据写入虚拟网卡，驱动smoltcp运行
        self.drive_interface_state(frame).await;

        Ok(())
    }

    fn build_iface(mtu: usize) -> (Interface<'static, virt_device::VirtTunDevice>, mpsc::UnboundedReceiver<Vec<u8>>, mpsc::UnboundedSender<Vec<u8>>) {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = mtu;

        let (virt, iface_rx, iface_tx) = virt_device::VirtTunDevice::new(capabilities);
        let iface_builder = InterfaceBuilder::new(virt, vec![]);
        let iface_ipaddrs = [
            IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0),
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0),
        ];

        let mut iface_routes = Routes::new(BTreeMap::new());
        iface_routes
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .expect("IPv4 route");
        iface_routes
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .expect("IPv6 route");

        let iface = iface_builder
            .any_ip(true)
            .ip_addrs(iface_ipaddrs)
            .routes(iface_routes)
            .finalize();

        (iface, iface_rx, iface_tx)
    }

    
}