use std::{
    net::SocketAddr,
    io::ErrorKind,
    sync::Arc
};

use spin::Mutex as SpinMutex;

use smoltcp::{
    storage::RingBuffer,
    wire::TcpPacket,
    iface::SocketHandle, 
    socket::{TcpSocket, TcpState, TcpSocketBuffer},
    time::Duration as SmolDuration,
};

use log::{error, trace};
use tokio::{
    sync::mpsc::UnboundedSender
};

use super::tun_sockets::{SocketControl, SharedConnectionControl, Connection, ManagerNotify, SocketCreation, TunSocket};
use super::redirection::handle_redir_client;

// NOTE: Default buffer could contain 20 AEAD packets
const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 0x3FFF * 20;
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 0x3FFF * 20;

pub struct TcpTun {
}

impl TcpTun {
    pub async fn handle_packet(
        manager_notify: Arc<ManagerNotify>, manager_socket_creation_tx: &UnboundedSender<SocketCreation>,
        src_addr: SocketAddr, dst_addr: SocketAddr, tcp_packet: &TcpPacket<&[u8]>) -> std::io::Result<()> {
        // TCP first handshake packet, create a new Connection
        if tcp_packet.syn() && !tcp_packet.ack() {
            let send_buffer_size = DEFAULT_TCP_SEND_BUFFER_SIZE;
            let recv_buffer_size = DEFAULT_TCP_RECV_BUFFER_SIZE;
            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; recv_buffer_size as usize]),
                TcpSocketBuffer::new(vec![0u8; send_buffer_size as usize]),
            );

            socket.set_keep_alive(Some(SmolDuration::from_millis(1000)));
            // FIXME: It should follow system's setting. 7200 is Linux's default.
            socket.set_timeout(Some(SmolDuration::from_secs(7200)));
            // NO ACK delay
            // socket.set_ack_delay(None);

            if let Err(err) = socket.listen(dst_addr) {
                return Err(std::io::Error::new(ErrorKind::Other, err));
            }

            trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

            let control = Arc::new(SpinMutex::new(SocketControl {
                send_buffer: RingBuffer::new(vec![0u8; send_buffer_size as usize]),
                send_waker: None,
                recv_buffer: RingBuffer::new(vec![0u8; recv_buffer_size as usize]),
                recv_waker: None,
                is_closed: false,
            }));

            let _ = manager_socket_creation_tx.send(SocketCreation {
                control: control.clone(),
                tun_socket: TunSocket::TunTcpSocket(socket) 
            });

            let connection = Connection {
                control, 
                manager_notify: manager_notify
            };

            tokio::spawn(async move {
                if let Err(err) = handle_redir_client(connection, src_addr, dst_addr).await {
                    error!("TCP tunnel failure, {} <-> {}, error: {}", src_addr, dst_addr, err);
                }
            });
        }
        Ok(())
    }

    pub fn hanlde_tun_socket(remove_sockets: &mut Vec<SocketHandle>, socket_handle : SocketHandle, tcp_socket: &mut TcpSocket, control: &SharedConnectionControl) {
        let mut control = control.lock();
        #[inline]
        fn close_socket_control(scoket_control: &mut SocketControl) {
            scoket_control.is_closed = true;
            if let Some(waker) = scoket_control.send_waker.take() {
                waker.wake();
            }
            if let Some(waker) = scoket_control.recv_waker.take() {
                waker.wake();
            }
        }

        if !tcp_socket.is_open() || tcp_socket.state() == TcpState::Closed {
            close_socket_control(&mut *control);
            return
        }

        if control.is_closed {
            // Close the socket.
            tcp_socket.close();
            // sockets_to_remove.push(socket_handle);
            // close_socket_control(&mut *control);
            return
        }

        // Check if readable
        let mut has_received = false;
        while tcp_socket.can_recv() && !control.recv_buffer.is_full() {
            let result = tcp_socket.recv(|buffer| {
                let n = control.recv_buffer.enqueue_slice(buffer);
                (n, ())
            });

            match result {
                Ok(..) => {
                    has_received = true;
                }
                Err(err) => {
                    error!("socket recv error: {}", err);
                    remove_sockets.push(socket_handle);
                    close_socket_control(&mut *control);
                    break;
                }
            }
        }

        if has_received && control.recv_waker.is_some() {
            if let Some(waker) = control.recv_waker.take() {
                waker.wake();
            }
        }

        // Check if writable
        let mut has_sent = false;
        while tcp_socket.can_send() && !control.send_buffer.is_empty() {
            let result = tcp_socket.send(|buffer| {
                let n = control.send_buffer.dequeue_slice(buffer);
                (n, ())
            });

            match result {
                Ok(..) => {
                    has_sent = true;
                }
                Err(err) => {
                    error!("socket send error: {}", err);
                    remove_sockets.push(socket_handle);
                    close_socket_control(&mut *control);
                    break;
                }
            }
        }

        if has_sent && control.send_waker.is_some() {
            if let Some(waker) = control.send_waker.take() {
                waker.wake();
            }
        }

    }
}