use smoltcp::{
    socket::{TcpSocket, UdpSocket},
    storage::RingBuffer,
    wire::IpProtocol,
};
use std::{
    io, mem,
    pin::Pin,
    sync::{Arc},
    task::{Waker, Poll, Context},
    thread::Thread,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf}
};
use spin::Mutex as SpinMutex;

pub enum TunSocket {
    TunTcpSocket(TcpSocket<'static>),
    TunUdpSocket(UdpSocket<'static>)
}
pub struct ManagerNotify {
    thread: Thread,
}

impl ManagerNotify {
    pub fn new(thread: Thread) -> ManagerNotify {
        ManagerNotify { thread }
    }

    pub fn notify(&self) {
        self.thread.unpark();
    }
}

pub struct TunTransfer {
    pub protocol: IpProtocol,
    pub control: SharedConnectionControl,
}

pub struct SocketControl {
    pub send_buffer: RingBuffer<'static, u8>,
    pub send_waker: Option<Waker>,
    pub recv_buffer: RingBuffer<'static, u8>,
    pub recv_waker: Option<Waker>,
    pub is_closed: bool,
}

pub type SharedConnectionControl = Arc<SpinMutex<SocketControl>>;

pub struct SocketCreation {
    pub control: SharedConnectionControl,
    pub tun_socket: TunSocket
}

pub struct Connection {
    pub control: SharedConnectionControl,
    pub manager_notify: Arc<ManagerNotify>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        let mut control = self.control.lock();
        control.is_closed = true;
    }
}

impl AsyncRead for Connection {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut control = self.control.lock();

        // If socket is already closed, just return EOF directly.
        if control.is_closed {
            return Ok(()).into();
        }

        // Read from buffer

        if control.recv_buffer.is_empty() {
            // Nothing could be read. Wait for notify.
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let recv_buf = unsafe { mem::transmute::<_, &mut [u8]>(buf.unfilled_mut()) };
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);

        if control.recv_buffer.is_empty() {
            self.manager_notify.notify();
        }
        Ok(()).into()
    }
}

impl AsyncWrite for Connection {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut control = self.control.lock();
        if control.is_closed {
            return Err(io::ErrorKind::BrokenPipe.into()).into();
        }

        // Write to buffer

        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);

        if control.send_buffer.is_full() {
            self.manager_notify.notify();
        }
        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut control = self.control.lock();

        if control.is_closed {
            return Ok(()).into();
        }

        control.is_closed = true;
        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
            if !old_waker.will_wake(cx.waker()) {
                old_waker.wake();
            }
        }

        Poll::Pending
    }
}