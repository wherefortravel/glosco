use std::{io::{self, Write}, thread, net::{UdpSocket, SocketAddr, TcpStream}, thread::JoinHandle, sync::{mpsc, Arc, Mutex}, cell::RefCell, time::{Duration, Instant}};

use crate::coding::Coder;

#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    dests: Vec<SocketAddr>,
    ident: String,
}

#[derive(Debug)]
pub struct Client {
    senders: Vec<mpsc::Sender<Arc<Vec<u8>>>>,
}

const RETRY_BACKOFF_WIN: (usize, Duration) = (5, Duration::new(10, 0));
fn client_thread(addr: SocketAddr, receiver: mpsc::Receiver<Arc<Vec<u8>>>, hello: Arc<Vec<u8>>) {
    loop {
        let mut tries = 0usize;
        let mut start = Instant::now();
        let mut sock = loop {
            if tries > RETRY_BACKOFF_WIN.0 {
                thread::sleep((start + RETRY_BACKOFF_WIN.1).saturating_duration_since(Instant::now()));
                start = Instant::now();
            }
            println!("Try connect to {:?}", addr);
            match TcpStream::connect(addr) {
                Ok(sock) => break sock,
                Err(e) => {
                    println!("Connect error to {:?}: {:?}", addr, e);
                    tries += 1;
                },
            }
        };
        if let Ok(_) = sock.write_all(&hello) {
            while let Ok(bytes) = receiver.recv() {
                if let Err(e) = sock.write_all(&bytes) {
                    println!("Send error: {:?}", e);
                    break;
                }
            }
        }
        println!("Lost connection to {:?}", addr);
    }
}

impl ClientConfig {
    pub fn new(ident: String) -> Self {
        Self {
            ident,
            ..Default::default()
        }
    }

    pub fn add(&mut self, addr: SocketAddr) {
        self.dests.push(addr);
    }

    pub fn build(self) -> io::Result<Client> {
        let mut hello: Vec<u8> = Vec::with_capacity(self.ident.as_bytes().len() + 4);
        self.ident.encode(&mut hello).unwrap();
        let hello = Arc::new(hello);
        let mut senders: Vec<mpsc::Sender<Arc<Vec<u8>>>> = Vec::new();
        for addr in self.dests.into_iter() {
            let (sender, receiver) = mpsc::channel();
            senders.push(sender);
            let hello = hello.clone();
            thread::spawn(move || client_thread(addr, receiver, hello));
        }
        Ok(Client { senders })
    }
}

impl Client {
    pub fn send<C: Coder>(&self, object: &C) {
        let mut buffer: Vec<u8> = Vec::new();
        object.encode(&mut buffer).unwrap();
        self.send_frame(&buffer);
    }

    pub fn send_frame(&self, bytes: &Vec<u8>) {
        let mut frame = Vec::with_capacity(bytes.len() + 4);
        bytes.encode(&mut frame).unwrap();
        let message = Arc::new(frame);
        for sender in self.senders.iter() {
            let _ = sender.send(message.clone());
        }
    }
}
