use std::{net::IpAddr, fmt::{Formatter, self, Display}, time::{self, SystemTime, Duration}, sync::mpsc, collections::HashMap, thread::{JoinHandle, self}};

use packet::{ether, ip, tcp, udp, icmp, Packet};
use pcap::{Linktype, Device, Capture};

#[derive(Debug, Clone)]
pub struct Ingress {
    pub data: Vec<u8>,
    pub interface: usize,
    pub link: pcap::Linktype
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostPair {
    pub src: IpAddr,
    pub dst: IpAddr,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Tcp, Udp,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Connection {
    pub interface: usize,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct State {
    pub as_of: time::SystemTime,
    pub connection: Connection,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Problem {
    pub kind: u8,
    pub code: u8,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Closed {
    Normally,
    Reset,
    TimedOut,
    Connectionless,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Message {
    Active(State),
    Ended(State, Closed),
    Failed(State, Problem),
    Name(String),
}

#[derive(Debug, Default)]
pub struct ObserverConfig {
    devices: Vec<Device>
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum StartError {
    NoDevices,
}

impl ObserverConfig {
    pub fn add_device(&mut self, dev: Device) {
        self.devices.push(dev);
    }

    pub fn start(mut self) -> Result<Observer, StartError> {
        let (endpoint, packets) = mpsc::channel();
        if self.devices.is_empty() {
            self.devices = Device::list().unwrap();
        }
        if self.devices.is_empty() {
            return Err(StartError::NoDevices);
        }
        let threads = self.devices.iter().enumerate().map(|(idx, dev)| {
            let ep = endpoint.clone();
            let dev = dev.clone();
            thread::spawn(move || {
                let mut cap = Capture::from_device(dev).unwrap().immediate_mode(true).open().unwrap();
                let link = cap.get_datalink();
                while let Ok(pkt) = cap.next_packet() {
                    ep.send(Ingress {
                        data: pkt.data.to_vec(),
                        interface: idx,
                        link,
                    }).unwrap();
                }
            })
        }).collect();
        Ok(Observer {
            packets, endpoint, threads,
            devices: self.devices,
            states: Default::default(),
        })
    }
}

#[derive(Debug)]
pub struct Observer {
    packets: mpsc::Receiver<Ingress>,
    endpoint: mpsc::Sender<Ingress>,
    devices: Vec<Device>,
    threads: Vec<JoinHandle<()>>,
    states: HashMap<Connection, Message>,
}

impl Observer {
    pub const KEEPALIVE_SECS: u64 = 30u64;

    pub fn namespace(&mut self) -> Vec<String> {
        self.devices.iter().map(|dev| dev.name.clone()).collect()
    }

    fn handle_ether(&mut self, interface: usize, bytes: impl AsRef<[u8]>) -> Option<Message> {
        if let Ok(pkt) = ether::Packet::new(bytes) {
            match pkt.protocol() {
                ether::Protocol::Ipv4 => self.handle_ipv4(interface, pkt.payload()),
                ether::Protocol::Ipv6 => self.handle_ipv6(interface, pkt.payload()),
                _ => None
            }
        } else {
            None
        }
    }

    fn handle_ipv4(&mut self, interface: usize, bytes: impl AsRef<[u8]>) -> Option<Message> {
        if let Ok(pkt) = ip::v4::Packet::new(bytes) {
            let pair = HostPair {
                src: IpAddr::V4(pkt.source()),
                dst: IpAddr::V4(pkt.destination(),)
            };
            match pkt.protocol() {
                ip::Protocol::Tcp => self.handle_tcp(interface, pkt.payload(), pair),
                ip::Protocol::Udp => self.handle_udp(interface, pkt.payload(), pair),
                ip::Protocol::Icmp => self.handle_icmp(interface, pkt.payload(), pair),
                _ => None
            }
        } else {
            None
        }
    }

    fn handle_ipv6(&mut self, _interface: usize, _bytes: impl AsRef<[u8]>) -> Option<Message> {
        // Parser doesn't support this yet
        /*
        if let Ok(pkt) = ip::v6::Packet::new(bytes) {
            match pkt.protocol() {
                ip::Protocol::Tcp => self.handle_tcp(pkt.payload(), HostPair {
                    src: IpAddr::V6(pkt.source()),
                    dst: IpAddr::V6(pkt.destination()),
                }),
                _ => (),
            }
        }
        */
        None
    }

    fn handle_tcp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) -> Option<Message> {
        if let Ok(pkt) = tcp::Packet::new(bytes) {
            let conn = Connection {
                interface,
                src: Endpoint { addr: hosts.src, port: pkt.source() },
                dst: Endpoint { addr: hosts.dst, port: pkt.destination() },
                protocol: Protocol::Tcp,
            };
            if pkt.flags().intersects(tcp::flag::RST | tcp::flag::FIN) {
                self.connection_closed(conn, if pkt.flags().intersects(tcp::flag::RST) {
                    Closed::Reset
                } else {
                    Closed::Normally
                })
            } else {
                self.connection_open(conn)
            }
        } else {
            None
        }
    }

    fn handle_udp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) -> Option<Message> {
        if let Ok(pkt) = udp::Packet::new(bytes) {
            let conn = Connection {
                interface,
                src: Endpoint { addr: hosts.src, port: pkt.source() },
                dst: Endpoint { addr: hosts.dst, port: pkt.destination() },
                protocol: Protocol::Udp,
            };
            // UDP is connectionless, so always consider it closed
            self.connection_closed(conn, Closed::Connectionless)
        } else {
            None
        }
    }

    fn handle_icmp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) -> Option<Message> {
        if let Ok(pkt) = icmp::Packet::new(bytes) {
            let conn = if let Ok(trans) = udp::Packet::new(pkt.payload()) {
                Some(Connection {
                    interface,
                    src: Endpoint { addr: hosts.src, port: trans.source() },
                    dst: Endpoint { addr: hosts.dst, port: trans.destination() },
                    protocol: Protocol::Udp,
                })
            } else if let Ok(trans) = tcp::Packet::new(pkt.payload()) {
                Some(Connection {
                    interface,
                    src: Endpoint { addr: hosts.src, port: trans.source() },
                    dst: Endpoint { addr: hosts.dst, port: trans.destination() },
                    protocol: Protocol::Tcp,
                })
            } else { None };
            if let Some(conn) = conn {
                let problem = Problem {
                    kind: pkt.kind().into(),
                    code: pkt.code(),
                };
                self.connection_unavail(conn, problem)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn connection_open(&mut self, conn: Connection) -> Option<Message> {
        if let Some(Message::Active(state)) = self.states.get(&conn) {
            // Ensure we heartbeat some of these connections somewhat regularly
            if SystemTime::now().duration_since(state.as_of)
                .map(|d| d > Duration::from_secs(Self::KEEPALIVE_SECS))
                .unwrap_or(false)
            {
                let message = Message::Active(
                    State { as_of: SystemTime::now(), connection: conn }
                );
                self.states.insert(conn, message.clone());
                Some(message)
            } else {
                None
            }
        } else {
            let message = Message::Active(
                State { as_of: SystemTime::now(), connection: conn }
            );
            self.states.insert(conn, message.clone());
            Some(message)
        }
    }

    fn connection_closed(&mut self, conn: Connection, how: Closed) -> Option<Message> {
        // Due to connectionless protocols, don't rate-limit this
        let message = Message::Ended(
            State { as_of: SystemTime::now(), connection: conn },
            how,
        );
        self.states.insert(conn, message.clone());
        Some(message)
    }

    fn connection_unavail(&mut self, conn: Connection, problem: Problem) -> Option<Message> {
        let message = Message::Failed(
            State { as_of: SystemTime::now(), connection: conn },
            problem,
        );
        self.states.insert(conn, message.clone());
        Some(message)
    }
}

impl Iterator for Observer {
    type Item = Message;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.packets.recv() {
                Err(_) => return None,
                Ok(ingress) => {
                    match ingress.link {
                        Linktype::ETHERNET => if let Some(msg) = self.handle_ether(ingress.interface, &ingress.data) {
                            return Some(msg)
                        },
                        _ => (),
                    }
                }
            }
        }
    }
}
