use std::{net::IpAddr, fmt::{Formatter, self, Display}, time::{self, SystemTime, Duration}, sync::mpsc, collections::HashMap, thread::{JoinHandle, self}};

use dns_parser::RData;
use pcap::{Linktype, Device, Capture};
use pktparse::{ethernet::{self, EtherType}, ipv4, ip, ipv6, tcp, udp, icmp::{self, IcmpCode}};

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
pub enum Resolution {
    Address(IpAddr),
    Alias(String),
    Service(String, Option<u16>),
    Text(Vec<Vec<u8>>),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name {
    pub name: String,
    pub address: Option<Resolution>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Message {
    Active(State),
    Ended(State, Closed),
    Failed(State, Problem),
    Name(State, Vec<Name>),
}

#[derive(Debug, Default)]
pub struct ObserverConfig {
    devices: Vec<Device>
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum StartError {
    NoDevices,
}

// This implementation reversed from the source code of pktparse with love
impl From<IcmpCode> for Problem {
    fn from(value: IcmpCode) -> Self {
        let (kind, code) = match value {
            IcmpCode::EchoReply => (0, 0),
            // XXX information is lost; the below can be (1, _), (2, _), (7, _)
            IcmpCode::Reserved => (1, 0),
            IcmpCode::DestinationUnreachable(un) => (3, match un {
                icmp::Unreachable::DestinationNetworkUnreachable => 0,
                icmp::Unreachable::DestinationHostUnreachable => 1,
                icmp::Unreachable::DestinationProtocolUnreachable => 2,
                icmp::Unreachable::DestinationPortUnreachable => 3,
                icmp::Unreachable::FragmentationRequired => 4,
                icmp::Unreachable::SourceRouteFailed => 5,
                icmp::Unreachable::DestinationNetworkUnknown => 6,
                icmp::Unreachable::DestinationHostUnknown => 7,
                icmp::Unreachable::SourceHostIsolated => 8,
                icmp::Unreachable::NetworkAdministrativelyProhibited => 9,
                icmp::Unreachable::HostAdministrativelyProhibited => 10,
                icmp::Unreachable::NetworkUnreachableForTos => 11,
                icmp::Unreachable::HostUnreachableForTos => 12,
                icmp::Unreachable::CommunicationAdministrativelyProhibited => 13,
                icmp::Unreachable::HostPrecedenceViolation => 14,
                icmp::Unreachable::PrecedentCutoffInEffect => 15,
            }),
            IcmpCode::SourceQuench => (4, 0),
            IcmpCode::Redirect(rd) => (5, match rd {
                icmp::Redirect::Network => 0,
                icmp::Redirect::Host => 1,
                icmp::Redirect::TosAndNetwork => 2,
                icmp::Redirect::TosAndHost => 3,
            }),
            IcmpCode::EchoRequest => (8, 0),
            IcmpCode::RouterAdvertisment => (9, 0),
            IcmpCode::RouterSolicication => (10, 0),
            IcmpCode::TimeExceeded(te) => (11, match te {
                icmp::TimeExceeded::TTL => 0,
                icmp::TimeExceeded::FragmentReassembly => 1,
            }),
            IcmpCode::ParameterProblem(pp) => (12, match pp {
                icmp::ParameterProblem::Pointer => 0,
                icmp::ParameterProblem::MissingRequiredOption => 1,
                icmp::ParameterProblem::BadLength => 2,
            }),
            IcmpCode::Timestamp => (12, 0),
            IcmpCode::TimestampReply => (13, 0),
            IcmpCode::ExtendedEchoRequest => (42, 0),
            IcmpCode::ExtendedEchoReply(eer) => (43, match eer {
                icmp::ExtendedEchoReply::NoError => 0,
                icmp::ExtendedEchoReply::MalformedQuery => 1,
                icmp::ExtendedEchoReply::NoSuchInterface => 2,
                icmp::ExtendedEchoReply::NoSuchTableEntry => 3,
                icmp::ExtendedEchoReply::MupltipleInterfacesStatisfyQuery => 4,
            }),
            IcmpCode::Other(raw) => ((raw >> 8) as u8, raw as u8),
        };
        Problem { kind, code }
    }
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

impl From<dns_parser::ResourceRecord<'_>> for Name {
    fn from(value: dns_parser::ResourceRecord) -> Self {
        Self {
            name: value.name.to_string(),
            address: match value.data {
                RData::A(arec) => Some(Resolution::Address(IpAddr::V4(arec.0))),
                RData::AAAA(arec) => Some(Resolution::Address(IpAddr::V6(arec.0))),
                RData::CNAME(crec) => Some(Resolution::Alias(crec.0.to_string())),
                RData::MX(mrec) => Some(Resolution::Service(mrec.exchange.to_string(), None)),
                RData::SRV(srec) => Some(Resolution::Service(srec.target.to_string(), Some(srec.port))),
                RData::TXT(trec) => Some(Resolution::Text(trec.iter().map(|txt| txt.to_vec()).collect())),
                _ => None
            },
        }
    }
}

impl From<dns_parser::Question<'_>> for Name {
    fn from(value: dns_parser::Question) -> Self {
        Self {
            name: value.qname.to_string(),
            address: None,
        }
    }
}

impl Observer {
    pub const KEEPALIVE_SECS: u64 = 30u64;

    pub fn namespace(&mut self) -> Vec<String> {
        self.devices.iter().map(|dev| dev.name.clone()).collect()
    }

    fn handle_ether(&mut self, interface: usize, bytes: impl AsRef<[u8]>) -> Vec<Message> {
        if let Ok((rest, pkt)) = ethernet::parse_ethernet_frame(bytes.as_ref()) {
            match pkt.ethertype {
                EtherType::IPv4 => self.handle_ipv4(interface, rest),
                EtherType::IPv6 => self.handle_ipv6(interface, rest),
                _ => Vec::new()
            }
        } else {
            Vec::new()
        }
    }

    fn handle_ipv4(&mut self, interface: usize, bytes: impl AsRef<[u8]>) -> Vec<Message> {
        if let Ok((rest, pkt)) = ipv4::parse_ipv4_header(bytes.as_ref()) {
            let pair = HostPair {
                src: IpAddr::V4(pkt.source_addr),
                dst: IpAddr::V4(pkt.dest_addr),
            };
            match pkt.protocol {
                ip::IPProtocol::TCP => self.handle_tcp(interface, rest, pair),
                ip::IPProtocol::UDP => self.handle_udp(interface, rest, pair),
                ip::IPProtocol::ICMP => self.handle_icmp(interface, rest, pair),
                _ => Vec::new()
            }
        } else {
            Vec::new()
        }
    }

    fn handle_ipv6(&mut self, interface: usize, bytes: impl AsRef<[u8]>) -> Vec<Message> {
        if let Ok((rest, pkt)) = ipv6::parse_ipv6_header(bytes.as_ref()) {
            let pair = HostPair {
                src: IpAddr::V6(pkt.source_addr),
                dst: IpAddr::V6(pkt.dest_addr),
            };
            match pkt.next_header {
                ip::IPProtocol::TCP => self.handle_tcp(interface, rest, pair),
                ip::IPProtocol::UDP => self.handle_udp(interface, rest, pair),
                ip::IPProtocol::ICMP6 => self.handle_icmp(interface, rest, pair),
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }

    fn handle_tcp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) -> Vec<Message> {
        if let Ok((rest, pkt)) = tcp::parse_tcp_header(bytes.as_ref()) {
            let conn = Connection {
                interface,
                src: Endpoint { addr: hosts.src, port: pkt.source_port },
                dst: Endpoint { addr: hosts.dst, port: pkt.dest_port },
                protocol: Protocol::Tcp,
            };
            if pkt.flag_rst | pkt.flag_fin {
                self.connection_closed(conn, if pkt.flag_rst {
                    Closed::Reset
                } else {
                    Closed::Normally
                })
            } else {
                self.connection_open(conn)
            }
        } else {
            Vec::new()
        }
    }

    fn handle_udp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) -> Vec<Message> {
        if let Ok((rest, pkt)) = udp::parse_udp_header(bytes.as_ref()) {
            let conn = Connection {
                interface,
                src: Endpoint { addr: hosts.src, port: pkt.source_port },
                dst: Endpoint { addr: hosts.dst, port: pkt.dest_port },
                protocol: Protocol::Udp,
            };
            if pkt.dest_port == 53 || pkt.source_port == 53 {
                self.handle_dns(rest, conn)
            } else {
                // UDP is connectionless, so always consider it closed
                self.connection_closed(conn, Closed::Connectionless)
            }
        } else {
            Vec::new()
        }
    }

    fn handle_dns(&mut self, bytes: impl AsRef<[u8]>, conn: Connection) -> Vec<Message> {
        println!("trying DNS");
        if let Ok(dns) = dns_parser::Packet::parse(bytes.as_ref()) {
            println!("packet ingested");
            if dns.questions.is_empty() {
                Vec::new()
            } else {
                let mut names: Vec<Name> = Vec::new();
                for ques in dns.questions {
                    names.push(ques.into());
                }
                for resp in dns.answers {
                    names.push(resp.into());
                }
                self.send_names(conn, names)
            }
        } else {
            Vec::new()
        }
    }

    fn handle_icmp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) -> Vec<Message> {
        if let Ok((rest, pkt)) = icmp::parse_icmp_header(bytes.as_ref()) {
            let conn = if let Ok((_rest, trans)) = udp::parse_udp_header(rest) {
                Some(Connection {
                    interface,
                    src: Endpoint { addr: hosts.src, port: trans.source_port },
                    dst: Endpoint { addr: hosts.dst, port: trans.dest_port },
                    protocol: Protocol::Udp,
                })
            } else if let Ok((_rest, trans)) = tcp::parse_tcp_header(rest) {
                Some(Connection {
                    interface,
                    src: Endpoint { addr: hosts.src, port: trans.source_port },
                    dst: Endpoint { addr: hosts.dst, port: trans.dest_port },
                    protocol: Protocol::Tcp,
                })
            } else { None };
            if let Some(conn) = conn {
                // TODO
                let problem: Problem = pkt.code.into();
                self.connection_unavail(conn, problem)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }

    fn send_names(&mut self, conn: Connection, names: Vec<Name>) -> Vec<Message> {
        let mut messages = self.connection_closed(conn, Closed::Connectionless);
        messages.push(Message::Name(State { as_of: SystemTime::now(), connection: conn }, names));
        messages
    }

    fn connection_open(&mut self, conn: Connection) -> Vec<Message> {
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
                vec![message]
            } else {
                Vec::new()
            }
        } else {
            let message = Message::Active(
                State { as_of: SystemTime::now(), connection: conn }
            );
            self.states.insert(conn, message.clone());
            vec![message]
        }
    }

    fn connection_closed(&mut self, conn: Connection, how: Closed) -> Vec<Message> {
        // Due to connectionless protocols, don't rate-limit this
        let message = Message::Ended(
            State { as_of: SystemTime::now(), connection: conn },
            how,
        );
        self.states.insert(conn, message.clone());
        vec![message]
    }

    fn connection_unavail(&mut self, conn: Connection, problem: Problem) -> Vec<Message> {
        let message = Message::Failed(
            State { as_of: SystemTime::now(), connection: conn },
            problem,
        );
        self.states.insert(conn, message.clone());
        vec![message]
    }
}

impl Iterator for Observer {
    type Item = Vec<Message>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.packets.recv() {
                Err(_) => return None,
                Ok(ingress) => {
                    match ingress.link {
                        Linktype::ETHERNET => {
                            let msgs = self.handle_ether(ingress.interface, &ingress.data);
                            if !msgs.is_empty() {
                                return Some(msgs);
                            }
                        },
                        _ => (),
                    }
                }
            }
        }
    }
}
