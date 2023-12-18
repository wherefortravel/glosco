use std::{process, thread, time, sync::mpsc, net::{IpAddr, TcpStream, TcpListener, self}, collections::{HashSet, HashMap}, fmt::Display};

use clap::Parser;
use packet::{ip, ether, Packet, tcp, udp, icmp};

pub mod observe;

#[derive(Debug, Parser)]
#[command(author = "Grissess", version = "0.1",
          about = "Track connection state globally across large networks",
          long_about = None)]
struct Args {
    /// Interfaces, by name to use; if not provided, use all of them.
    #[arg(short, long)]
    interfaces: Option<Vec<String>>,
    
    /// How long to wait between redrawing the screen and updating clients, in milliseconds
    #[arg(short, long, default_value_t = 250)]
    refresh: u64,

    /// Don't actually write to the screen--just run the service
    #[arg(short, long)]
    quiet: bool,

    /// Remote instances to which to connect
    #[arg(short='R', long)]
    remotes: Vec<String>,
}

#[derive(Debug, Clone)]
struct Ingress {
    data: Vec<u8>,
    source: usize,
    link: pcap::Linktype,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    addr: IpAddr,
    port: u16,
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Tcp, Udp,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match *self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct HostPair {
    src: IpAddr,
    dst: IpAddr,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Connection {
    interface: usize,
    src: Endpoint,
    dst: Endpoint,
    protocol: Protocol,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} -> {}", self.protocol, self.src, self.dst)
    }
}

impl Connection {
    fn canonical(self) -> Self {
        let alt = Connection { src: self.dst, dst: self.src, ..self };
        if alt < self { self } else { alt }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum CloseMode {
    Finish,
    Reset,
    NeverOpen,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum FlowState {
    Active,
    Former { ended: time::Instant, how: CloseMode },
    Unavailable { kind: u8, code: u8 },
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Event {
    Add { connection: Connection, state: FlowState },
    Remove { connection: Connection },
}

#[derive(Debug)]
struct Connections {
    active: HashMap<Connection, FlowState>,
    last: HashMap<Connection, FlowState>,
    keep: time::Duration,
    last_prune: time::Instant,
    prune: time::Duration,
}

impl Default for Connections {
    fn default() -> Self {
        Connections {
            active: HashMap::new(),
            last: HashMap::new(),
            keep: time::Duration::from_secs(300),
            last_prune: time::Instant::now(),
            prune: time::Duration::from_secs(1),
        }
    }
}

impl Connections {
    pub fn handle_ether(&mut self, interface: usize, bytes: impl AsRef<[u8]>) {
        if let Ok(pkt) = ether::Packet::new(bytes) {
            match pkt.protocol() {
                ether::Protocol::Ipv4 => self.handle_ipv4(interface, pkt.payload()),
                ether::Protocol::Ipv6 => self.handle_ipv6(interface, pkt.payload()),
                _ => (),
            }
        }
    }

    pub fn handle_ipv4(&mut self, interface: usize, bytes: impl AsRef<[u8]>) {
        if let Ok(pkt) = ip::v4::Packet::new(bytes) {
            let pair = HostPair {
                src: IpAddr::V4(pkt.source()),
                dst: IpAddr::V4(pkt.destination(),)
            };
            match pkt.protocol() {
                ip::Protocol::Tcp => self.handle_tcp(interface, pkt.payload(), pair),
                ip::Protocol::Udp => self.handle_udp(interface, pkt.payload(), pair),
                ip::Protocol::Icmp => self.handle_icmp(interface, pkt.payload(), pair),
                _ => (),
            }
        }
    }

    pub fn handle_ipv6(&mut self, _interface: usize, _bytes: impl AsRef<[u8]>) {
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
    }

    pub fn handle_tcp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) {
        if let Ok(pkt) = tcp::Packet::new(bytes) {
            let conn = Connection {
                interface,
                src: Endpoint { addr: hosts.src, port: pkt.source() },
                dst: Endpoint { addr: hosts.dst, port: pkt.destination() },
                protocol: Protocol::Tcp,
            }.canonical();
            if pkt.flags().intersects(tcp::flag::RST | tcp::flag::FIN) {
                self.connection_closed(conn, if pkt.flags().intersects(tcp::flag::RST) {
                    CloseMode::Reset
                } else {
                    CloseMode::Finish
                });
            } else {
                self.connection_open(conn);
            }
        }
    }

    pub fn handle_udp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) {
        if let Ok(pkt) = udp::Packet::new(bytes) {
            let conn = Connection {
                interface,
                src: Endpoint { addr: hosts.src, port: pkt.source() },
                dst: Endpoint { addr: hosts.dst, port: pkt.destination() },
                protocol: Protocol::Udp,
            }.canonical();
            // UDP is connectionless, so always consider it closed
            self.connection_closed(conn, CloseMode::NeverOpen);
        }
    }

    pub fn handle_icmp(&mut self, interface: usize, bytes: impl AsRef<[u8]>, hosts: HostPair) {
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
                self.connection_unavail(conn.canonical(), pkt.kind().into(), pkt.code());
            }
        }
    }

    pub fn connection_closed(&mut self, conn: Connection, how: CloseMode) {
        self.active.insert(conn, FlowState::Former {
            ended: time::Instant::now(),
            how,
        });
    }

    pub fn connection_open(&mut self, conn: Connection) {
        self.active.insert(conn, FlowState::Active);
    }

    pub fn connection_unavail(&mut self, conn: Connection, kind: u8, code: u8) {
        self.active.insert(conn, FlowState::Unavailable { kind, code });
    }

    pub fn update(&mut self) -> Vec<Event> {
        let now = time::Instant::now();
        if now - self.last_prune >= self.prune {
            self.last_prune = now;
            self.active.retain(|_k, v| match v {
                FlowState::Former { ended, .. } => now.duration_since(*ended) < self.keep,
                _ => true,
            });
        }

        let mut events = Vec::new();
        for (conn, state) in self.active.iter() {
            let last_st = self.last.get(conn);
            if let Some(st) = last_st {
                if st != state {
                    events.push(Event::Add { connection: *conn, state: *state });
                }
            } else {
                events.push(Event::Add { connection: *conn, state: *state });
            }
        }

        for (conn, state) in self.last.iter() {
            if !self.active.contains_key(conn) {
                events.push(Event::Remove { connection: *conn });
            }
        }

        events
    }

    pub fn take_event(&mut self, ev: &Event) {
        match ev {
            Event::Add { connection, state } => {
                self.active.insert(*connection, *state);
            },
            Event::Remove { connection } => {
                self.active.remove(connection);
            },
        }
    }
}

#[derive(Debug, Default)]
pub struct App {
    db: Connections,
    remote: HashMap<Endpoint, Connections>,
}

fn main() {
    let args = Args::parse();

    let mut devices = pcap::Device::list().unwrap();
    if let Some(intf) = args.interfaces {
        devices = intf.iter().map(|s| pcap::Device::from(&s[..])).collect();
    }

    if devices.is_empty() {
        eprintln!("No devices to capture from!");
        process::exit(1);
    }

    let namespace: Vec<_> = devices.iter().map(|dev| dev.name.clone()).collect();

    let (pkt_tx, pkt_rx) = mpsc::channel();

    let _threads: Vec<_> = devices.into_iter().enumerate().map(|(idx, dev)| {
        let our_tx = pkt_tx.clone();
        thread::spawn(move || {
            let mut cap = pcap::Capture::from_device(dev).unwrap().immediate_mode(true).open().unwrap();
            let link = cap.get_datalink();
            while let Ok(pkt) = cap.next_packet() {
                our_tx.send(Ingress {
                    data: pkt.data.to_vec(),
                    source: idx,
                    link,
                }).unwrap();
            }
        })
    }).collect();

    let mut app = App::default();
    let conns = &mut app.db;

    let listener = net::TcpListener::bind("0.0.0.0:12074").unwrap();

    let refresh = time::Duration::from_millis(args.refresh);
    let mut update = time::Instant::now() + refresh;
    let dunno = "(???)".to_string();

    loop {
        let pkt = pkt_rx.recv().unwrap();
        match pkt.link {
            pcap::Linktype::ETHERNET => conns.handle_ether(pkt.source, &pkt.data),
            _ => (),
        }
        conns.update();

        if !args.quiet {
            let now = time::Instant::now();
            if now >= update {
                update = now + refresh;
                print!("\x1b[H\x1b[J");
                for (conn, state) in conns.active.iter() {
                    println!("{:?} - {:?}", state, conn);
                }
            }
        }
    }
}
