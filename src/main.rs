use std::{net::{ToSocketAddrs, TcpListener, SocketAddr, TcpStream}, thread, string, time::{SystemTime, Duration}};

use clap::{arg, Parser, command};
use coding::{Coder, TCP_MARK, TMOUT_MARK};
use observe::{ObserverConfig, Message};
use pcap::Device;
use rusqlite::{params, types::Null, named_params};
use sync::ClientConfig;

pub mod observe;
//pub mod mesh;
pub mod coding;
pub mod sync;

#[derive(Debug, Parser)]
#[command(author = "Grissess", version = "0.1",
          about = "Track connection state globally across large networks",
          long_about = None)]
struct Args {
    /// Operating mode, one of "client" or "server"
    #[arg(long, default_value = "client")]
    mode: String,
    
    /// client: Interfaces, by name to use; if not provided, use all of them.
    #[arg(short, long)]
    interfaces: Option<Vec<String>>,
    
    /// client: Remote instances to which to connect
    #[arg(short = 'R', long)]
    remotes: Vec<String>,

    /// client: Identity to advertise to server, defaults to hostname
    #[arg(long)]
    ident: Option<String>,

    /// server: Bind address
    #[arg(short = 'B', long, default_value = "0.0.0.0:12074")]
    bind: SocketAddr,

    /// server: Database file
    #[arg(short, long, default_value = "glosco.db")]
    database: String,

    /// server: Timeout on TCP connections, after which we assume they closed without notice
    #[arg(long, default_value = "60")]
    tcp_timeout: f64,

    /// server: Maintenance period--how often to do periodic database tasks
    #[arg(long, default_value = "5")]
    maintenance: f64,
}

fn main() {
    let args = Args::parse();

    match args.mode.as_str() {
        "client" => main_client(args),
        "server" => main_server(args),
        _ => panic!("unknown mode {:?}, try 'client' or 'server'", args.mode),
    }
}

fn main_client(args: Args) {
    let mut observer = ObserverConfig::default();

    if let Some(intf) = args.interfaces {
        for devname in intf {
            observer.add_device(Device::from(&devname[..]));
        }
    }

    let ident = args.ident.unwrap_or_else(|| {
        gethostname::gethostname().into_string().expect("couldn't encode hostname")
    });
    let mut client = ClientConfig::new(ident);
    for remote in args.remotes {
        for addr in remote.to_socket_addrs().expect("failed to parse as socket address") {
            client.add(addr);
        }
    }

    let client = client.build().expect("failed to build remote client");

    let mut observer = observer.start().expect("failed to start");

    let namespace = observer.namespace();

    for message in observer {
        println!("{:?}", message);
        client.send(&message);
    }
}

fn maint_thread(path: String, period: Duration, timeout: Duration) {
    let timeout = timeout.as_secs_f64();
    loop {
        thread::sleep(period);
        {
            let mut db = rusqlite::Connection::open(path.clone()).expect("failed to open database to maintain");
            db.pragma_update_and_check(None, "journal_mode", "WAL", |row| {
                let journal_mode: String = row.get(0).expect("query did not return a result");
                println!("post-assign journal_mode={}", journal_mode);
                assert!(journal_mode == "wal", "failed to set WAL mode");
                Ok(())
            }).expect("failed to query WAL mode");
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                .expect("time is before UNIX epoch!")
                .as_secs_f64();
            db.trace(Some(|s| println!("{}", s)));
            db.execute("
                INSERT INTO state
                (instime, conntime, ident, peer, srchost, srcport, dsthost, dstport, proto, close, pkind, pcode)
                SELECT :now, :now, ident, peer, srchost, srcport, dsthost, dstport, :tcp, :timeout, NULL, NULL
                FROM latest_ins
                WHERE close IS NOT :timeout AND proto = :tcp AND instime < :threshold;
            ", named_params! {
                ":now": now,
                ":threshold": now - timeout,
                ":tcp": TCP_MARK,
                ":timeout": TMOUT_MARK,
            }).expect("failed to maintain database");
            println!("maintenance tick: {} rows changed", db.changes());
        }
    }
}

fn main_server(args: Args) {
    let sock = TcpListener::bind(args.bind).expect("failed to bind socket");

    {
        let db = rusqlite::Connection::open(args.database.clone()).expect("failed to open database");
        db.pragma_update_and_check(None, "journal_mode", "WAL", |row| {
            let journal_mode: String = row.get(0).expect("query did not return a result");
            println!("post-assign journal_mode={}", journal_mode);
            assert!(journal_mode == "wal", "failed to set WAL mode");
            Ok(())
        }).expect("failed to query WAL mode");
        db.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS state
            (instime, conntime, ident, peer, srchost, srcport, dsthost, dstport, proto, close, pkind, pcode);
            CREATE INDEX IF NOT EXISTS state_instime ON state (instime);
            CREATE INDEX IF NOT EXISTS state_conntime ON state (conntime);
            CREATE INDEX IF NOT EXISTS state_ident ON state (ident);
            CREATE INDEX IF NOT EXISTS state_src ON state (srchost, srcport);
            CREATE INDEX IF NOT EXISTS state_dst ON state (dsthost, dstport);
            CREATE VIEW IF NOT EXISTS latest_ins AS
            SELECT max(instime), * FROM state
            GROUP BY ident, srchost, srcport, dsthost, dstport, proto;
            CREATE INDEX IF NOT EXISTS latest_ins_idx
            ON STATE (ident, srchost, srcport, dsthost, dstport, proto);
            ",
        ).expect("failed to initialize database connection");
    }

    {
        let dbname = args.database.clone();
        let period = Duration::from_secs_f64(args.maintenance);
        let timeout = Duration::from_secs_f64(args.tcp_timeout);
        thread::spawn(move || maint_thread(dbname, period, timeout));
    }

    loop {
        if let Ok((client, peer)) = sock.accept() {
            println!("Connection from {:?}", peer);
            let dbname = args.database.clone();
            thread::spawn(move || {
                let db = rusqlite::Connection::open(dbname).expect("failed to connect to database");
                client_thread(client, peer, db);
            });
        }
    }
}

fn to_float_secs(st: SystemTime) -> f64 {
    let dur = st.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    dur.as_secs_f64()
}

fn client_thread(mut client: TcpStream, peer: SocketAddr, db: rusqlite::Connection) {
    let ident = if let Ok(frame) = Vec::<u8>::decode(&mut client) {
        if let Ok(str) = String::from_utf8(frame) {
            str
        } else {
            println!("failed to parse initial ident");
            return;
        }
    } else {
        println!("failed to read initial ident");
        return;
    };
    let peername = format!("{:?}", peer);
    while let Ok(frame) = Vec::<u8>::decode(&mut client) {
        if let Ok(message) = Message::decode(&mut frame.as_slice()) {
            println!("{}@{:?}: {:?}", ident, peer, message);
            let mut stmt = db.prepare_cached(
                "INSERT INTO state
                (instime, conntime, ident, peer, srchost, srcport, dsthost, dstport, proto, close, pkind, pcode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                "
            ).expect("failed to prepare statement");
            let now = SystemTime::now();
            match message {
                Message::Active(state) => {
                    let conn = state.connection;
                    let (src, dst) = (conn.src, conn.dst);
                    stmt.execute(params![
                        to_float_secs(now), to_float_secs(state.as_of),
                        ident, peername,
                        src.addr.to_string(), src.port,
                        dst.addr.to_string(), dst.port,
                        conn.protocol.number(),
                        Null, Null, Null,
                    ]).expect("failed to exec statement");
                },
                Message::Ended(state, closed) => {
                    let conn = state.connection;
                    let (src, dst) = (conn.src, conn.dst);
                    stmt.execute(params![
                        to_float_secs(now), to_float_secs(state.as_of),
                        ident, peername,
                        src.addr.to_string(), src.port,
                        dst.addr.to_string(), dst.port,
                        conn.protocol.number(),
                        closed.number(), Null, Null,
                    ]).expect("failed to exec statement");
                },
                Message::Failed(state, problem) => {
                    let conn = state.connection;
                    let (src, dst) = (conn.src, conn.dst);
                    stmt.execute(params![
                        to_float_secs(now), to_float_secs(state.as_of),
                        ident, peername,
                        src.addr.to_string(), src.port,
                        dst.addr.to_string(), dst.port,
                        conn.protocol.number(),
                        Null, problem.kind, problem.code,
                    ]).expect("failed to exec statement");
                },
                Message::Name(name) => {
                    todo!();
                }
            }
        }
    }
}
