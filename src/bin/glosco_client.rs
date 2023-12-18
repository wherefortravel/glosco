use std::net::ToSocketAddrs;

use clap::{arg, Parser, command};
use glosco::observe::ObserverConfig;
use pcap::Device;
use glosco::sync::ClientConfig;

#[derive(Debug, Parser)]
#[command(author = "Grissess", version = "0.1",
          about = "Track connection state globally across large networks",
          long_about = None)]
struct Args {
    /// Interfaces, by name to use; if not provided, use all of them.
    #[arg(short, long)]
    interfaces: Option<Vec<String>>,
    
    /// Remote instances to which to connect
    #[arg(short = 'R', long)]
    remotes: Vec<String>,

    /// Identity to advertise to server, defaults to hostname
    #[arg(long)]
    ident: Option<String>,
}

fn main() {
    let args = Args::parse();

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

    let _namespace = observer.namespace();

    for bundle in observer {
        for message in bundle.into_iter() {
            println!("{:?}", message);
            client.send(&message);
        }
    }
}
