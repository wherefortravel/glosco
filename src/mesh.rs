use std::{sync::Arc, net::{SocketAddr, SocketAddrV4, Ipv4Addr}, io};

use futures::future::try_join_all;

use tokio::{sync::broadcast, net::{TcpListener, TcpStream}};

type Buffer = Arc<Vec<u8>>;

#[derive(Debug)]
pub struct Mesh {
    degree: usize,
    broadcast: (broadcast::Sender<Buffer>, broadcast::Receiver<Buffer>),
    listeners: Vec<Arc<TcpListener>>,
}

#[derive(Debug, Clone)]
pub struct MeshConfig {
    degree: usize,
    buffer: usize,
    listens: Vec<SocketAddr>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            degree: 4,
            buffer: 1024,
            listens: vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 12074))],
        }
    }
}

impl MeshConfig {
    pub async fn build(self) -> io::Result<Arc<Mesh>> {
        let listeners = try_join_all(
            self.listens
                .into_iter()
                .map(|a| TcpListener::bind(a))
        ).await?
            .into_iter()
            .map(Arc::new)
            .collect();
        let mesh = Arc::new(Mesh {
            degree: self.degree,
            broadcast: broadcast::channel(self.buffer),
            listeners,
        });
        mesh.clone().boot_listeners();
        Ok(mesh)
    }
}

impl Mesh {
    fn boot_listeners(self: Arc<Self>) {
        self.listeners.iter().cloned().for_each(|socket| {
            let this = self.clone();
            tokio::spawn(async move {
                loop {
                    if let Ok((stream, addr)) = socket.accept().await {
                        tokio::spawn(this.clone().take_client(stream, addr));
                    }
                }
            });
        });
    }

    async fn take_client(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) {
        while let Ok()
    }
}
