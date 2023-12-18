use std::{io::{Write, Read, self, ErrorKind, Error}, net::{Ipv4Addr, Ipv6Addr, IpAddr}, array, time::{SystemTime, Duration}, string};

use crate::observe::{Protocol, Closed, Problem, State, Connection, Endpoint, Message};

pub trait Coder: Sized {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()>;
    fn decode<R: Read>(reader: &mut R) -> io::Result<Self>;
}

pub const V4_MARK: u8 = 1;
pub const V6_MARK: u8 = 2;
pub const TCP_MARK: u8 = 1;
pub const UDP_MARK: u8 = 2;
pub const NORMAL_MARK: u8 = 1;
pub const RESET_MARK: u8 = 2;
pub const CLESS_MARK: u8 = 3;
pub const TMOUT_MARK: u8 = 4;
pub const ACTIVE_MARK: u8 = 1;
pub const ENDED_MARK: u8 = 2;
pub const FAILED_MARK: u8 = 3;
pub const NAME_MARK: u8 = 4;

impl Coder for Ipv4Addr {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
writer.write_all(&self.octets())
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer)?;
        Ok(Self::new(buffer[0], buffer[1], buffer[2], buffer[3]))
    }
}

impl Coder for Ipv6Addr {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.octets())
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buffer = [0u8; 16];
        reader.read_exact(&mut buffer)?;
        Ok(Self::new(
                (buffer[0] as u16) << 8 | (buffer[1] as u16),
                (buffer[2] as u16) << 8 | (buffer[3] as u16),
                (buffer[4] as u16) << 8 | (buffer[5] as u16),
                (buffer[6] as u16) << 8 | (buffer[7] as u16),
                (buffer[8] as u16) << 8 | (buffer[9] as u16),
                (buffer[10] as u16) << 8 | (buffer[11] as u16),
                (buffer[12] as u16) << 8 | (buffer[13] as u16),
                (buffer[14] as u16) << 8 | (buffer[15] as u16),
        ))
    }
}

impl Coder for IpAddr {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            Self::V4(v4) => {
            writer.write_all(&[V4_MARK])?;
                v4.encode(writer)
            },
            Self::V6(v6) => {
                writer.write_all(&[V6_MARK])?;
                v6.encode(writer)
            },
        }
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut mark: u8 = 0;
        reader.read_exact(array::from_mut(&mut mark))?;
        match mark {
            V4_MARK => Ok(Self::V4(Ipv4Addr::decode(reader)?)),
            V6_MARK => Ok(Self::V6(Ipv6Addr::decode(reader)?)),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl Coder for u8 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(array::from_ref(self))
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut this: Self = 0;
        reader.read_exact(array::from_mut(&mut this))?;
        Ok(this)
    }
}

impl Coder for u16 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        // Safety: "Casting from a larger integer to a smaller integer (e.g. u32 -> u8) will
        // truncate" (reference)
        ((*self >> 8) as u8).encode(writer)?;
        (*self as u8).encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let hi = u8::decode(reader)?;
        let lo = u8::decode(reader)?;
        Ok(((hi as Self) << 8) | (lo as Self))
    }
}

impl Coder for u32 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        ((*self >> 16) as u16).encode(writer)?;
        (*self as u16).encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let hi = u16::decode(reader)?;
        let lo = u16::decode(reader)?;
        Ok(((hi as Self) << 16) | (lo as Self))
    }
}

impl Coder for u64 {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        ((*self >> 32) as u32).encode(writer)?;
        (*self as u32).encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let hi = u32::decode(reader)?;
        let lo = u32::decode(reader)?;
        Ok(((hi as Self) << 32) | (lo as Self))
    }
}

impl Protocol {
    pub fn number(&self) -> u8 {
        match self {
            Self::Tcp => TCP_MARK,
            Self::Udp => UDP_MARK,
        }
    }
}

impl Coder for Protocol {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.number()])
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut mark: u8 = 0;
        reader.read_exact(array::from_mut(&mut mark))?;
        match mark {
            TCP_MARK => Ok(Self::Tcp),
            UDP_MARK => Ok(Self::Udp),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl Closed {
    pub fn number(&self) -> u8 {
        match self {
            Self::Normally => NORMAL_MARK,
            Self::Reset => RESET_MARK,
            Self::TimedOut => TMOUT_MARK,
            Self::Connectionless => CLESS_MARK,
        }
    }
}

impl Coder for Closed {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.number()])
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut mark: u8 = 0;
        reader.read_exact(array::from_mut(&mut mark))?;
        match mark {
            NORMAL_MARK => Ok(Self::Normally),
            RESET_MARK => Ok(Self::Reset),
            CLESS_MARK => Ok(Self::Connectionless),
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl Coder for Problem {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.kind.encode(writer)?;
        self.code.encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let kind = u8::decode(reader)?;
        let code = u8::decode(reader)?;
        Ok(Self { kind, code })
    }
}

impl Coder for SystemTime {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let dur = self
            .duration_since(Self::UNIX_EPOCH)
            .map_err(|_| Error::from(ErrorKind::InvalidData))?;
        dur.as_secs().encode(writer)?;
        dur.subsec_nanos().encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let secs = u64::decode(reader)?;
        let nanos = u32::decode(reader)?;
        let dur = Duration::new(secs, nanos);
        Ok(Self::UNIX_EPOCH + dur)
    }
}

impl Coder for Endpoint {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.addr.encode(writer)?;
        self.port.encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let addr = IpAddr::decode(reader)?;
        let port = u16::decode(reader)?;
        Ok(Self { addr, port })
    }
}

impl Coder for Connection {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        (self.interface as u16).encode(writer)?;
        self.src.encode(writer)?;
        self.dst.encode(writer)?;
        self.protocol.encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let interface = u16::decode(reader)? as usize;
        let src = Endpoint::decode(reader)?;
        let dst = Endpoint::decode(reader)?;
        let protocol = Protocol::decode(reader)?;
        Ok(Self { interface, src, dst, protocol })
    }
}

impl Coder for State {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.as_of.encode(writer)?;
        self.connection.encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let as_of = SystemTime::decode(reader)?;
        let connection = Connection::decode(reader)?;
        Ok(Self { as_of, connection })
    }
}

impl Coder for Message {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            Self::Active(state) => {
                writer.write_all(&[ACTIVE_MARK])?;
                state.encode(writer)
            },
            Self::Ended(state, closed) => {
                writer.write_all(&[ENDED_MARK])?;
                state.encode(writer)?;
                closed.encode(writer)
            },
            Self::Failed(state, problem) => {
                writer.write_all(&[FAILED_MARK])?;
                state.encode(writer)?;
                problem.encode(writer)
            },
            Self::Name(nm) => {
                writer.write_all(&[NAME_MARK])?;
                nm.encode(writer)
            }
        }
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut mark: u8 = 0;
        reader.read_exact(array::from_mut(&mut mark))?;
        match mark {
            ACTIVE_MARK => {
                let state = State::decode(reader)?;
                Ok(Self::Active(state))
            },
            ENDED_MARK => {
                let state = State::decode(reader)?;
                let closed = Closed::decode(reader)?;
                Ok(Self::Ended(state, closed))
            },
            FAILED_MARK => {
                let state = State::decode(reader)?;
                let problem = Problem::decode(reader)?;
                Ok(Self::Failed(state, problem))
            },
            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl Coder for Vec<u8> {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        (self.len() as u16).encode(writer)?;
        println!("frame write: {:?}", self.len());
        writer.write_all(self)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let len = u16::decode(reader)?;
        println!("frame read: {:?}", len);
        let mut this = vec![0; len as usize];
        reader.read_exact(&mut this)?;
        Ok(this)
    }
}

impl Coder for String {
    fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.as_bytes().to_vec().encode(writer)
    }

    fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        String::from_utf8(Vec::<u8>::decode(reader)?).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }
}
