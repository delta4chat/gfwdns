pub mod cache;
pub use cache::*;

#[cfg(feature="sqlite")]
pub mod db;
#[cfg(feature="sqlite")]
pub use db::*;

pub mod detector;
pub use detector::*;

pub mod forwarder;
pub use forwarder::*;

pub mod data;
pub use data::*;

pub use core::fmt::Debug;
pub use core::borrow::Borrow;

pub use std::time::{Duration, SystemTime, Instant};
pub use std::sync::Arc;
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
pub use std::path::{Path, PathBuf};

pub use smol::net::{UdpSocket, TcpStream, TcpListener};
pub use smol::io::{AsyncReadExt, AsyncWriteExt};
pub use smol::future::FutureExt;
pub use smol::stream::StreamExt;

pub use once_cell::sync::{OnceCell, Lazy};

pub use smoltimeout::TimeoutExt;

pub use portable_atomic::AtomicBool;
pub use portable_atomic::Ordering::Relaxed;

pub use serde::{Serialize, Deserialize};

pub use anyhow::Context;

#[cfg(feature="sqlite")]
pub use sqlx::{
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode,
        SqliteLockingMode, SqlitePool, SqlitePoolOptions,
        SqliteSynchronous,
    },
    {Row, Value, ValueRef},
};

pub mod dns {
    pub use hickory_proto::op::*;
    pub use hickory_proto::rr::{
        IntoName,
        domain::Name,
        LowerName,
        RecordData,
        dns_class::DNSClass,
        record_type::RecordType,
        record_data::RData,
        rdata,
        Record,
    };

    pub use hickory_proto::serialize::binary::BinEncodable;

    pub use DNSClass as Class;
    pub use DNSClass as RdClass;
    pub use RecordType as Type;
    pub use RecordType as RdType;
}

pub static DISABLE_IPV6: AtomicBool = AtomicBool::new(false);

pub trait LogResult: Debug + Sized {
    fn log_generic(self, level: log::Level) -> Self;

    fn log_error(self) -> Self {
        self.log_generic(log::Level::Error)
    }

    fn log_warn(self) -> Self {
        self.log_generic(log::Level::Warn)
    }

    fn log_info(self) -> Self {
        self.log_generic(log::Level::Info)
    }

    fn log_debug(self) -> Self {
        self.log_generic(log::Level::Debug)
    }
    fn log_trace(self) -> Self {
        self.log_generic(log::Level::Trace)
    }
}

impl<T: Debug, E: Debug> LogResult for Result<T, E> {
    fn log_generic(self, level: log::Level) -> Self {
        if let Err(_) = self {
            log::log!(level, "{:?}", self);
        }
        self
    }
}
impl<T: Debug, E: Debug> LogResult for &Result<T, E> {
    fn log_generic(self, level: log::Level) -> Self {
        if let Err(_) = self {
            log::log!(level, "{:?}", self);
        }
        self
    }
}
