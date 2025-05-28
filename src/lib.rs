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

pub use core::{
    fmt::Debug,
    borrow::Borrow,
};

pub use std::{
    time::{Duration, SystemTime, Instant},
    sync::Arc,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

pub use async_net::{
    UdpSocket,
    TcpStream, TcpListener,
};
pub use futures_lite::{
    io::{AsyncReadExt, AsyncWriteExt},
    future::FutureExt,
    stream::StreamExt,
};

pub use once_cell::sync::{OnceCell, Lazy};

pub use smoltimeout::TimeoutExt;

pub use portable_atomic::{
    AtomicBool,
    Ordering::Relaxed,
};

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

    #[inline(always)]
    fn log_error(self) -> Self {
        self.log_generic(log::Level::Error)
    }

    #[inline(always)]
    fn log_warn(self) -> Self {
        self.log_generic(log::Level::Warn)
    }

    #[inline(always)]
    fn log_info(self) -> Self {
        self.log_generic(log::Level::Info)
    }

    #[inline(always)]
    fn log_debug(self) -> Self {
        self.log_generic(log::Level::Debug)
    }

    #[inline(always)]
    fn log_trace(self) -> Self {
        self.log_generic(log::Level::Trace)
    }
}

impl<T: Debug, E: Debug> LogResult for Result<T, E> {
    #[inline(always)]
    fn log_generic(self, level: log::Level) -> Self {
        if let Err(_) = self {
            log::log!(level, "{:?}", self);
        }
        self
    }
}
impl<T: Debug, E: Debug> LogResult for &Result<T, E> {
    #[inline(always)]
    fn log_generic(self, level: log::Level) -> Self {
        if let Err(_) = self {
            log::log!(level, "{:?}", self);
        }
        self
    }
}
