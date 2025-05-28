use gfwdns::*;

use clap::Parser;

pub static DB_FILE: Lazy<PathBuf> = Lazy::new(|| {
    let mut buf = data_dir(None).unwrap().clone();
    buf.push("gfwdns.sqlx.sqlite3.db");
    buf
});

#[inline(always)]
pub fn data_dir(maybe_dir: Option<PathBuf>) -> anyhow::Result<&'static PathBuf> {
    static DATA_DIR: OnceCell<PathBuf> = OnceCell::new();
    loop {
        if let Some(dir) = DATA_DIR.get() {
            return Ok(dir);
        }

        let dir =
            if let Some(ref dir) = maybe_dir {
                dir.to_owned()
            } else {
                if let Some(pd) = directories::ProjectDirs::from("org", "delta4chat", "gfwdns") {
                    pd.data_dir().to_owned()
                } else {
                    anyhow::bail!("unable to get default data dir using 'directories::ProjectDirs'!");
                }
            };

        std::fs::create_dir_all(&dir).context("unable to create the provided dir")?;

        if DATA_DIR.set(dir).is_err() {
            log::error!("another thread already set the GFWDNS_DIR (OnceCell), using it");
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, clap::Parser)]
#[command(version, author, about, long_about)]
pub struct GfwdnsOpt {
    #[arg(long)]
    #[serde(default)]
    pub data_dir: Option<PathBuf>,

    #[arg(long)]
    #[serde(default)]
    pub disable_ipv6: bool,

    #[arg(long)]
    #[serde(default)]
    pub detect_method: Option<DomainSpoofDetectMethod>,

    #[arg(long)]
    #[serde(default)]
    pub listen: Option<SocketAddr>,

    #[arg(long)]
    #[serde(default)]
    pub local: Option<SocketAddr>,

    #[arg(long)]
    #[serde(default)]
    pub global: Option<SocketAddr>,
}

#[inline(always)]
async fn main_async() -> anyhow::Result<()> {
    env_logger::init();

    let opt = GfwdnsOpt::parse();

    if opt.disable_ipv6 {
        DISABLE_IPV6.store(true, Relaxed);
    }

    data_dir(opt.data_dir)?;

    let listen =
        match opt.listen {
            Some(val) => val,
            _ => {
                anyhow::bail!("No plaintext DNS listen address provided!");
            }
        };

    let local =
        match opt.local {
            Some(val) => val,
            _ => {
                anyhow::bail!("No Local DNS Upstream address provided!");
            }
        };

    let global =
        match opt.global {
            Some(val) => val,
            _ => {
                anyhow::bail!("No Global DNS Upstream address provided!");
            }
        };

    let cache = DomainStatusCache::with_db(&*DB_FILE).await?;

    let forwarder = {
        let mut b =
            DNSForwarder::builder()
            .status_cache(cache)

            .listen(listen)
            .local(local)
            .global(global);

        /*
        if let Some(method) = opt.detect_method {
            b = b.detect_method_data(method, data);
        }
        */

        b.build().await?
    };

    forwarder.run().await
}

#[inline(always)]
fn main() -> anyhow::Result<()> {
    futures_lite::future::block_on(main_async())
}

