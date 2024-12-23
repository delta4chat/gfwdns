use crate::*;

/// This struct provides information of Domain affected by GFW's DNS Spoofing.
#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct DomainStatusInfo {
    domain: String, // domain of GFW Spoofed
    is_blocked: bool, // whether this domain blocked by GFW
    first_seen: SystemTime, // first seen time
    expire: SystemTime, // re-check times
    method: DomainSpoofDetectMethod, // which detect type of this domain?
}
impl DomainStatusInfo {
    pub fn new(domain: &str, is_blocked: bool, method: DomainSpoofDetectMethod) -> Self {
        let now = SystemTime::now();

        let mut this = Self {
            domain: domain.to_string(),
            is_blocked,
            first_seen: now,
            expire: now,
            method,
        };
        this.on_updated(now);

        this
    }

    pub const fn ttl() -> Duration {
        Duration::from_secs(86400)
    }

    fn on_updated(&mut self, now: SystemTime) {
        self.expire = now + Self::ttl();
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expire
    }

    /* === read-only getters === */

    pub fn domain(&self) -> &str {
        self.domain.as_ref()
    }
    pub fn is_blocked(&self) -> bool {
        self.is_blocked
    }
    pub fn first_seen(&self) -> SystemTime {
        self.first_seen
    }
    pub fn method(&self) -> DomainSpoofDetectMethod {
        self.method
    }
    pub fn expire(&self) -> SystemTime {
        self.expire
    }

    /* == write-only setters == */
    pub fn set_method(&mut self, method: DomainSpoofDetectMethod) {
        self.method = method;
    }
    pub fn set_blocked(&mut self, is_blocked: bool) {
        self.is_blocked = is_blocked;
        self.on_updated(SystemTime::now());
    }
}

#[derive(Debug)]
struct DbInner {
    db: Database,
    negative_domains: scc::HashSet<String>,
}
impl DbInner {
    fn new(db: Database) -> Self {
        Self {
            db,
            negative_domains: scc::HashSet::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DomainStatusCache {
    memory: Arc<scc::HashMap<String, DomainStatusInfo>>,
    maybe_di: Option<Arc<DbInner>>,
}

impl Default for DomainStatusCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainStatusCache {
    pub fn new() -> Self {
        Self {
            memory: Arc::new(scc::HashMap::new()),
            maybe_di: None,
        }
    }

    #[cfg(feature="sqlite")]
    pub async fn with_db(db_file: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut this = Self::new();

        let di = DbInner::new(Database::new(db_file).await?);
        this.maybe_di = Some(Arc::new(di));

        Ok(this)
    }

    pub async fn get(&self, domain: &str) -> anyhow::Result<DomainStatusInfo> {
        if let Some(info) = self.memory.get_async(domain).await {
            Ok(info.clone())
        } else {
            if let Some(ref di) = self.maybe_di {
                if ! di.negative_domains.contains_async(domain).await {
                    let ret = di.db.load(domain).await;
                    if ret.is_err() {
                        let _ = di.negative_domains.insert_async(domain.to_string()).await;
                    }
                    let info = ret?;
                    let _ = self.memory.insert_async(domain.to_string(), info.clone()).await;
                    return Ok(info);
                }
            }
            anyhow::bail!("no info yet");
        }
    }

    pub async fn put(&self, domain: &str, is_blocked: bool, detect_method: DomainSpoofDetectMethod) {
        let mut entry =
            self.memory.entry_async(domain.to_string()).await
            .or_insert_with(|| { DomainStatusInfo::new(domain, is_blocked, detect_method) });

        let mut_info = entry.get_mut();
        mut_info.set_method(detect_method);
        mut_info.set_blocked(is_blocked);

        if self.maybe_di.is_none() {
            return;
        }

        let info = mut_info.clone();
        drop(entry);

        if let Some(ref di) = self.maybe_di {
            let _ = di.db.store(domain, info).await;
        }
    }
}

