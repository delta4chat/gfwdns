use crate::*;

#[derive(Debug, Clone)]
pub struct Database {
    pool: Arc<SqlitePool>,
}
impl Database {
    #[inline(always)]
    pub async fn new(db_file: impl AsRef<Path>) -> anyhow::Result<Self> {
        let db_file = db_file.as_ref();

        let pool =
            SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .max_lifetime(None)
            .idle_timeout(None)
            .connect_with(
                SqliteConnectOptions::new()
                .filename(db_file)
                .create_if_missing(true)
                .read_only(false)
                .journal_mode(SqliteJournalMode::Wal)
                .locking_mode(SqliteLockingMode::Normal)
                .synchronous(SqliteSynchronous::Normal)
            ).await.context("sqlx cannot connect to sqlite db")?;

        sqlx::query("CREATE TABLE IF NOT EXISTS gfwdns_cache_v1 (domain TEXT NOT NULL UNIQUE, info BLOB NOT NULL) STRICT")
        .execute(&pool).await.context("sqlx cannot create table in opened sqlite db")?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    #[inline(always)]
    pub async fn load_all(&self) -> Vec<DomainStatusInfo> {
        let mut out = Vec::new();
        let mut bads = Vec::new();

        let mut res = sqlx::query("SELECT * FROM gfwdns_cache_v1").fetch(&*self.pool);
        while let Ok(Some(line)) = res.try_next().await {
            assert_eq!(line.len(), 2);

            let domain: String =
                match
                    line.try_get(0)
                    .context("unable load string 'domain' from sqlite (col.0)")
                    .log_error()
                {
                    Ok(maybe_val) => {
                        if let Some(val) = maybe_val {
                            val
                        } else {
                            continue;
                        }
                    },
                    _ => {
                        continue;
                    }
                };

            let info: Vec<u8> =
                match
                    line.try_get(1)
                    .context("unable load postcard-encoded 'info' from sqlite (col.1)")
                    .log_error()
                {
                    Ok(maybe_val) => {
                        if let Some(val) = maybe_val {
                            val
                        } else {
                            bads.push(domain);
                            continue;
                        }
                    },
                    _ => {
                        bads.push(domain);
                        continue;
                    }
                };

            let info: DomainStatusInfo =
                match
                    postcard::from_bytes(&info)
                    .context("unable deserialize postcard-encoded 'info' to DomainStatusInfo")
                    .log_error()
                {
                    Ok(maybe_val) => {
                        if let Some(val) = maybe_val {
                            val
                        } else {
                            bads.push(domain);
                            continue;
                        }
                    },
                    _ => {
                        bads.push(domain);
                        continue;
                    }
                };

            if &domain != info.domain() {
                log::error!("invalid line from sqlite: col.0 != info.domain");
                bads.push(domain);
                continue;
            }

            out.push(info);
        }

        drop(res);

        for bad in bads.iter() {
            let _ =
                sqlx::query("DELETE FROM gfwdns_cache_v1 WHERE domain = ?")
                .bind(bad)
                .execute(&*self.pool)
                .await;
        }

        out
    }

    #[inline(always)]
    pub async fn load(&self, domain: &str) -> anyhow::Result<DomainStatusInfo> {
        let ret = self._load(domain).await;

        if ret.is_err() {
            let _ =
                sqlx::query("DELETE FROM gfwdns_cache_v1 WHERE domain = ?")
                .bind(domain)
                .execute(&*self.pool)
                .await;
        }

        let maybe_info = ret?;

        if let Some(info) = maybe_info {
            Ok(info)
        } else {
            anyhow::bail!("no info yet");
        }
    }

    #[inline(always)]
    async fn _load(&self, domain: &str) -> anyhow::Result<Option<DomainStatusInfo>> {
        let maybe_line =
            sqlx::query("SELECT * FROM gfwdns_cache_v1 WHERE domain = ?")
            .bind(domain)
            .fetch_one(&*self.pool)
            .await;

        let line =
            match maybe_line {
                Ok(val) => val,
                _ => {
                    return Ok(None);
                }
            };

        let info: Vec<u8> = line.try_get(1)?;
        let info: DomainStatusInfo = postcard::from_bytes(&info)?;

        Ok(Some(info))
    }

    #[inline(always)]
    pub async fn store(&self, domain: &str, info: DomainStatusInfo) -> anyhow::Result<()> {
        let info: Vec<u8> = postcard::to_allocvec(&info)?;

        sqlx::query("INSERT OR IGNORE INTO gfwdns_cache_v1 VALUES (?1, ?2); UPDATE gfwdns_cache_v1 SET info = ?2 WHERE domain = ?1")
        .bind(domain).bind(info)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }
}
