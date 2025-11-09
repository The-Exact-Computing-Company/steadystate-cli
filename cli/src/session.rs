use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
// The `tokio::task` import is no longer needed, so we remove it.
// use tokio::task; 
use tracing::warn;

use crate::auth::extract_exp_from_jwt;
use crate::config::{CONFIG_OVERRIDE_ENV, SERVICE_NAME};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    pub login: String,
    pub jwt: String,
    pub jwt_exp: Option<u64>, // epoch seconds
}

impl Session {
    pub fn new(login: String, jwt: String) -> Self {
        let jwt_exp = extract_exp_from_jwt(&jwt);
        Self {
            login,
            jwt,
            jwt_exp,
        }
    }

    pub fn is_near_expiry(&self, buffer_secs: u64) -> bool {
        if let Some(exp) = self.jwt_exp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            exp <= now + buffer_secs
        } else {
            false
        }
    }
}

pub async fn cfg_dir() -> Result<PathBuf> {
    if let Ok(override_dir) = std::env::var(CONFIG_OVERRIDE_ENV) {
        let mut p = PathBuf::from(override_dir);
        tokio::fs::create_dir_all(&p)
            .await
            .context("create override config dir")?;
        p.push(SERVICE_NAME);
        tokio::fs::create_dir_all(&p)
            .await
            .context("create service config dir")?;
        return Ok(p);
    }

    let mut p = dirs::config_dir().context("could not determine config directory")?;
    p.push(SERVICE_NAME);
    tokio::fs::create_dir_all(&p)
        .await
        .context("create config dir")?;
    Ok(p)
}

pub async fn session_file() -> Result<PathBuf> {
    Ok(cfg_dir().await?.join("session.json"))
}

// ** THIS IS THE ONLY FUNCTION THAT CHANGES **
// We replace the complex spawn_blocking logic with a simple, robust async write.
pub async fn write_session(session: &Session) -> Result<()> {
    let path = session_file().await?;
    let data = serde_json::to_vec_pretty(session)?;

    tokio::fs::write(&path, &data)
        .await
        .context("write session file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Note: Using async version for setting permissions as well for consistency.
        if let Err(e) =
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await
        {
            warn!("Failed to set strict permissions on session file: {}", e);
        }
    }

    Ok(())
}


pub async fn read_session() -> Result<Session> {
    let path = session_file().await?;
    let bytes = tokio::fs::read(&path).await.context("read session file")?;
    let session: Session = serde_json::from_slice(&bytes).context("parse session json")?;
    Ok(session)
}

pub async fn remove_session() -> Result<()> {
    let path = session_file().await?;
    match tokio::fs::remove_file(path).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("remove session file"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    use tempfile::tempdir;

    static TEST_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct TestContext {
        _guard: std::sync::LockResult<std::sync::MutexGuard<'static, ()>>,
        _dir: tempfile::TempDir,
    }

    impl TestContext {
        fn new() -> Self {
            let guard = TEST_GUARD.lock();
            let dir = tempdir().expect("create tempdir");
            // Set the environment variable to the tempdir path
            // ** Reverting to your original, correct use of `unsafe` **
            unsafe {
                std::env::set_var(CONFIG_OVERRIDE_ENV, dir.path().to_str().unwrap());
            }
            Self {
                _guard: guard,
                _dir: dir,
            }
        }
    }

    impl Drop for TestContext {
        fn drop(&mut self) {
            // Clean up the environment variable
            // ** Reverting to your original, correct use of `unsafe` **
            unsafe {
                std::env::remove_var(CONFIG_OVERRIDE_ENV);
            }
        }
    }

    #[tokio::test]
    async fn test_write_read_cycle() {
        let _ctx = TestContext::new();
        
        let _ = remove_session().await;
        
        let session = Session {
            login: "test_user".into(),
            jwt: "fake_jwt".into(),
            jwt_exp: Some(42),
        };
        
        write_session(&session).await.unwrap();
        
        let loaded = read_session().await.unwrap();
        
        assert_eq!(loaded.login, session.login);
        assert_eq!(loaded.jwt, session.jwt);
        assert_eq!(loaded.jwt_exp, session.jwt_exp);
    }

    #[tokio::test]
    async fn test_remove_missing_session_ok() {
        let _ctx = TestContext::new();
        remove_session().await.unwrap();
    }
}
