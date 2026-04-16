use chrono::Local;
use rusqlite::Connection;
use zeroize::Zeroize;

use crate::{crypto, db, error, fuse_fs, logger};

// ---------------------------------------------------------------------------
// 参照透過性のための型定義
// ---------------------------------------------------------------------------

/// コマンドが生成する監査イベント（データとして返し、呼び出し元が Logger に書き込む）
#[derive(Debug, Clone)]
pub enum AuditEvent {
    Set {
        key: String,
        expires: Option<String>,
    },
    Get {
        key: String,
    },
    List,
    Delete {
        key: String,
    },
    Serve {
        env_path: String,
        once: bool,
        timeout: Option<u64>,
    },
    Exec {
        command: String,
        keys_injected: usize,
    },
    RotatePassword,
    RotateDek {
        reencrypted: usize,
    },
    Merge {
        ns_a: String,
        ns_b: String,
        total: usize,
        conflicts: usize,
    },
    AuthFailed,
    Expired {
        key: String,
    },
}

/// 純粋なコマンド出力: 計算結果 + 監査イベント
pub struct CommandOutput<T> {
    pub value: T,
    pub events: Vec<AuditEvent>,
}

impl<T> CommandOutput<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            events: Vec::new(),
        }
    }

    pub fn with_event(mut self, event: AuditEvent) -> Self {
        self.events.push(event);
        self
    }
}

/// `cmd_set` の結果
pub struct SetResult {
    pub key: String,
    pub expires: Option<String>,
}

/// `cmd_list` の各エントリ
pub struct ListEntry {
    pub key: String,
    pub value: String,
    pub expires_at: Option<String>,
    pub expired: bool,
}

/// 復号済み環境変数（共通型）
pub struct DecryptedVar {
    pub key: String,
    pub value: String,
    pub expires_at: Option<String>,
    pub expired: bool,
}

/// AuditEvent を Logger に書き込む
pub fn flush_events(events: &[AuditEvent], log: &mut Option<logger::Logger>) {
    if let Some(l) = log {
        for event in events {
            match event {
                AuditEvent::Set { key, expires } => l.log_set(key, expires.as_deref()),
                AuditEvent::Get { key } => l.log_get(key),
                AuditEvent::List => l.log_list(),
                AuditEvent::Delete { key } => l.log_delete(key),
                AuditEvent::Serve {
                    env_path,
                    once,
                    timeout,
                } => l.log_serve(env_path, *once, *timeout),
                AuditEvent::Exec {
                    command,
                    keys_injected,
                } => l.log_exec(command, *keys_injected),
                AuditEvent::RotatePassword => l.log_rotate_password(),
                AuditEvent::RotateDek { reencrypted } => l.log_rotate_dek(*reencrypted),
                AuditEvent::Merge {
                    ns_a,
                    ns_b,
                    total,
                    conflicts,
                } => l.log_merge(ns_a, ns_b, *total, *conflicts),
                AuditEvent::AuthFailed => l.log_auth_failed(),
                AuditEvent::Expired { key } => l.log_expired(key),
            }
        }
    }
}

/// エラー型から監査イベントを抽出して Logger に書き込む
pub fn flush_error_events(e: &error::EnvsGateError, log: &mut Option<logger::Logger>) {
    if let Some(l) = log {
        match e {
            error::EnvsGateError::AuthenticationFailed => l.log_auth_failed(),
            error::EnvsGateError::KeyExpired { key, .. } => l.log_expired(key),
            _ => {}
        }
    }
}

pub fn validate_namespace(ns: &str) -> error::Result<()> {
    if ns.is_empty() || ns == "." || ns == ".." {
        return Err(error::EnvsGateError::InvalidInput(
            "Invalid namespace name".into(),
        ));
    }
    if ns.len() > 64 {
        return Err(error::EnvsGateError::InvalidInput(
            "Namespace name must be 64 characters or fewer".into(),
        ));
    }
    if !ns
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(error::EnvsGateError::InvalidInput(
            "Namespace must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }
    Ok(())
}

pub fn home_dir() -> error::Result<String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            error::EnvsGateError::InvalidInput("HOME (or USERPROFILE on Windows) not set".into())
        })
}

pub fn torii_home() -> error::Result<String> {
    let home = home_dir()?;
    Ok(format!("{home}/.torii"))
}

pub fn resolve_paths(
    db_path: &Option<String>,
    namespace: &str,
    log_path: &Option<String>,
) -> error::Result<(String, String)> {
    if let Some(db) = db_path {
        let log = log_path.clone().unwrap_or_else(|| {
            let db_path = std::path::Path::new(db);
            let dir = db_path.parent().filter(|p| !p.as_os_str().is_empty());
            match dir {
                Some(d) => format!("{}/audit.log", d.display()),
                None => "audit.log".into(),
            }
        });
        return Ok((db.clone(), log));
    }

    validate_namespace(namespace)?;
    let torii_home = torii_home()?;
    let ns_dir = format!("{torii_home}/{namespace}");
    std::fs::create_dir_all(&ns_dir).map_err(|e| {
        error::EnvsGateError::InvalidInput(format!("Cannot create namespace directory: {e}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        if let Err(e) = std::fs::set_permissions(&torii_home, perms.clone()) {
            eprintln!("Warning: Failed to set permissions on '{torii_home}': {e}");
        }
        if let Err(e) = std::fs::set_permissions(&ns_dir, perms) {
            eprintln!("Warning: Failed to set permissions on '{ns_dir}': {e}");
        }
    }

    let db = format!("{ns_dir}/torii.db");

    if namespace == "default" && !std::path::Path::new(&db).exists() {
        let legacy_db = std::path::Path::new("torii.db");
        if legacy_db.exists() {
            eprintln!(
                "Warning: Found ./torii.db in current directory, but default namespace DB does not exist yet."
            );
            eprintln!("  To use the existing DB: torii --db-path ./torii.db <command>");
            eprintln!("  To migrate: mv ./torii.db {db}");
        }
    }

    let ns_log = format!("{ns_dir}/audit.log");
    if namespace == "default" && !std::path::Path::new(&ns_log).exists() {
        let legacy_log = format!("{torii_home}/audit.log");
        if std::path::Path::new(&legacy_log).exists() {
            if let Err(e) = std::fs::rename(&legacy_log, &ns_log) {
                eprintln!("Warning: Failed to migrate audit log: {e}");
            } else {
                eprintln!("Migrated audit log: {legacy_log} → {ns_log}");
            }
        }
    }

    let log = log_path.clone().unwrap_or(ns_log);
    Ok((db, log))
}

/// 全環境変数を復号して返す。期限切れは `expired` フラグで示すだけで、
/// スキップやエラーにはしない（ポリシーは呼び出し元が決める）。
pub fn decrypt_all_env_vars(conn: &Connection, dek: &[u8; 32]) -> error::Result<Vec<DecryptedVar>> {
    let vars = db::list_env_vars(conn)?;
    let mut result = Vec::with_capacity(vars.len());

    for var in &vars {
        let expired = var.expires_at.as_ref().is_some_and(|exp| is_expired(exp));

        let plaintext = crypto::decrypt_value(dek, &var.nonce, &var.ciphertext)?;
        let value = String::from_utf8(plaintext).map_err(|e| {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            error::EnvsGateError::InvalidInput(format!(
                "Value for '{}' contains invalid UTF-8",
                var.key_name
            ))
        })?;

        result.push(DecryptedVar {
            key: var.key_name.clone(),
            value,
            expires_at: var.expires_at.clone(),
            expired,
        });
    }

    Ok(result)
}

/// Parse an expiry string into an ISO 8601 datetime string.
/// Accepts:
///   - Relative: "30s", "5m", "1h", "7d" (seconds, minutes, hours, days)
///   - Absolute date: "2025-12-31"
///   - Absolute datetime: "2025-12-31T23:59:59"
pub fn parse_expires(input: &str) -> error::Result<String> {
    let input = input.trim();

    // Try relative duration: <number><unit>
    if let Some((num_str, unit)) = input
        .strip_suffix('s')
        .map(|n| (n, 's'))
        .or_else(|| input.strip_suffix('m').map(|n| (n, 'm')))
        .or_else(|| input.strip_suffix('h').map(|n| (n, 'h')))
        .or_else(|| input.strip_suffix('d').map(|n| (n, 'd')))
        && let Ok(num) = num_str.parse::<i64>()
    {
        let duration = match unit {
            's' => chrono::Duration::seconds(num),
            'm' => chrono::Duration::minutes(num),
            'h' => chrono::Duration::hours(num),
            'd' => chrono::Duration::days(num),
            _ => unreachable!(),
        };
        let expires_at = Local::now().naive_local() + duration;
        return Ok(expires_at.format("%Y-%m-%dT%H:%M:%S").to_string());
    }

    // Try absolute datetime
    if chrono::NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S").is_ok() {
        return Ok(input.to_string());
    }

    // Try absolute date (set to end of day)
    if let Ok(date) = chrono::NaiveDate::parse_from_str(input, "%Y-%m-%d") {
        let dt = date
            .and_hms_opt(23, 59, 59)
            .ok_or_else(|| error::EnvsGateError::InvalidInput("Invalid time".into()))?;
        return Ok(dt.format("%Y-%m-%dT%H:%M:%S").to_string());
    }

    Err(error::EnvsGateError::InvalidInput(format!(
        "Invalid expires format: '{input}'. Use: 30s, 5m, 1h, 7d, YYYY-MM-DD, or YYYY-MM-DDTHH:MM:SS"
    )))
}

pub fn is_expired(expires_at: &str) -> bool {
    let now = Local::now().naive_local();
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%dT%H:%M:%S") {
        return now > dt;
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(expires_at, "%Y-%m-%d") {
        return now.date() > d;
    }
    false
}

pub fn cmd_set(
    conn: &Connection,
    password: &str,
    key_value: &str,
    expires: Option<&str>,
) -> error::Result<CommandOutput<SetResult>> {
    let (key, value) = key_value
        .split_once('=')
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Expected KEY=VALUE format".into()))?;

    let resolved_expires = match expires {
        Some(exp) => Some(parse_expires(exp)?),
        None => None,
    };

    let dek = if db::is_initialized(conn)? {
        crypto::unwrap_dek(password, &db::load_metadata(conn)?.unwrap())?
    } else {
        let (vault_meta, dek) = crypto::init_vault(password)?;
        db::store_metadata(conn, &vault_meta)?;
        dek
    };

    let (nonce, ciphertext) = crypto::encrypt_value(&dek, value.as_bytes())?;
    db::upsert_env_var(conn, key, &nonce, &ciphertext, resolved_expires.as_deref())?;

    let result = SetResult {
        key: key.to_string(),
        expires: resolved_expires.clone(),
    };
    Ok(CommandOutput::new(result).with_event(AuditEvent::Set {
        key: key.to_string(),
        expires: resolved_expires,
    }))
}

pub fn cmd_get(
    conn: &Connection,
    password: &str,
    key: &str,
) -> error::Result<CommandOutput<String>> {
    let meta = db::load_metadata(conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let var =
        db::get_env_var(conn, key)?.ok_or_else(|| error::EnvsGateError::KeyNotFound(key.into()))?;

    if let Some(ref exp) = var.expires_at
        && is_expired(exp)
    {
        return Err(error::EnvsGateError::KeyExpired {
            key: key.into(),
            expired_at: exp.clone(),
        });
    }

    let mut plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
    let value = String::from_utf8_lossy(&plaintext).into_owned();
    plaintext.zeroize();

    Ok(CommandOutput::new(value).with_event(AuditEvent::Get {
        key: key.to_string(),
    }))
}

pub fn cmd_list(conn: &Connection, password: &str) -> error::Result<CommandOutput<Vec<ListEntry>>> {
    let meta = db::load_metadata(conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let decrypted = decrypt_all_env_vars(conn, &dek)?;
    let entries: Vec<ListEntry> = decrypted
        .into_iter()
        .map(|v| ListEntry {
            key: v.key,
            value: v.value,
            expires_at: v.expires_at,
            expired: v.expired,
        })
        .collect();

    Ok(CommandOutput::new(entries).with_event(AuditEvent::List))
}

pub fn cmd_delete(
    conn: &Connection,
    password: &str,
    key: &str,
) -> error::Result<CommandOutput<()>> {
    let meta = db::load_metadata(conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    // Verify password
    let _dek = crypto::unwrap_dek(password, &meta)?;

    if db::delete_env_var(conn, key)? {
        Ok(CommandOutput::new(()).with_event(AuditEvent::Delete {
            key: key.to_string(),
        }))
    } else {
        Err(error::EnvsGateError::KeyNotFound(key.into()))
    }
}

pub fn cmd_serve(
    conn: &Connection,
    db_path: &str,
    password: &str,
    env_path: &str,
    once: bool,
    timeout: Option<u64>,
) -> error::Result<CommandOutput<()>> {
    let meta = db::load_metadata(conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let vars = decrypt_all_env_vars(conn, &dek)?;
    if let Some(v) = vars.iter().find(|v| v.expired) {
        return Err(error::EnvsGateError::KeyExpired {
            key: v.key.clone(),
            expired_at: v.expires_at.clone().unwrap_or_default(),
        });
    }

    let events = vec![AuditEvent::Serve {
        env_path: env_path.to_string(),
        once,
        timeout,
    }];

    // serve は副作用だが、事前チェック後に実行
    fuse_fs::serve(db_path, &dek, env_path, once, timeout)?;

    Ok(CommandOutput { value: (), events })
}

static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn forward_signal_to_child(sig: libc::c_int) {
    let pid = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

fn install_signal_forwarder() {
    unsafe {
        for sig in [libc::SIGTERM, libc::SIGINT] {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = forward_signal_to_child as *const () as usize;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

pub fn cmd_exec(
    conn: &Connection,
    password: &str,
    command: &[String],
) -> error::Result<CommandOutput<i32>> {
    if command.is_empty() {
        return Err(error::EnvsGateError::InvalidInput(
            "No command specified".into(),
        ));
    }

    let meta = db::load_metadata(conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let vars = decrypt_all_env_vars(conn, &dek)?;
    if let Some(v) = vars.iter().find(|v| v.expired) {
        return Err(error::EnvsGateError::KeyExpired {
            key: v.key.clone(),
            expired_at: v.expires_at.clone().unwrap_or_default(),
        });
    }

    let env_pairs: Vec<(String, String)> = vars.into_iter().map(|v| (v.key, v.value)).collect();

    let keys_injected = env_pairs.len();
    let events = vec![AuditEvent::Exec {
        command: command[0].clone(),
        keys_injected,
    }];

    let program = &command[0];
    let args = &command[1..];

    install_signal_forwarder();

    // NOTE: On Linux, injected env vars are visible via /proc/<pid>/environ
    // to the process owner and root. This is an OS-level constraint.
    let mut child = std::process::Command::new(program)
        .args(args)
        .envs(env_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .spawn()
        .map_err(|e| {
            error::EnvsGateError::InvalidInput(format!("Failed to execute '{program}': {e}"))
        })?;

    // Zeroize decrypted values immediately after spawn
    for (_, mut val) in env_pairs {
        val.zeroize();
    }

    CHILD_PID.store(child.id() as i32, std::sync::atomic::Ordering::SeqCst);

    let status = child.wait().map_err(|e| {
        error::EnvsGateError::InvalidInput(format!("Failed to wait for child process: {e}"))
    })?;

    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |sig| 128 + sig));

    Ok(CommandOutput {
        value: code,
        events,
    })
}

pub fn list_namespace_names() -> error::Result<Vec<String>> {
    let torii_home = torii_home()?;
    let path = std::path::Path::new(&torii_home);

    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<String> = std::fs::read_dir(path)
        .map_err(|e| error::EnvsGateError::InvalidInput(format!("Cannot read directory: {e}")))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            p.is_dir() && (p.join("torii.db").exists() || p.join("audit.log").exists())
        })
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    entries.sort();
    Ok(entries)
}

pub fn cmd_namespaces() -> error::Result<Vec<String>> {
    list_namespace_names()
}

/// Decrypt all non-expired environment variables from a namespace DB.
/// Returns Vec of (key, plaintext_value, expires_at).
pub fn decrypt_all_vars(
    conn: &Connection,
    password: &str,
) -> error::Result<Vec<(String, String, Option<String>)>> {
    let meta = db::load_metadata(conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let vars = decrypt_all_env_vars(conn, &dek)?;
    let result = vars
        .into_iter()
        .filter(|v| {
            if v.expired {
                eprintln!(
                    "Warning: {} expired at {}, skipping",
                    v.key,
                    v.expires_at.as_deref().unwrap_or("unknown")
                );
                false
            } else {
                true
            }
        })
        .map(|v| (v.key, v.value, v.expires_at))
        .collect();

    Ok(result)
}

/// Execute a command with pre-built environment variable pairs.
pub fn exec_with_env(
    command: &[String],
    env_pairs: Vec<(String, String)>,
) -> error::Result<CommandOutput<i32>> {
    if command.is_empty() {
        return Err(error::EnvsGateError::InvalidInput(
            "No command specified".into(),
        ));
    }

    let keys_injected = env_pairs.len();
    let events = vec![AuditEvent::Exec {
        command: command[0].clone(),
        keys_injected,
    }];

    let program = &command[0];
    let args = &command[1..];

    install_signal_forwarder();

    let mut child = std::process::Command::new(program)
        .args(args)
        .envs(env_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .spawn()
        .map_err(|e| {
            error::EnvsGateError::InvalidInput(format!("Failed to execute '{program}': {e}"))
        })?;

    for (_, mut val) in env_pairs {
        val.zeroize();
    }

    CHILD_PID.store(child.id() as i32, std::sync::atomic::Ordering::SeqCst);

    let status = child.wait().map_err(|e| {
        error::EnvsGateError::InvalidInput(format!("Failed to wait for child process: {e}"))
    })?;

    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |sig| 128 + sig));

    Ok(CommandOutput {
        value: code,
        events,
    })
}

pub fn cmd_rotate_password(
    conn: &Connection,
    old_password: &str,
    new_password: &str,
) -> error::Result<CommandOutput<()>> {
    let meta = db::load_metadata(conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;

    let mut dek = crypto::unwrap_dek(old_password, &meta)?;
    let new_meta = crypto::wrap_dek(new_password, &dek)?;
    dek.zeroize();

    db::update_metadata(conn, &new_meta)?;

    Ok(CommandOutput::new(()).with_event(AuditEvent::RotatePassword))
}

pub fn cmd_rotate_dek(
    conn: &mut Connection,
    password: &str,
) -> error::Result<CommandOutput<usize>> {
    let meta = db::load_metadata(conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;

    let mut old_dek = crypto::unwrap_dek(password, &meta)?;

    // IMMEDIATE transaction to prevent concurrent writes during rotation
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(error::EnvsGateError::Db)?;

    // Decrypt all values with old DEK (inside transaction for consistency)
    let vars = db::list_env_vars(&tx)?;
    let mut decrypted: Vec<(String, zeroize::Zeroizing<Vec<u8>>, Option<String>)> = Vec::new();

    for var in &vars {
        let plaintext = crypto::decrypt_value(&old_dek, &var.nonce, &var.ciphertext)?;
        decrypted.push((
            var.key_name.clone(),
            zeroize::Zeroizing::new(plaintext),
            var.expires_at.clone(),
        ));
    }

    old_dek.zeroize();

    // Generate new DEK, wrap with same password, re-encrypt all values
    let (new_meta, mut new_dek) = crypto::init_vault(password)?;
    db::update_metadata(&tx, &new_meta)?;

    for (key, plaintext, expires_at) in &decrypted {
        let (nonce, ciphertext) = crypto::encrypt_value(&new_dek, plaintext)?;
        db::upsert_env_var(&tx, key, &nonce, &ciphertext, expires_at.as_deref())?;
    }

    new_dek.zeroize();
    drop(decrypted);

    let reencrypted = vars.len();
    tx.commit().map_err(error::EnvsGateError::Db)?;

    Ok(CommandOutput::new(reencrypted).with_event(AuditEvent::RotateDek { reencrypted }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_expires: 正常系 ---

    #[test]
    fn parse_expires_seconds() {
        let result = parse_expires("30s").unwrap();
        assert!(result.contains("T"));
        chrono::NaiveDateTime::parse_from_str(&result, "%Y-%m-%dT%H:%M:%S").unwrap();
    }

    #[test]
    fn parse_expires_minutes() {
        let result = parse_expires("5m").unwrap();
        chrono::NaiveDateTime::parse_from_str(&result, "%Y-%m-%dT%H:%M:%S").unwrap();
    }

    #[test]
    fn parse_expires_hours() {
        let result = parse_expires("1h").unwrap();
        chrono::NaiveDateTime::parse_from_str(&result, "%Y-%m-%dT%H:%M:%S").unwrap();
    }

    #[test]
    fn parse_expires_days() {
        let result = parse_expires("7d").unwrap();
        chrono::NaiveDateTime::parse_from_str(&result, "%Y-%m-%dT%H:%M:%S").unwrap();
    }

    #[test]
    fn parse_expires_absolute_date() {
        let result = parse_expires("2030-06-15").unwrap();
        assert_eq!(result, "2030-06-15T23:59:59");
    }

    #[test]
    fn parse_expires_absolute_datetime() {
        let result = parse_expires("2030-06-15T12:30:00").unwrap();
        assert_eq!(result, "2030-06-15T12:30:00");
    }

    #[test]
    fn parse_expires_with_whitespace() {
        let result = parse_expires("  1h  ").unwrap();
        chrono::NaiveDateTime::parse_from_str(&result, "%Y-%m-%dT%H:%M:%S").unwrap();
    }

    // --- parse_expires: 異常系 ---

    #[test]
    fn parse_expires_invalid_format() {
        assert!(parse_expires("abc").is_err());
    }

    #[test]
    fn parse_expires_empty() {
        assert!(parse_expires("").is_err());
    }

    #[test]
    fn parse_expires_invalid_unit() {
        assert!(parse_expires("5x").is_err());
    }

    #[test]
    fn parse_expires_invalid_date() {
        assert!(parse_expires("2030-13-01").is_err());
    }

    #[test]
    fn parse_expires_invalid_datetime() {
        assert!(parse_expires("2030-01-01T25:00:00").is_err());
    }

    // --- is_expired ---

    #[test]
    fn is_expired_past_datetime() {
        assert!(is_expired("2000-01-01T00:00:00"));
    }

    #[test]
    fn is_expired_future_datetime() {
        assert!(!is_expired("2099-12-31T23:59:59"));
    }

    #[test]
    fn is_expired_past_date() {
        assert!(is_expired("2000-01-01"));
    }

    #[test]
    fn is_expired_future_date() {
        assert!(!is_expired("2099-12-31"));
    }

    #[test]
    fn is_expired_invalid_format_returns_false() {
        assert!(!is_expired("not-a-date"));
    }

    #[test]
    fn is_expired_empty_returns_false() {
        assert!(!is_expired(""));
    }

    // --- テストヘルパー ---

    fn test_conn(db_path: &str) -> Connection {
        db::open_or_create_db(db_path).unwrap()
    }

    // --- 統合テスト ---

    #[test]
    fn set_get_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "MY_KEY=my_value", None).unwrap();

        let meta = db::load_metadata(&conn).unwrap().unwrap();
        let dek = crypto::unwrap_dek("pw", &meta).unwrap();
        let var = db::get_env_var(&conn, "MY_KEY").unwrap().unwrap();
        let plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext).unwrap();
        assert_eq!(plaintext, b"my_value");

        cmd_delete(&conn, "pw", "MY_KEY").unwrap();
        assert!(db::get_env_var(&conn, "MY_KEY").unwrap().is_none());
    }

    #[test]
    fn set_with_wrong_password_on_existing_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "correct", "K=V", None).unwrap();
        let result = cmd_set(&conn, "wrong", "K2=V2", None);
        assert!(result.is_err());
    }

    #[test]
    fn get_nonexistent_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "EXISTS=yes", None).unwrap();
        let result = cmd_get(&conn, "pw", "NOPE");
        assert!(result.is_err());
    }

    #[test]
    fn get_expired_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "OLD=val", Some("2000-01-01")).unwrap();
        let result = cmd_get(&conn, "pw", "OLD");
        assert!(result.is_err());
    }

    #[test]
    fn delete_nonexistent_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();
        let result = cmd_delete(&conn, "pw", "MISSING");
        assert!(result.is_err());
    }

    #[test]
    fn set_invalid_key_value_format_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        let result = cmd_set(&conn, "pw", "NO_EQUALS_SIGN", None);
        assert!(result.is_err());
    }

    #[test]
    fn set_with_expires_stores_datetime() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", Some("1h")).unwrap();

        let var = db::get_env_var(&conn, "K").unwrap().unwrap();
        assert!(var.expires_at.is_some());
        let exp = var.expires_at.unwrap();
        chrono::NaiveDateTime::parse_from_str(&exp, "%Y-%m-%dT%H:%M:%S").unwrap();
    }

    // --- ロガー統合テスト (flush_events 経由) ---

    #[test]
    fn commands_write_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let log_path = dir.path().join("audit.log");
        let log_path_str = log_path.to_str().unwrap();

        let mut log = Some(logger::Logger::open(log_path_str).unwrap());
        let conn = test_conn(db_path);

        let out = cmd_set(&conn, "pw", "K=V", None).unwrap();
        flush_events(&out.events, &mut log);
        let out = cmd_get(&conn, "pw", "K").unwrap();
        flush_events(&out.events, &mut log);
        let out = cmd_list(&conn, "pw").unwrap();
        flush_events(&out.events, &mut log);
        let out = cmd_delete(&conn, "pw", "K").unwrap();
        flush_events(&out.events, &mut log);

        drop(log);

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 4);

        let actions: Vec<String> = lines
            .iter()
            .map(|l| serde_json::from_str::<logger::LogEntry>(l).unwrap().action)
            .collect();
        assert_eq!(actions, vec!["set", "get", "list", "delete"]);
    }

    // --- exec テスト ---

    #[test]
    fn exec_empty_command_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();
        let result = cmd_exec(&conn, "pw", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn exec_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();
        let result = cmd_exec(&conn, "wrong", &["echo".into(), "hello".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn exec_with_expired_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "OLD=val", Some("2000-01-01")).unwrap();
        let result = cmd_exec(&conn, "pw", &["echo".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn exec_uninitialized_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        let result = cmd_exec(&conn, "pw", &["echo".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn exec_injects_env_vars() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let out_file = dir.path().join("out.txt");

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "TORII_TEST_VAR=hello123", None).unwrap();

        let cmd = vec![
            "sh".into(),
            "-c".into(),
            format!("echo $TORII_TEST_VAR > {}", out_file.display()),
        ];
        let output = cmd_exec(&conn, "pw", &cmd).unwrap();
        assert_eq!(output.value, 0);

        let content = std::fs::read_to_string(&out_file).unwrap();
        assert_eq!(content.trim(), "hello123");
    }

    #[test]
    fn exec_returns_child_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();

        let cmd = vec!["sh".into(), "-c".into(), "exit 42".into()];
        let output = cmd_exec(&conn, "pw", &cmd).unwrap();
        assert_eq!(output.value, 42);
    }

    #[test]
    fn exec_signal_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();

        // Child sends SIGKILL to itself → exit code should be 128 + 9 = 137
        let cmd = vec!["sh".into(), "-c".into(), "kill -9 $$".into()];
        let output = cmd_exec(&conn, "pw", &cmd).unwrap();
        assert_eq!(output.value, 137);
    }

    // --- rotate-password テスト ---

    fn decrypt_var(db_path: &str, password: &str, key: &str) -> String {
        let conn = db::open_or_create_db(db_path).unwrap();
        let meta = db::load_metadata(&conn).unwrap().unwrap();
        let dek = crypto::unwrap_dek(password, &meta).unwrap();
        let var = db::get_env_var(&conn, key).unwrap().unwrap();
        let plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext).unwrap();
        String::from_utf8(plaintext).unwrap()
    }

    #[test]
    fn rotate_password_changes_password() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "old_pw", "DATA=hello", None).unwrap();
        cmd_rotate_password(&conn, "old_pw", "new_pw").unwrap();

        // Old password should fail
        let meta = db::load_metadata(&conn).unwrap().unwrap();
        assert!(crypto::unwrap_dek("old_pw", &meta).is_err());

        // New password should work
        assert_eq!(decrypt_var(db_path, "new_pw", "DATA"), "hello");
    }

    #[test]
    fn rotate_password_wrong_old_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();

        let result = cmd_rotate_password(&conn, "wrong", "new_pw");
        assert!(result.is_err());

        // Original password should still work
        assert_eq!(decrypt_var(db_path, "pw", "K"), "V");
    }

    #[test]
    fn rotate_password_uninitialized_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        let result = cmd_rotate_password(&conn, "old", "new");
        assert!(result.is_err());
    }

    #[test]
    fn rotate_password_preserves_multiple_vars() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "A=1", None).unwrap();
        cmd_set(&conn, "pw", "B=2", None).unwrap();
        cmd_set(&conn, "pw", "C=3", Some("2099-12-31")).unwrap();
        cmd_rotate_password(&conn, "pw", "new_pw").unwrap();

        assert_eq!(decrypt_var(db_path, "new_pw", "A"), "1");
        assert_eq!(decrypt_var(db_path, "new_pw", "B"), "2");
        assert_eq!(decrypt_var(db_path, "new_pw", "C"), "3");
    }

    #[test]
    fn rotate_password_logs_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let log_path = dir.path().join("audit.log");

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();

        let mut log = Some(logger::Logger::open(log_path.to_str().unwrap()).unwrap());
        let out = cmd_rotate_password(&conn, "pw", "new_pw").unwrap();
        flush_events(&out.events, &mut log);
        drop(log);

        let content = std::fs::read_to_string(&log_path).unwrap();
        let entry: logger::LogEntry =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.action, "rotate_password");
    }

    // --- rotate-dek テスト ---

    #[test]
    fn rotate_dek_reencrypts_values() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "DATA=hello", None).unwrap();

        // Save old ciphertext
        let old_var = db::get_env_var(&conn, "DATA").unwrap().unwrap();
        let old_ciphertext = old_var.ciphertext.clone();
        let old_nonce = old_var.nonce.clone();
        drop(conn);

        let mut conn = db::open_or_create_db(db_path).unwrap();
        cmd_rotate_dek(&mut conn, "pw").unwrap();

        // Value should still be readable
        assert_eq!(decrypt_var(db_path, "pw", "DATA"), "hello");

        // Ciphertext should have changed (new DEK + new nonce)
        let new_var = db::get_env_var(&conn, "DATA").unwrap().unwrap();
        assert_ne!(new_var.ciphertext, old_ciphertext);
        assert_ne!(new_var.nonce, old_nonce);
    }

    #[test]
    fn rotate_dek_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();
        drop(conn);

        let mut conn = db::open_or_create_db(db_path).unwrap();
        let result = cmd_rotate_dek(&mut conn, "wrong");
        assert!(result.is_err());

        // Original should still work
        assert_eq!(decrypt_var(db_path, "pw", "K"), "V");
    }

    #[test]
    fn rotate_dek_uninitialized_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let mut conn = db::open_or_create_db(db_path).unwrap();
        let result = cmd_rotate_dek(&mut conn, "pw");
        assert!(result.is_err());
    }

    #[test]
    fn rotate_dek_preserves_expires() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", Some("2099-12-31")).unwrap();
        drop(conn);

        let mut conn = db::open_or_create_db(db_path).unwrap();
        cmd_rotate_dek(&mut conn, "pw").unwrap();

        let var = db::get_env_var(&conn, "K").unwrap().unwrap();
        assert!(var.expires_at.unwrap().starts_with("2099-12-31"));
    }

    #[test]
    fn rotate_dek_empty_db_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "K=V", None).unwrap();
        cmd_delete(&conn, "pw", "K").unwrap();
        drop(conn);

        let mut conn = db::open_or_create_db(db_path).unwrap();
        cmd_rotate_dek(&mut conn, "pw").unwrap();
    }

    #[test]
    fn rotate_dek_logs_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let log_path = dir.path().join("audit.log");

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "A=1", None).unwrap();
        cmd_set(&conn, "pw", "B=2", None).unwrap();
        drop(conn);

        let mut log = Some(logger::Logger::open(log_path.to_str().unwrap()).unwrap());
        let mut conn = db::open_or_create_db(db_path).unwrap();
        let out = cmd_rotate_dek(&mut conn, "pw").unwrap();
        flush_events(&out.events, &mut log);
        drop(log);

        let content = std::fs::read_to_string(&log_path).unwrap();
        let entry: logger::LogEntry =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.action, "rotate_dek");
        assert!(entry.detail.unwrap().contains("reencrypted=2"));
    }

    // --- namespace テスト ---

    #[test]
    fn validate_namespace_valid() {
        assert!(validate_namespace("default").is_ok());
        assert!(validate_namespace("my-project").is_ok());
        assert!(validate_namespace("project_1").is_ok());
        assert!(validate_namespace("ABC123").is_ok());
    }

    #[test]
    fn validate_namespace_invalid() {
        assert!(validate_namespace("").is_err());
        assert!(validate_namespace(".").is_err());
        assert!(validate_namespace("..").is_err());
        assert!(validate_namespace("foo/bar").is_err());
        assert!(validate_namespace("foo bar").is_err());
        assert!(validate_namespace("a@b").is_err());
        // Length limit
        assert!(validate_namespace(&"a".repeat(64)).is_ok());
        assert!(validate_namespace(&"a".repeat(65)).is_err());
    }

    #[test]
    fn resolve_paths_sets_directory_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        unsafe { std::env::set_var("HOME", home) };

        resolve_paths(&None, "permtest", &None).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let torii_dir = format!("{home}/.torii");
            let ns_dir = format!("{torii_dir}/permtest");
            let torii_perms = std::fs::metadata(&torii_dir).unwrap().permissions().mode() & 0o777;
            let ns_perms = std::fs::metadata(&ns_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(torii_perms, 0o700);
            assert_eq!(ns_perms, 0o700);
        }
    }

    #[test]
    fn resolve_paths_explicit_db_path_ignores_namespace() {
        let (db, log) = resolve_paths(&Some("./custom.db".into()), "myproject", &None).unwrap();
        assert_eq!(db, "./custom.db");
        assert_eq!(log, "./audit.log");
    }

    #[test]
    fn resolve_paths_explicit_db_path_log_adjacent() {
        let (_, log) =
            resolve_paths(&Some("/tmp/mydir/vault.db".into()), "default", &None).unwrap();
        assert_eq!(log, "/tmp/mydir/audit.log");
    }

    #[test]
    fn resolve_paths_bare_filename_db_path() {
        // bare filename like "custom.db" — parent is empty, log should be "audit.log" in CWD
        let (db, log) = resolve_paths(&Some("custom.db".into()), "default", &None).unwrap();
        assert_eq!(db, "custom.db");
        assert_eq!(log, "audit.log");
    }

    #[test]
    fn resolve_paths_namespace_creates_dir() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        unsafe { std::env::set_var("HOME", home) };

        let (db, log) = resolve_paths(&None, "testns", &None).unwrap();

        assert!(db.contains("/.torii/testns/torii.db"));
        assert!(log.contains("/.torii/testns/audit.log"));
        assert!(std::path::Path::new(&format!("{home}/.torii/testns")).is_dir());
    }

    #[test]
    fn resolve_paths_explicit_log_path_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        unsafe { std::env::set_var("HOME", home) };

        let (_, log) = resolve_paths(&None, "default", &Some("/tmp/custom.log".into())).unwrap();
        assert_eq!(log, "/tmp/custom.log");
    }

    #[test]
    fn resolve_paths_invalid_namespace_fails() {
        assert!(resolve_paths(&None, "../escape", &None).is_err());
        assert!(resolve_paths(&None, "", &None).is_err());
    }

    #[test]
    fn cmd_namespaces_with_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        unsafe { std::env::set_var("HOME", home) };

        // Should not error even if ~/.torii doesn't exist
        assert!(cmd_namespaces().is_ok());
    }

    #[test]
    fn cmd_namespaces_lists_existing() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        unsafe { std::env::set_var("HOME", home) };

        // Create namespace directories
        let ns1 = format!("{home}/.torii/alpha");
        let ns2 = format!("{home}/.torii/beta");
        let ns_log_only = format!("{home}/.torii/gamma");
        let ns_empty = format!("{home}/.torii/empty");
        std::fs::create_dir_all(&ns1).unwrap();
        std::fs::create_dir_all(&ns2).unwrap();
        std::fs::create_dir_all(&ns_log_only).unwrap();
        std::fs::create_dir_all(&ns_empty).unwrap();
        std::fs::write(format!("{ns1}/torii.db"), b"").unwrap();
        std::fs::write(format!("{ns2}/torii.db"), b"").unwrap();
        std::fs::write(format!("{ns_log_only}/audit.log"), b"").unwrap();
        // ns_empty has neither torii.db nor audit.log, should not appear

        assert!(cmd_namespaces().is_ok());
    }

    #[test]
    fn exec_logs_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let log_path = dir.path().join("audit.log");

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "A=1", None).unwrap();
        cmd_set(&conn, "pw", "B=2", None).unwrap();

        let mut log = Some(logger::Logger::open(log_path.to_str().unwrap()).unwrap());
        let cmd = vec!["true".into()];
        let out = cmd_exec(&conn, "pw", &cmd).unwrap();
        flush_events(&out.events, &mut log);
        drop(log);

        let content = std::fs::read_to_string(&log_path).unwrap();
        let entry: logger::LogEntry =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.action, "exec");
        assert!(entry.detail.unwrap().contains("keys_injected=2"));
    }

    // --- CommandOutput テスト ---

    #[test]
    fn command_output_with_event() {
        let out = CommandOutput::new(42).with_event(AuditEvent::Get {
            key: "K".to_string(),
        });
        assert_eq!(out.value, 42);
        assert_eq!(out.events.len(), 1);
    }

    #[test]
    fn cmd_get_returns_value() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "KEY=secret_value", None).unwrap();
        let out = cmd_get(&conn, "pw", "KEY").unwrap();
        assert_eq!(out.value, "secret_value");
        assert_eq!(out.events.len(), 1);
    }

    #[test]
    fn cmd_list_returns_entries() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "A=1", None).unwrap();
        cmd_set(&conn, "pw", "B=2", Some("2099-12-31")).unwrap();

        let out = cmd_list(&conn, "pw").unwrap();
        assert_eq!(out.value.len(), 2);
        assert_eq!(out.value[0].key, "A");
        assert_eq!(out.value[0].value, "1");
        assert!(!out.value[0].expired);
        assert_eq!(out.value[1].key, "B");
        assert!(out.value[1].expires_at.is_some());
    }

    #[test]
    fn decrypt_all_env_vars_marks_expired() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let conn = test_conn(db_path);
        cmd_set(&conn, "pw", "LIVE=val", None).unwrap();
        cmd_set(&conn, "pw", "OLD=val", Some("2000-01-01")).unwrap();

        let meta = db::load_metadata(&conn).unwrap().unwrap();
        let dek = crypto::unwrap_dek("pw", &meta).unwrap();
        let vars = decrypt_all_env_vars(&conn, &dek).unwrap();

        assert_eq!(vars.len(), 2);
        let live = vars.iter().find(|v| v.key == "LIVE").unwrap();
        let old = vars.iter().find(|v| v.key == "OLD").unwrap();
        assert!(!live.expired);
        assert!(old.expired);
    }
}
