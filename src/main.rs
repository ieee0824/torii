mod cli;
mod crypto;
mod db;
mod error;
mod fuse_fs;
mod logger;
mod tui;

use chrono::Local;
use clap::Parser;
use cli::{Cli, Commands};
use zeroize::Zeroize;

fn prompt_password() -> error::Result<String> {
    dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
        .map_err(|e| error::EnvsGateError::InvalidInput(format!("Password prompt failed: {e}")))
}

fn prompt_password_with_message(msg: &str) -> error::Result<String> {
    dialoguer::Password::new()
        .with_prompt(msg)
        .interact()
        .map_err(|e| error::EnvsGateError::InvalidInput(format!("Password prompt failed: {e}")))
}

fn prompt_new_password() -> error::Result<String> {
    dialoguer::Password::new()
        .with_prompt("New password")
        .with_confirmation("Confirm new password", "Passwords do not match")
        .interact()
        .map_err(|e| error::EnvsGateError::InvalidInput(format!("Password prompt failed: {e}")))
}

fn validate_namespace(ns: &str) -> error::Result<()> {
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

fn torii_home() -> error::Result<String> {
    let home = std::env::var("HOME")
        .map_err(|_| error::EnvsGateError::InvalidInput("HOME not set".into()))?;
    Ok(format!("{home}/.torii"))
}

fn resolve_paths(
    db_path: &Option<String>,
    namespace: &str,
    log_path: &Option<String>,
) -> error::Result<(String, String)> {
    if let Some(db) = db_path {
        // Explicit db-path: ignore namespace
        let log = log_path.clone().unwrap_or_else(logger::default_log_path);
        return Ok((db.clone(), log));
    }

    validate_namespace(namespace)?;
    let torii_home = torii_home()?;
    let ns_dir = format!("{torii_home}/{namespace}");
    std::fs::create_dir_all(&ns_dir).map_err(|e| {
        error::EnvsGateError::InvalidInput(format!("Cannot create namespace directory: {e}"))
    })?;

    // Restrict directory permissions to owner only (0o700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(&torii_home, perms.clone());
        let _ = std::fs::set_permissions(&ns_dir, perms);
    }

    let db = format!("{ns_dir}/torii.db");

    // P1: Warn if CWD has a legacy torii.db but namespace DB doesn't exist yet
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

    // P2: Migrate legacy audit log (~/.torii/audit.log → ~/.torii/default/audit.log)
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

fn open_logger(log_path: &str) -> error::Result<logger::Logger> {
    logger::Logger::open(log_path)
}

/// Unwrap DEK with auth failure logging
fn unwrap_dek_logged(
    password: &str,
    meta: &db::VaultMetadata,
    log: &mut Option<logger::Logger>,
) -> error::Result<[u8; 32]> {
    match crypto::unwrap_dek(password, meta) {
        Ok(dek) => Ok(dek),
        Err(e) => {
            if let Some(l) = log {
                l.log_auth_failed();
            }
            Err(e)
        }
    }
}

fn main() -> error::Result<()> {
    let cli = Cli::parse();

    // Handle namespaces command before resolving paths (no DB needed)
    if matches!(cli.command, Some(Commands::Namespaces)) {
        return cmd_namespaces();
    }

    let (db_path, log_path) = resolve_paths(&cli.db_path, &cli.namespace, &cli.log_path)?;
    let mut log = Some(open_logger(&log_path)?);

    match cli.command {
        None => return tui::run_interactive(&db_path, Some(&log_path)),
        Some(Commands::Set { key_value, expires }) => {
            let mut password = prompt_password()?;
            let result = cmd_set(
                &db_path,
                &password,
                &key_value,
                expires.as_deref(),
                &mut log,
            );
            password.zeroize();
            result?;
        }
        Some(Commands::Get { key }) => {
            let mut password = prompt_password()?;
            let result = cmd_get(&db_path, &password, &key, &mut log);
            password.zeroize();
            result?;
        }
        Some(Commands::List) => {
            let mut password = prompt_password()?;
            let result = cmd_list(&db_path, &password, &mut log);
            password.zeroize();
            result?;
        }
        Some(Commands::Delete { key }) => {
            let mut password = prompt_password()?;
            let result = cmd_delete(&db_path, &password, &key, &mut log);
            password.zeroize();
            result?;
        }
        Some(Commands::Serve { env_path, once }) => {
            let mut password = prompt_password()?;
            let result = cmd_serve(&db_path, &password, &env_path, once, &mut log);
            password.zeroize();
            result?;
        }
        Some(Commands::Exec { command }) => {
            let mut password = prompt_password()?;
            let result = cmd_exec(&db_path, &password, &command, &mut log);
            password.zeroize();
            let code = result?;
            std::process::exit(code);
        }
        Some(Commands::RotatePassword) => {
            let old_password = prompt_password_with_message("Old password: ")?;
            let mut new_password = prompt_new_password()?;
            let mut old_pw = old_password;
            let result = cmd_rotate_password(&db_path, &old_pw, &new_password, &mut log);
            old_pw.zeroize();
            new_password.zeroize();
            result?;
        }
        Some(Commands::RotateDek) => {
            let mut password = prompt_password()?;
            let result = cmd_rotate_dek(&db_path, &password, &mut log);
            password.zeroize();
            result?;
        }
        Some(Commands::Namespaces) => unreachable!(),
        Some(Commands::Logs { format }) => {
            let fmt = match format.as_str() {
                "json" => logger::LogFormat::Json,
                "tsv" => logger::LogFormat::Tsv,
                _ => {
                    return Err(error::EnvsGateError::InvalidInput(
                        "Invalid format. Use: json, tsv".into(),
                    ));
                }
            };
            logger::read_logs(&log_path, fmt)?;
        }
    }

    Ok(())
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

fn is_expired(expires_at: &str) -> bool {
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
    db_path: &str,
    password: &str,
    key_value: &str,
    expires: Option<&str>,
    log: &mut Option<logger::Logger>,
) -> error::Result<()> {
    let (key, value) = key_value
        .split_once('=')
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Expected KEY=VALUE format".into()))?;

    let resolved_expires = match expires {
        Some(exp) => Some(parse_expires(exp)?),
        None => None,
    };

    let conn = db::open_or_create_db(db_path)?;

    let dek = if db::is_initialized(&conn)? {
        unwrap_dek_logged(password, &db::load_metadata(&conn)?.unwrap(), log)?
    } else {
        let (vault_meta, dek) = crypto::init_vault(password)?;
        db::store_metadata(&conn, &vault_meta)?;
        dek
    };

    let (nonce, ciphertext) = crypto::encrypt_value(&dek, value.as_bytes())?;
    db::upsert_env_var(&conn, key, &nonce, &ciphertext, resolved_expires.as_deref())?;

    if let Some(l) = log {
        l.log_set(key, resolved_expires.as_deref());
    }

    if let Some(ref exp) = resolved_expires {
        eprintln!("Set: {key} (expires: {exp})");
    } else {
        eprintln!("Set: {key}");
    }
    Ok(())
}

pub fn cmd_get(
    db_path: &str,
    password: &str,
    key: &str,
    log: &mut Option<logger::Logger>,
) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = unwrap_dek_logged(password, &meta, log)?;

    let var = db::get_env_var(&conn, key)?
        .ok_or_else(|| error::EnvsGateError::KeyNotFound(key.into()))?;

    if let Some(ref exp) = var.expires_at
        && is_expired(exp)
    {
        if let Some(l) = log {
            l.log_expired(key);
        }
        return Err(error::EnvsGateError::KeyExpired {
            key: key.into(),
            expired_at: exp.clone(),
        });
    }

    if let Some(l) = log {
        l.log_get(key);
    }

    let mut plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
    println!("{}", String::from_utf8_lossy(&plaintext));
    plaintext.zeroize();
    Ok(())
}

pub fn cmd_list(
    db_path: &str,
    password: &str,
    log: &mut Option<logger::Logger>,
) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = unwrap_dek_logged(password, &meta, log)?;

    let vars = db::list_env_vars(&conn)?;

    if let Some(l) = log {
        l.log_list();
    }

    for var in &vars {
        let expired = var.expires_at.as_ref().is_some_and(|exp| is_expired(exp));

        let mut plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
        let value = String::from_utf8_lossy(&plaintext);

        if expired {
            println!(
                "{}={} [EXPIRED: {}]",
                var.key_name,
                value,
                var.expires_at.as_deref().unwrap()
            );
        } else if let Some(ref exp) = var.expires_at {
            println!("{}={} [expires: {}]", var.key_name, value, exp);
        } else {
            println!("{}={}", var.key_name, value);
        }

        drop(value);
        plaintext.zeroize();
    }

    Ok(())
}

pub fn cmd_delete(
    db_path: &str,
    password: &str,
    key: &str,
    log: &mut Option<logger::Logger>,
) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    // Verify password
    let _dek = unwrap_dek_logged(password, &meta, log)?;

    if db::delete_env_var(&conn, key)? {
        if let Some(l) = log {
            l.log_delete(key);
        }
        eprintln!("Deleted: {key}");
    } else {
        return Err(error::EnvsGateError::KeyNotFound(key.into()));
    }

    Ok(())
}

pub fn cmd_serve(
    db_path: &str,
    password: &str,
    env_path: &str,
    once: bool,
    log: &mut Option<logger::Logger>,
) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = unwrap_dek_logged(password, &meta, log)?;

    let vars = db::list_env_vars(&conn)?;
    for var in &vars {
        if let Some(ref exp) = var.expires_at
            && is_expired(exp)
        {
            if let Some(l) = log {
                l.log_expired(&var.key_name);
            }
            return Err(error::EnvsGateError::KeyExpired {
                key: var.key_name.clone(),
                expired_at: exp.clone(),
            });
        }
    }

    if let Some(l) = log {
        l.log_serve(env_path, once);
    }

    fuse_fs::serve(db_path, &dek, env_path, once)
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
    db_path: &str,
    password: &str,
    command: &[String],
    log: &mut Option<logger::Logger>,
) -> error::Result<i32> {
    if command.is_empty() {
        return Err(error::EnvsGateError::InvalidInput(
            "No command specified".into(),
        ));
    }

    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = unwrap_dek_logged(password, &meta, log)?;

    let vars = db::list_env_vars(&conn)?;
    let mut env_pairs = Vec::new();

    for var in &vars {
        if let Some(ref exp) = var.expires_at
            && is_expired(exp)
        {
            if let Some(l) = log {
                l.log_expired(&var.key_name);
            }
            return Err(error::EnvsGateError::KeyExpired {
                key: var.key_name.clone(),
                expired_at: exp.clone(),
            });
        }

        let plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
        let value = String::from_utf8(plaintext).map_err(|e| {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            error::EnvsGateError::InvalidInput(format!(
                "Value for '{}' contains invalid UTF-8",
                var.key_name
            ))
        })?;
        env_pairs.push((var.key_name.clone(), value));
    }

    if let Some(l) = log {
        l.log_exec(&command[0], env_pairs.len());
    }

    let program = &command[0];
    let args = &command[1..];

    // Install signal handlers before spawn so no window exists
    // where a signal could kill the parent without forwarding.
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
    Ok(status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |sig| 128 + sig)))
}

pub fn cmd_namespaces() -> error::Result<()> {
    let torii_home = torii_home()?;
    let path = std::path::Path::new(&torii_home);

    if !path.exists() {
        eprintln!("No namespaces found.");
        return Ok(());
    }

    let mut entries: Vec<String> = std::fs::read_dir(path)
        .map_err(|e| error::EnvsGateError::InvalidInput(format!("Cannot read directory: {e}")))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir() && e.path().join("torii.db").exists())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    entries.sort();

    if entries.is_empty() {
        eprintln!("No namespaces found.");
    } else {
        for ns in &entries {
            if ns == "default" {
                println!("{ns} (default)");
            } else {
                println!("{ns}");
            }
        }
    }

    Ok(())
}

pub fn cmd_rotate_password(
    db_path: &str,
    old_password: &str,
    new_password: &str,
    log: &mut Option<logger::Logger>,
) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;

    let mut dek = unwrap_dek_logged(old_password, &meta, log)?;
    let new_meta = crypto::wrap_dek(new_password, &dek)?;
    dek.zeroize();

    db::update_metadata(&conn, &new_meta)?;

    if let Some(l) = log {
        l.log_rotate_password();
    }

    eprintln!("Password rotated successfully");
    Ok(())
}

pub fn cmd_rotate_dek(
    db_path: &str,
    password: &str,
    log: &mut Option<logger::Logger>,
) -> error::Result<()> {
    let mut conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;

    let mut old_dek = unwrap_dek_logged(password, &meta, log)?;

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

    tx.commit().map_err(error::EnvsGateError::Db)?;

    if let Some(l) = log {
        l.log_rotate_dek(vars.len());
    }

    eprintln!(
        "DEK rotated successfully ({} values re-encrypted)",
        vars.len()
    );
    Ok(())
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

    // --- 統合テスト ---

    #[test]
    fn set_get_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "MY_KEY=my_value", None, &mut None).unwrap();

        let conn = db::open_or_create_db(db_path).unwrap();
        let meta = db::load_metadata(&conn).unwrap().unwrap();
        let dek = crypto::unwrap_dek("pw", &meta).unwrap();
        let var = db::get_env_var(&conn, "MY_KEY").unwrap().unwrap();
        let plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext).unwrap();
        assert_eq!(plaintext, b"my_value");

        cmd_delete(db_path, "pw", "MY_KEY", &mut None).unwrap();
        assert!(db::get_env_var(&conn, "MY_KEY").unwrap().is_none());
    }

    #[test]
    fn set_with_wrong_password_on_existing_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "correct", "K=V", None, &mut None).unwrap();
        let result = cmd_set(db_path, "wrong", "K2=V2", None, &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn get_nonexistent_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "EXISTS=yes", None, &mut None).unwrap();
        let result = cmd_get(db_path, "pw", "NOPE", &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn get_expired_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "OLD=val", Some("2000-01-01"), &mut None).unwrap();
        let result = cmd_get(db_path, "pw", "OLD", &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn delete_nonexistent_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();
        let result = cmd_delete(db_path, "pw", "MISSING", &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn set_invalid_key_value_format_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let result = cmd_set(db_path, "pw", "NO_EQUALS_SIGN", None, &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn set_with_expires_stores_datetime() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", Some("1h"), &mut None).unwrap();

        let conn = db::open_or_create_db(db_path).unwrap();
        let var = db::get_env_var(&conn, "K").unwrap().unwrap();
        assert!(var.expires_at.is_some());
        let exp = var.expires_at.unwrap();
        chrono::NaiveDateTime::parse_from_str(&exp, "%Y-%m-%dT%H:%M:%S").unwrap();
    }

    // --- ロガー統合テスト ---

    #[test]
    fn commands_write_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let log_path = dir.path().join("audit.log");
        let log_path_str = log_path.to_str().unwrap();

        let mut log = Some(logger::Logger::open(log_path_str).unwrap());

        cmd_set(db_path, "pw", "K=V", None, &mut log).unwrap();
        cmd_get(db_path, "pw", "K", &mut log).unwrap();
        cmd_list(db_path, "pw", &mut log).unwrap();
        cmd_delete(db_path, "pw", "K", &mut log).unwrap();

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

        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();
        let result = cmd_exec(db_path, "pw", &[], &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn exec_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();
        let result = cmd_exec(
            db_path,
            "wrong",
            &["echo".into(), "hello".into()],
            &mut None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn exec_with_expired_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "OLD=val", Some("2000-01-01"), &mut None).unwrap();
        let result = cmd_exec(db_path, "pw", &["echo".into()], &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn exec_uninitialized_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let result = cmd_exec(db_path, "pw", &["echo".into()], &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn exec_injects_env_vars() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let out_file = dir.path().join("out.txt");

        cmd_set(db_path, "pw", "TORII_TEST_VAR=hello123", None, &mut None).unwrap();

        let cmd = vec![
            "sh".into(),
            "-c".into(),
            format!("echo $TORII_TEST_VAR > {}", out_file.display()),
        ];
        let code = cmd_exec(db_path, "pw", &cmd, &mut None).unwrap();
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&out_file).unwrap();
        assert_eq!(content.trim(), "hello123");
    }

    #[test]
    fn exec_returns_child_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();

        let cmd = vec!["sh".into(), "-c".into(), "exit 42".into()];
        let code = cmd_exec(db_path, "pw", &cmd, &mut None).unwrap();
        assert_eq!(code, 42);
    }

    #[test]
    fn exec_signal_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();

        // Child sends SIGKILL to itself → exit code should be 128 + 9 = 137
        let cmd = vec!["sh".into(), "-c".into(), "kill -9 $$".into()];
        let code = cmd_exec(db_path, "pw", &cmd, &mut None).unwrap();
        assert_eq!(code, 137);
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

        cmd_set(db_path, "old_pw", "SECRET=hello", None, &mut None).unwrap();

        cmd_rotate_password(db_path, "old_pw", "new_pw", &mut None).unwrap();

        // Old password should fail
        let conn = db::open_or_create_db(db_path).unwrap();
        let meta = db::load_metadata(&conn).unwrap().unwrap();
        assert!(crypto::unwrap_dek("old_pw", &meta).is_err());

        // New password should work
        assert_eq!(decrypt_var(db_path, "new_pw", "SECRET"), "hello");
    }

    #[test]
    fn rotate_password_wrong_old_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();

        let result = cmd_rotate_password(db_path, "wrong", "new_pw", &mut None);
        assert!(result.is_err());

        // Original password should still work
        assert_eq!(decrypt_var(db_path, "pw", "K"), "V");
    }

    #[test]
    fn rotate_password_uninitialized_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let result = cmd_rotate_password(db_path, "old", "new", &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn rotate_password_preserves_multiple_vars() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "A=1", None, &mut None).unwrap();
        cmd_set(db_path, "pw", "B=2", None, &mut None).unwrap();
        cmd_set(db_path, "pw", "C=3", Some("2099-12-31"), &mut None).unwrap();

        cmd_rotate_password(db_path, "pw", "new_pw", &mut None).unwrap();

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

        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();

        let mut log = Some(logger::Logger::open(log_path.to_str().unwrap()).unwrap());
        cmd_rotate_password(db_path, "pw", "new_pw", &mut log).unwrap();
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

        cmd_set(db_path, "pw", "SECRET=hello", None, &mut None).unwrap();

        // Save old ciphertext
        let conn = db::open_or_create_db(db_path).unwrap();
        let old_var = db::get_env_var(&conn, "SECRET").unwrap().unwrap();
        let old_ciphertext = old_var.ciphertext.clone();
        let old_nonce = old_var.nonce.clone();
        drop(conn);

        cmd_rotate_dek(db_path, "pw", &mut None).unwrap();

        // Value should still be readable
        assert_eq!(decrypt_var(db_path, "pw", "SECRET"), "hello");

        // Ciphertext should have changed (new DEK + new nonce)
        let conn = db::open_or_create_db(db_path).unwrap();
        let new_var = db::get_env_var(&conn, "SECRET").unwrap().unwrap();
        assert_ne!(new_var.ciphertext, old_ciphertext);
        assert_ne!(new_var.nonce, old_nonce);
    }

    #[test]
    fn rotate_dek_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();

        let result = cmd_rotate_dek(db_path, "wrong", &mut None);
        assert!(result.is_err());

        // Original should still work
        assert_eq!(decrypt_var(db_path, "pw", "K"), "V");
    }

    #[test]
    fn rotate_dek_uninitialized_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let result = cmd_rotate_dek(db_path, "pw", &mut None);
        assert!(result.is_err());
    }

    #[test]
    fn rotate_dek_preserves_expires() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", Some("2099-12-31"), &mut None).unwrap();

        cmd_rotate_dek(db_path, "pw", &mut None).unwrap();

        let conn = db::open_or_create_db(db_path).unwrap();
        let var = db::get_env_var(&conn, "K").unwrap().unwrap();
        assert!(var.expires_at.unwrap().starts_with("2099-12-31"));
    }

    #[test]
    fn rotate_dek_empty_db_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        // Initialize DB with no env vars
        cmd_set(db_path, "pw", "K=V", None, &mut None).unwrap();
        cmd_delete(db_path, "pw", "K", &mut None).unwrap();

        cmd_rotate_dek(db_path, "pw", &mut None).unwrap();
    }

    #[test]
    fn rotate_dek_logs_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let log_path = dir.path().join("audit.log");

        cmd_set(db_path, "pw", "A=1", None, &mut None).unwrap();
        cmd_set(db_path, "pw", "B=2", None, &mut None).unwrap();

        let mut log = Some(logger::Logger::open(log_path.to_str().unwrap()).unwrap());
        cmd_rotate_dek(db_path, "pw", &mut log).unwrap();
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
        let (db, _log) = resolve_paths(&Some("./custom.db".into()), "myproject", &None).unwrap();
        assert_eq!(db, "./custom.db");
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

        // Create namespace directories with DBs
        let ns1 = format!("{home}/.torii/alpha");
        let ns2 = format!("{home}/.torii/beta");
        let ns_empty = format!("{home}/.torii/empty");
        std::fs::create_dir_all(&ns1).unwrap();
        std::fs::create_dir_all(&ns2).unwrap();
        std::fs::create_dir_all(&ns_empty).unwrap();
        std::fs::write(format!("{ns1}/torii.db"), b"").unwrap();
        std::fs::write(format!("{ns2}/torii.db"), b"").unwrap();
        // ns_empty has no torii.db, should not appear

        assert!(cmd_namespaces().is_ok());
    }

    #[test]
    fn exec_logs_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();
        let log_path = dir.path().join("audit.log");

        cmd_set(db_path, "pw", "A=1", None, &mut None).unwrap();
        cmd_set(db_path, "pw", "B=2", None, &mut None).unwrap();

        let mut log = Some(logger::Logger::open(log_path.to_str().unwrap()).unwrap());
        let cmd = vec!["true".into()];
        cmd_exec(db_path, "pw", &cmd, &mut log).unwrap();
        drop(log);

        let content = std::fs::read_to_string(&log_path).unwrap();
        let entry: logger::LogEntry =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.action, "exec");
        assert!(entry.detail.unwrap().contains("keys_injected=2"));
    }
}
