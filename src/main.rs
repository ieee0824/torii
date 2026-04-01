mod cli;
mod crypto;
mod db;
mod error;
mod fuse_fs;
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

fn main() -> error::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => return tui::run_interactive(&cli.db_path),
        Some(Commands::Set { key_value, expires }) => {
            let mut password = prompt_password()?;
            let result = cmd_set(&cli.db_path, &password, &key_value, expires.as_deref());
            password.zeroize();
            result?;
        }
        Some(Commands::Get { key }) => {
            let mut password = prompt_password()?;
            let result = cmd_get(&cli.db_path, &password, &key);
            password.zeroize();
            result?;
        }
        Some(Commands::List) => {
            let mut password = prompt_password()?;
            let result = cmd_list(&cli.db_path, &password);
            password.zeroize();
            result?;
        }
        Some(Commands::Delete { key }) => {
            let mut password = prompt_password()?;
            let result = cmd_delete(&cli.db_path, &password, &key);
            password.zeroize();
            result?;
        }
        Some(Commands::Serve { env_path, once }) => {
            let mut password = prompt_password()?;
            let result = cmd_serve(&cli.db_path, &password, &env_path, once);
            password.zeroize();
            result?;
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
        crypto::unwrap_dek(password, &db::load_metadata(&conn)?.unwrap())?
    } else {
        let (vault_meta, dek) = crypto::init_vault(password)?;
        db::store_metadata(&conn, &vault_meta)?;
        dek
    };

    let (nonce, ciphertext) = crypto::encrypt_value(&dek, value.as_bytes())?;
    db::upsert_env_var(&conn, key, &nonce, &ciphertext, resolved_expires.as_deref())?;

    if let Some(ref exp) = resolved_expires {
        eprintln!("Set: {key} (expires: {exp})");
    } else {
        eprintln!("Set: {key}");
    }
    Ok(())
}

pub fn cmd_get(db_path: &str, password: &str, key: &str) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let var = db::get_env_var(&conn, key)?
        .ok_or_else(|| error::EnvsGateError::KeyNotFound(key.into()))?;

    if let Some(ref exp) = var.expires_at
        && is_expired(exp)
    {
        return Err(error::EnvsGateError::KeyExpired {
            key: key.into(),
            expired_at: exp.clone(),
        });
    }

    let mut plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
    println!("{}", String::from_utf8_lossy(&plaintext));
    plaintext.zeroize();
    Ok(())
}

pub fn cmd_list(db_path: &str, password: &str) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let vars = db::list_env_vars(&conn)?;

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

pub fn cmd_delete(db_path: &str, password: &str, key: &str) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    // Verify password
    let _dek = crypto::unwrap_dek(password, &meta)?;

    if db::delete_env_var(&conn, key)? {
        eprintln!("Deleted: {key}");
    } else {
        return Err(error::EnvsGateError::KeyNotFound(key.into()));
    }

    Ok(())
}

pub fn cmd_serve(db_path: &str, password: &str, env_path: &str, once: bool) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let vars = db::list_env_vars(&conn)?;
    for var in &vars {
        if let Some(ref exp) = var.expires_at
            && is_expired(exp)
        {
            return Err(error::EnvsGateError::KeyExpired {
                key: var.key_name.clone(),
                expired_at: exp.clone(),
            });
        }
    }

    fuse_fs::serve(db_path, &dek, env_path, once)
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

    // --- is_expired: 正常系 ---

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

    // --- is_expired: 異常系 ---

    #[test]
    fn is_expired_invalid_format_returns_false() {
        assert!(!is_expired("not-a-date"));
    }

    #[test]
    fn is_expired_empty_returns_false() {
        assert!(!is_expired(""));
    }

    // --- cmd_set / cmd_get / cmd_delete 統合テスト ---

    #[test]
    fn set_get_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "MY_KEY=my_value", None).unwrap();

        let conn = db::open_or_create_db(db_path).unwrap();
        let meta = db::load_metadata(&conn).unwrap().unwrap();
        let dek = crypto::unwrap_dek("pw", &meta).unwrap();
        let var = db::get_env_var(&conn, "MY_KEY").unwrap().unwrap();
        let plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext).unwrap();
        assert_eq!(plaintext, b"my_value");

        cmd_delete(db_path, "pw", "MY_KEY").unwrap();
        assert!(db::get_env_var(&conn, "MY_KEY").unwrap().is_none());
    }

    #[test]
    fn set_with_wrong_password_on_existing_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "correct", "K=V", None).unwrap();
        let result = cmd_set(db_path, "wrong", "K2=V2", None);
        assert!(result.is_err());
    }

    #[test]
    fn get_nonexistent_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "EXISTS=yes", None).unwrap();
        let result = cmd_get(db_path, "pw", "NOPE");
        assert!(result.is_err());
    }

    #[test]
    fn get_expired_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "OLD=val", Some("2000-01-01")).unwrap();
        let result = cmd_get(db_path, "pw", "OLD");
        assert!(result.is_err());
    }

    #[test]
    fn delete_nonexistent_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", None).unwrap();
        let result = cmd_delete(db_path, "pw", "MISSING");
        assert!(result.is_err());
    }

    #[test]
    fn set_invalid_key_value_format_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        let result = cmd_set(db_path, "pw", "NO_EQUALS_SIGN", None);
        assert!(result.is_err());
    }

    #[test]
    fn set_with_expires_stores_datetime() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_path = db_path.to_str().unwrap();

        cmd_set(db_path, "pw", "K=V", Some("1h")).unwrap();

        let conn = db::open_or_create_db(db_path).unwrap();
        let var = db::get_env_var(&conn, "K").unwrap().unwrap();
        assert!(var.expires_at.is_some());
        let exp = var.expires_at.unwrap();
        chrono::NaiveDateTime::parse_from_str(&exp, "%Y-%m-%dT%H:%M:%S").unwrap();
    }
}
