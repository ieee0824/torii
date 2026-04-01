mod cli;
mod crypto;
mod db;
mod error;
#[cfg(feature = "fuse")]
mod fuse_fs;

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> error::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Set {
            password,
            key_value,
            expires,
        } => cmd_set(&cli.db_path, &password, &key_value, expires.as_deref())?,
        Commands::Get { password, key } => cmd_get(&cli.db_path, &password, &key)?,
        Commands::List { password } => cmd_list(&cli.db_path, &password)?,
        Commands::Delete { password, key } => cmd_delete(&cli.db_path, &password, &key)?,
        Commands::Serve { password, env_path } => cmd_serve(&cli.db_path, &password, &env_path)?,
    }

    Ok(())
}

fn cmd_set(db_path: &str, password: &str, key_value: &str, expires: Option<&str>) -> error::Result<()> {
    let (key, value) = key_value
        .split_once('=')
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Expected KEY=VALUE format".into()))?;

    if let Some(exp) = expires {
        chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d")
            .map_err(|e| error::EnvsGateError::InvalidInput(format!("Invalid date: {e}")))?;
    }

    let conn = db::open_or_create_db(db_path)?;

    let dek = if db::is_initialized(&conn)? {
        crypto::unwrap_dek(password, &db::load_metadata(&conn)?.unwrap())?
    } else {
        let (vault_meta, dek) = crypto::init_vault(password)?;
        db::store_metadata(&conn, &vault_meta)?;
        dek
    };

    let (nonce, ciphertext) = crypto::encrypt_value(&dek, value.as_bytes())?;
    db::upsert_env_var(&conn, key, &nonce, &ciphertext, expires)?;

    eprintln!("Set: {key}");
    Ok(())
}

fn cmd_get(db_path: &str, password: &str, key: &str) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let var = db::get_env_var(&conn, key)?
        .ok_or_else(|| error::EnvsGateError::KeyNotFound(key.into()))?;

    if let Some(ref exp) = var.expires_at {
        let exp_date = chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d")
            .map_err(|e| error::EnvsGateError::InvalidInput(format!("Invalid stored date: {e}")))?;
        if chrono::Local::now().date_naive() > exp_date {
            return Err(error::EnvsGateError::KeyExpired {
                key: key.into(),
                expired_at: exp.clone(),
            });
        }
    }

    let plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
    println!("{}", String::from_utf8_lossy(&plaintext));
    Ok(())
}

fn cmd_list(db_path: &str, password: &str) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = crypto::unwrap_dek(password, &meta)?;

    let vars = db::list_env_vars(&conn)?;
    let now = chrono::Local::now().date_naive();

    for var in &vars {
        let expired = var.expires_at.as_ref().is_some_and(|exp| {
            chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d")
                .map(|d| now > d)
                .unwrap_or(false)
        });

        let plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
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
    }

    Ok(())
}

fn cmd_delete(db_path: &str, password: &str, key: &str) -> error::Result<()> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let _dek = crypto::unwrap_dek(password, &meta)?;

    if db::delete_env_var(&conn, key)? {
        eprintln!("Deleted: {key}");
    } else {
        return Err(error::EnvsGateError::KeyNotFound(key.into()));
    }

    Ok(())
}

fn cmd_serve(db_path: &str, password: &str, env_path: &str) -> error::Result<()> {
    #[cfg(not(feature = "fuse"))]
    {
        let _ = (db_path, password, env_path);
        return Err(error::EnvsGateError::Fuse(
            "FUSE support not compiled. Rebuild with: cargo build --features fuse".into(),
        ));
    }

    #[cfg(feature = "fuse")]
    {
        let conn = db::open_or_create_db(db_path)?;
        let meta = db::load_metadata(&conn)?
            .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
        let dek = crypto::unwrap_dek(password, &meta)?;

        // Check for expired vars at startup
        let vars = db::list_env_vars(&conn)?;
        let now = chrono::Local::now().date_naive();
        for var in &vars {
            if let Some(ref exp) = var.expires_at {
                if let Ok(exp_date) = chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
                    if now > exp_date {
                        return Err(error::EnvsGateError::KeyExpired {
                            key: var.key_name.clone(),
                            expired_at: exp.clone(),
                        });
                    }
                }
            }
        }

        fuse_fs::serve(db_path, &dek, env_path)
    }
}
