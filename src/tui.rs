use dialoguer::{Confirm, Input, Password, Select};

use crate::error::{EnvsGateError, Result};
use crate::logger::Logger;
use crate::{cmd_delete, cmd_get, cmd_list, cmd_serve, cmd_set, crypto, db};

fn io_err(e: dialoguer::Error) -> EnvsGateError {
    EnvsGateError::InvalidInput(format!("Prompt error: {e}"))
}

pub fn run_interactive(db_path: &str, log_path: Option<&str>) -> Result<()> {
    let mut log: Option<Logger> = match log_path {
        Some(p) => Some(Logger::open(p)?),
        None => None,
    };

    let password: String = Password::new()
        .with_prompt("Password")
        .interact()
        .map_err(io_err)?;

    // Verify password if DB already exists
    let conn = db::open_or_create_db(db_path)?;
    if db::is_initialized(&conn)? {
        let meta = db::load_metadata(&conn)?.unwrap();
        if let Err(e) = crypto::unwrap_dek(&password, &meta) {
            if let Some(l) = &mut log {
                l.log_auth_failed();
            }
            return Err(e);
        }
    }
    drop(conn);

    loop {
        let actions = &[
            "Set environment variable",
            "Get environment variable",
            "List all variables",
            "Delete environment variable",
            "Serve virtual .env",
            "Exit",
        ];

        let choice = Select::new()
            .with_prompt("What do you want to do?")
            .items(actions)
            .default(0)
            .interact()
            .map_err(io_err)?;

        let result = match choice {
            0 => interactive_set(db_path, &password, &mut log),
            1 => interactive_get(db_path, &password, &mut log),
            2 => cmd_list(db_path, &password, &mut log),
            3 => interactive_delete(db_path, &password, &mut log),
            4 => interactive_serve(db_path, &password, &mut log),
            5 => break,
            _ => unreachable!(),
        };

        if let Err(e) = result {
            eprintln!("Error: {e}");
        }

        println!();
    }

    Ok(())
}

fn interactive_set(db_path: &str, password: &str, log: &mut Option<Logger>) -> Result<()> {
    let key: String = Input::new()
        .with_prompt("Key")
        .interact_text()
        .map_err(io_err)?;

    let value: String = Input::new()
        .with_prompt("Value")
        .interact_text()
        .map_err(io_err)?;

    let set_expires = Confirm::new()
        .with_prompt("Set expiration?")
        .default(false)
        .interact()
        .map_err(io_err)?;

    let expires = if set_expires {
        let date: String = Input::new()
            .with_prompt("Expires (e.g. 1h, 7d, 2025-12-31)")
            .interact_text()
            .map_err(io_err)?;
        Some(date)
    } else {
        None
    };

    let key_value = format!("{key}={value}");
    cmd_set(db_path, password, &key_value, expires.as_deref(), log)
}

fn interactive_get(db_path: &str, password: &str, log: &mut Option<Logger>) -> Result<()> {
    let key: String = Input::new()
        .with_prompt("Key")
        .interact_text()
        .map_err(io_err)?;

    cmd_get(db_path, password, &key, log)
}

fn interactive_delete(db_path: &str, password: &str, log: &mut Option<Logger>) -> Result<()> {
    let key: String = Input::new()
        .with_prompt("Key")
        .interact_text()
        .map_err(io_err)?;

    let confirmed = Confirm::new()
        .with_prompt(format!("Delete {key}?"))
        .default(false)
        .interact()
        .map_err(io_err)?;

    if confirmed {
        cmd_delete(db_path, password, &key, log)
    } else {
        eprintln!("Cancelled.");
        Ok(())
    }
}

fn interactive_serve(db_path: &str, password: &str, log: &mut Option<Logger>) -> Result<()> {
    let env_path: String = Input::new()
        .with_prompt(".env path")
        .default(".env".into())
        .interact_text()
        .map_err(io_err)?;

    let once = Confirm::new()
        .with_prompt("Exit after first read?")
        .default(true)
        .interact()
        .map_err(io_err)?;

    cmd_serve(db_path, password, &env_path, once, None, log)
}
