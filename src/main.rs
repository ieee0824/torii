use clap::{CommandFactory, Parser};
use torii::cli::{Cli, Commands};
use torii::commands::*;
use torii::error::EnvsGateError;
use torii::{db, error, logger};
use zeroize::Zeroize;

fn prompt_password() -> error::Result<String> {
    dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
        .map_err(|e| EnvsGateError::InvalidInput(format!("Password prompt failed: {e}")))
}

fn prompt_password_with_message(msg: &str) -> error::Result<String> {
    dialoguer::Password::new()
        .with_prompt(msg)
        .interact()
        .map_err(|e| EnvsGateError::InvalidInput(format!("Password prompt failed: {e}")))
}

fn prompt_new_password() -> error::Result<String> {
    dialoguer::Password::new()
        .with_prompt("New password")
        .with_confirmation("Confirm new password", "Passwords do not match")
        .interact()
        .map_err(|e| EnvsGateError::InvalidInput(format!("Password prompt failed: {e}")))
}

fn open_logger(log_path: &str) -> error::Result<logger::Logger> {
    logger::Logger::open(log_path)
}

/// エラー時の監査イベントをログに書き込んでからエラーを返す
fn handle_error(e: error::EnvsGateError, log: &mut Option<logger::Logger>) -> error::EnvsGateError {
    flush_error_events(&e, log);
    e
}

fn main() -> error::Result<()> {
    let cli = Cli::parse();

    // Handle commands that don't need DB or password
    if matches!(cli.command, Some(Commands::Namespaces)) {
        let entries = cmd_namespaces()?;
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
        return Ok(());
    }
    if let Some(Commands::Completions { shell }) = &cli.command {
        clap_complete::generate(*shell, &mut Cli::command(), "torii", &mut std::io::stdout());
        return Ok(());
    }

    let (db_path, log_path) = resolve_paths(&cli.db_path, &cli.namespace, &cli.log_path)?;
    let mut log = Some(open_logger(&log_path)?);

    match cli.command {
        None => return torii::tui::run_interactive(&db_path, Some(&log_path)),
        Some(Commands::Set { key_value, expires }) => {
            let mut password = prompt_password()?;
            let conn = db::open_or_create_db(&db_path)?;
            let result = cmd_set(&conn, &password, &key_value, expires.as_deref());
            password.zeroize();
            match result {
                Ok(output) => {
                    flush_events(&output.events, &mut log);
                    if let Some(ref exp) = output.value.expires {
                        eprintln!("Set: {} (expires: {exp})", output.value.key);
                    } else {
                        eprintln!("Set: {}", output.value.key);
                    }
                }
                Err(e) => return Err(handle_error(e, &mut log)),
            }
        }
        Some(Commands::Get { key }) => {
            let mut password = prompt_password()?;
            let conn = db::open_or_create_db(&db_path)?;
            let result = cmd_get(&conn, &password, &key);
            password.zeroize();
            match result {
                Ok(output) => {
                    flush_events(&output.events, &mut log);
                    let mut value = output.value;
                    println!("{value}");
                    value.zeroize();
                }
                Err(e) => return Err(handle_error(e, &mut log)),
            }
        }
        Some(Commands::List) => {
            let mut password = prompt_password()?;
            let conn = db::open_or_create_db(&db_path)?;
            let result = cmd_list(&conn, &password);
            password.zeroize();
            match result {
                Ok(output) => {
                    flush_events(&output.events, &mut log);
                    for entry in &output.value {
                        if entry.expired {
                            println!(
                                "{}={} [EXPIRED: {}]",
                                entry.key,
                                entry.value,
                                entry.expires_at.as_deref().unwrap()
                            );
                        } else if let Some(ref exp) = entry.expires_at {
                            println!("{}={} [expires: {}]", entry.key, entry.value, exp);
                        } else {
                            println!("{}={}", entry.key, entry.value);
                        }
                    }
                    for mut entry in output.value {
                        entry.value.zeroize();
                    }
                }
                Err(e) => return Err(handle_error(e, &mut log)),
            }
        }
        Some(Commands::Delete { key }) => {
            let mut password = prompt_password()?;
            let conn = db::open_or_create_db(&db_path)?;
            let result = cmd_delete(&conn, &password, &key);
            password.zeroize();
            match result {
                Ok(output) => {
                    flush_events(&output.events, &mut log);
                    eprintln!("Deleted: {key}");
                }
                Err(e) => return Err(handle_error(e, &mut log)),
            }
        }
        Some(Commands::Serve {
            env_path,
            once,
            timeout,
        }) => {
            let mut password = prompt_password()?;
            let conn = db::open_or_create_db(&db_path)?;
            let result = cmd_serve(&conn, &db_path, &password, &env_path, once, timeout);
            password.zeroize();
            match result {
                Ok(output) => {
                    flush_events(&output.events, &mut log);
                }
                Err(e) => return Err(handle_error(e, &mut log)),
            }
        }
        Some(Commands::Exec { command }) => {
            let mut password = prompt_password()?;
            let conn = db::open_or_create_db(&db_path)?;
            let result = cmd_exec(&conn, &password, &command);
            password.zeroize();
            match result {
                Ok(output) => {
                    flush_events(&output.events, &mut log);
                    std::process::exit(output.value);
                }
                Err(e) => return Err(handle_error(e, &mut log)),
            }
        }
        Some(Commands::RotatePassword) => {
            let old_password = prompt_password_with_message("Old password: ")?;
            let mut new_password = prompt_new_password()?;
            let mut old_pw = old_password;
            let conn = db::open_or_create_db(&db_path)?;
            let result = cmd_rotate_password(&conn, &old_pw, &new_password);
            old_pw.zeroize();
            new_password.zeroize();
            match result {
                Ok(output) => {
                    flush_events(&output.events, &mut log);
                    eprintln!("Password rotated successfully");
                }
                Err(e) => return Err(handle_error(e, &mut log)),
            }
        }
        Some(Commands::RotateDek) => {
            let mut password = prompt_password()?;
            let mut conn = db::open_or_create_db(&db_path)?;
            let result = cmd_rotate_dek(&mut conn, &password);
            password.zeroize();
            match result {
                Ok(output) => {
                    flush_events(&output.events, &mut log);
                    eprintln!(
                        "DEK rotated successfully ({} values re-encrypted)",
                        output.value
                    );
                }
                Err(e) => return Err(handle_error(e, &mut log)),
            }
        }
        Some(Commands::Namespaces) | Some(Commands::Completions { .. }) => unreachable!(),
        Some(Commands::Logs { format }) => {
            let fmt = match format.as_str() {
                "json" => logger::LogFormat::Json,
                "tsv" => logger::LogFormat::Tsv,
                _ => {
                    return Err(EnvsGateError::InvalidInput(
                        "Invalid format. Use: json, tsv".into(),
                    ));
                }
            };
            logger::read_logs(&log_path, fmt)?;
        }
    }

    Ok(())
}
