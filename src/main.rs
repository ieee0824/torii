use clap::{CommandFactory, Parser};
use torii::cli::{Cli, Commands};
use torii::commands::*;
use torii::{error, logger};
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

fn open_logger(log_path: &str) -> error::Result<logger::Logger> {
    logger::Logger::open(log_path)
}

fn main() -> error::Result<()> {
    let cli = Cli::parse();

    // Handle commands that don't need DB or password
    if matches!(cli.command, Some(Commands::Namespaces)) {
        return cmd_namespaces();
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
        Some(Commands::Serve {
            env_path,
            once,
            timeout,
        }) => {
            let mut password = prompt_password()?;
            let result = cmd_serve(&db_path, &password, &env_path, once, timeout, &mut log);
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
        Some(Commands::Namespaces) | Some(Commands::Completions { .. }) => unreachable!(),
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
