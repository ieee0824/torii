use std::collections::{BTreeMap, BTreeSet};

use dialoguer::{Confirm, Input, Password, Select};
use zeroize::Zeroize;

use crate::commands::{
    cmd_delete, cmd_get, cmd_list, cmd_serve, cmd_set, decrypt_all_vars, exec_with_env,
    list_namespace_names, resolve_paths,
};
use crate::error::{EnvsGateError, Result};
use crate::fuse_fs;
use crate::logger::Logger;
use crate::{crypto, db};

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
            "Merge namespaces",
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
            5 => interactive_merge(&mut log),
            6 => break,
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

fn interactive_merge(log: &mut Option<Logger>) -> Result<()> {
    let namespaces = list_namespace_names()?;
    if namespaces.len() < 2 {
        eprintln!("Namespace が 2 つ以上必要です。");
        return Ok(());
    }

    // namespace A を選択
    let idx_a = Select::new()
        .with_prompt("Namespace A")
        .items(&namespaces)
        .default(0)
        .interact()
        .map_err(io_err)?;

    // namespace B を選択（A と同じものは除外）
    let ns_b_items: Vec<&String> = namespaces
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != idx_a)
        .map(|(_, n)| n)
        .collect();
    let idx_b = Select::new()
        .with_prompt("Namespace B")
        .items(&ns_b_items)
        .default(0)
        .interact()
        .map_err(io_err)?;

    let ns_a = &namespaces[idx_a];
    let ns_b = ns_b_items[idx_b];

    // パスを解決
    let (db_a, _) = resolve_paths(&None, ns_a, &None)?;
    let (db_b, _) = resolve_paths(&None, ns_b, &None)?;

    // パスワード入力
    let pw_a: String = Password::new()
        .with_prompt(format!("Password for '{ns_a}'"))
        .interact()
        .map_err(io_err)?;

    let pw_b: String = Password::new()
        .with_prompt(format!("Password for '{ns_b}'"))
        .interact()
        .map_err(io_err)?;

    // 両方の環境変数を復号
    let vars_a = decrypt_all_vars(&db_a, &pw_a, log)?;
    let vars_b = decrypt_all_vars(&db_b, &pw_b, log)?;

    // マージ: BTreeMap で管理（キー順ソート）
    let map_a: BTreeMap<&str, (&str, Option<&str>)> = vars_a
        .iter()
        .map(|(k, v, e)| (k.as_str(), (v.as_str(), e.as_deref())))
        .collect();
    let map_b: BTreeMap<&str, (&str, Option<&str>)> = vars_b
        .iter()
        .map(|(k, v, e)| (k.as_str(), (v.as_str(), e.as_deref())))
        .collect();

    // 全キーを収集
    let all_keys: BTreeSet<&str> = map_a.keys().chain(map_b.keys()).copied().collect();

    let mut merged: Vec<(String, String)> = Vec::new();
    let mut conflict_count = 0;

    for key in &all_keys {
        match (map_a.get(key), map_b.get(key)) {
            (Some((val, _)), None) => {
                merged.push((key.to_string(), val.to_string()));
            }
            (None, Some((val, _))) => {
                merged.push((key.to_string(), val.to_string()));
            }
            (Some((val_a, _)), Some((val_b, _))) => {
                if val_a == val_b {
                    // 値が同じならそのまま
                    merged.push((key.to_string(), val_a.to_string()));
                } else {
                    conflict_count += 1;
                    eprintln!("\nConflict: {key}");
                    let choices = &[format!("[{ns_a}] {val_a}"), format!("[{ns_b}] {val_b}")];
                    let pick = Select::new()
                        .with_prompt(format!("Which value for '{key}'?"))
                        .items(choices)
                        .default(0)
                        .interact()
                        .map_err(io_err)?;
                    let chosen = if pick == 0 { val_a } else { val_b };
                    merged.push((key.to_string(), chosen.to_string()));
                }
            }
            (None, None) => unreachable!(),
        }
    }

    eprintln!(
        "\nMerged: {} keys ({} from '{ns_a}', {} from '{ns_b}', {} conflicts)",
        merged.len(),
        map_a.len(),
        map_b.len(),
        conflict_count,
    );

    if let Some(l) = log {
        l.log_merge(ns_a, ns_b, merged.len(), conflict_count);
    }

    // 出力方式を選択
    let output_modes = &["Print to stdout", "Serve virtual .env", "Execute command"];
    let mode = Select::new()
        .with_prompt("Output")
        .items(output_modes)
        .default(0)
        .interact()
        .map_err(io_err)?;

    match mode {
        0 => {
            // stdout
            for (k, v) in &merged {
                println!("{k}={v}");
            }
            // zeroize
            for (_, mut v) in merged {
                v.zeroize();
            }
        }
        1 => {
            // serve
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

            let mut content = String::new();
            for (k, v) in &merged {
                content.push_str(&format!("{k}={v}\n"));
            }

            for (_, mut v) in merged {
                v.zeroize();
            }

            fuse_fs::serve_content(&content, &env_path, once, None)?;
            content.zeroize();
        }
        2 => {
            // exec
            let cmd_str: String = Input::new()
                .with_prompt("Command")
                .interact_text()
                .map_err(io_err)?;

            let command: Vec<String> = shell_words::split(&cmd_str)
                .map_err(|e| EnvsGateError::InvalidInput(format!("Invalid command: {e}")))?;

            let code = exec_with_env(&command, merged, log)?;
            eprintln!("Exit code: {code}");
        }
        _ => unreachable!(),
    }

    Ok(())
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
