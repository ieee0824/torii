use std::io::Write;
use std::process::Command;

use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use torii::commands::{resolve_paths, unwrap_dek_logged};
use torii::{crypto, db, error, logger};

const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "docker-torii")]
struct Cli {
    #[command(subcommand)]
    command: PluginCommand,
}

#[derive(Subcommand)]
enum PluginCommand {
    /// Return Docker CLI plugin metadata (called by Docker)
    #[command(name = "docker-cli-plugin-metadata")]
    Metadata,

    /// Run a Docker container with torii-encrypted env vars
    Run {
        /// Namespace for isolating databases
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,

        /// Path to the SQLite database file (overrides --namespace)
        #[arg(long)]
        db_path: Option<String>,

        /// Mount path inside the container for the .env file
        #[arg(long, default_value = "/secrets/.env")]
        env_path: String,

        /// Docker run arguments (after --)
        #[arg(trailing_var_arg = true, required = true)]
        docker_args: Vec<String>,
    },
}

fn prompt_password() -> error::Result<String> {
    dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
        .map_err(|e| error::EnvsGateError::InvalidInput(format!("Password prompt failed: {e}")))
}

fn decrypt_env_content(
    db_path: &str,
    password: &str,
    log: &mut Option<logger::Logger>,
) -> error::Result<String> {
    let conn = db::open_or_create_db(db_path)?;
    let meta = db::load_metadata(&conn)?
        .ok_or_else(|| error::EnvsGateError::InvalidInput("Database not initialized".into()))?;
    let dek = unwrap_dek_logged(password, &meta, log)?;

    let vars = db::list_env_vars(&conn)?;
    let mut content = String::new();

    for var in &vars {
        if let Some(ref exp) = var.expires_at {
            let now = chrono::Local::now().naive_local();
            let expired = chrono::NaiveDateTime::parse_from_str(exp, "%Y-%m-%dT%H:%M:%S")
                .map(|dt| now > dt)
                .or_else(|_| {
                    chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d").map(|d| now.date() > d)
                })
                .unwrap_or(false);
            if expired {
                return Err(error::EnvsGateError::KeyExpired {
                    key: var.key_name.clone(),
                    expired_at: exp.clone(),
                });
            }
        }

        let mut plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
        let value = String::from_utf8_lossy(&plaintext);
        content.push_str(&format!("{}={}\n", var.key_name, value));
        plaintext.zeroize();
    }

    Ok(content)
}

/// Create a temporary directory backed by tmpfs (macOS: ramfs via diskutil,
/// Linux: mount -t tmpfs). Falls back to a regular tempdir if tmpfs is unavailable.
fn create_tmpfs_dir() -> error::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("torii-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| error::EnvsGateError::InvalidInput(format!("Cannot create temp dir: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(&dir, perms);
    }

    // Try to mount tmpfs (Linux only; macOS doesn't support mount -t tmpfs easily)
    #[cfg(target_os = "linux")]
    {
        let status = Command::new("mount")
            .args(["-t", "tmpfs", "-o", "size=1m,mode=0700", "tmpfs"])
            .arg(&dir)
            .status();
        if let Ok(s) = status {
            if s.success() {
                return Ok(dir);
            }
        }
        eprintln!("Warning: Could not mount tmpfs, using regular temp directory");
    }

    Ok(dir)
}

fn cleanup_tmpfs_dir(dir: &std::path::Path) {
    // Zeroize any files in the directory
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                // Overwrite with zeros before deleting
                if let Ok(len) = std::fs::metadata(&path).map(|m| m.len())
                    && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path)
                {
                    let zeros = vec![0u8; len as usize];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_all();
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    // Try to unmount (Linux tmpfs)
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("umount").arg(dir).status();
    }

    let _ = std::fs::remove_dir(dir);
}

fn run(
    namespace: &str,
    db_path_opt: &Option<String>,
    env_path: &str,
    docker_args: &[String],
) -> error::Result<i32> {
    let (db_path, log_path) = resolve_paths(db_path_opt, namespace, &None)?;
    let mut log = logger::Logger::open(&log_path).ok();

    let mut password = prompt_password()?;
    let mut content = decrypt_env_content(&db_path, &password, &mut log)?;
    password.zeroize();

    // Create tmpfs-backed temp dir and write .env
    let tmp_dir = create_tmpfs_dir()?;
    let env_file = tmp_dir.join(".env");

    std::fs::write(&env_file, content.as_bytes()).map_err(|e| {
        error::EnvsGateError::InvalidInput(format!("Cannot write .env to tmpfs: {e}"))
    })?;
    content.zeroize();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o400));
    }

    // Register signal handler to clean up tmpfs on Ctrl+C / SIGTERM
    let tmp_dir_for_signal = tmp_dir.clone();
    ctrlc::set_handler(move || {
        cleanup_tmpfs_dir(&tmp_dir_for_signal);
        std::process::exit(130);
    })
    .map_err(|e| {
        cleanup_tmpfs_dir(&tmp_dir);
        error::EnvsGateError::InvalidInput(format!("Cannot set signal handler: {e}"))
    })?;

    let mount_arg = format!(
        "type=bind,src={},dst={},readonly",
        env_file.display(),
        env_path
    );

    let status = match Command::new("docker")
        .arg("run")
        .args(["--mount", &mount_arg])
        .args(docker_args)
        .status()
    {
        Ok(s) => s,
        Err(e) => {
            cleanup_tmpfs_dir(&tmp_dir);
            return Err(error::EnvsGateError::InvalidInput(format!(
                "Failed to run docker: {e}"
            )));
        }
    };

    cleanup_tmpfs_dir(&tmp_dir);

    Ok(status.code().unwrap_or(1))
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        PluginCommand::Metadata => {
            println!(
                r#"{{"SchemaVersion":"0.1.0","Vendor":"torii","Version":"{}","ShortDescription":"Run containers with torii-encrypted env vars"}}"#,
                PLUGIN_VERSION
            );
        }
        PluginCommand::Run {
            namespace,
            db_path,
            env_path,
            docker_args,
        } => match run(&namespace, &db_path, &env_path, &docker_args) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
    }
}
