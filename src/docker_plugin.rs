use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use torii::commands::{is_expired, resolve_paths, unwrap_dek_logged};
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

fn validate_env_path(env_path: &str) -> error::Result<()> {
    if env_path.contains(',') {
        return Err(error::EnvsGateError::InvalidInput(
            "Container env-path must not contain commas (mount option injection risk)".into(),
        ));
    }
    if !env_path.starts_with('/') {
        return Err(error::EnvsGateError::InvalidInput(
            "Container env-path must be an absolute path".into(),
        ));
    }
    Ok(())
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
        if let Some(ref exp) = var.expires_at
            && is_expired(exp)
        {
            return Err(error::EnvsGateError::KeyExpired {
                key: var.key_name.clone(),
                expired_at: exp.clone(),
            });
        }

        let mut plaintext = crypto::decrypt_value(&dek, &var.nonce, &var.ciphertext)?;
        let value = std::str::from_utf8(&plaintext).map_err(|_| {
            error::EnvsGateError::InvalidInput(format!(
                "Value for '{}' contains invalid UTF-8",
                var.key_name
            ))
        })?;
        content.push_str(&var.key_name);
        content.push('=');
        content.push_str(value);
        content.push('\n');
        plaintext.zeroize();
    }

    Ok(content)
}

/// Create a secure temporary directory.
/// On Linux, tries /dev/shm (memory-backed) first, then $XDG_RUNTIME_DIR.
/// Falls back to the system temp directory.
fn create_secure_tmpdir() -> error::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        // /dev/shm is a user-accessible tmpfs on most Linux distributions
        let shm = Path::new("/dev/shm");
        if shm.is_dir()
            && let Ok(dir) = tempfile::Builder::new().prefix("torii-").tempdir_in(shm)
        {
            let path = dir.keep();
            set_dir_permissions(&path)?;
            return Ok(path);
        }
        // $XDG_RUNTIME_DIR is typically a per-user tmpfs
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            let rt = Path::new(&runtime_dir);
            if rt.is_dir()
                && let Ok(dir) = tempfile::Builder::new().prefix("torii-").tempdir_in(rt)
            {
                let path = dir.keep();
                set_dir_permissions(&path)?;
                return Ok(path);
            }
        }
    }

    // Fallback: system temp directory with secure random name
    let dir = tempfile::Builder::new()
        .prefix("torii-")
        .tempdir()
        .map_err(|e| error::EnvsGateError::InvalidInput(format!("Cannot create temp dir: {e}")))?;
    let path = dir.keep();
    set_dir_permissions(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> error::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        error::EnvsGateError::InvalidInput(format!(
            "Cannot set permissions on '{}': {e}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> error::Result<()> {
    Ok(())
}

fn cleanup_tmpdir(dir: &Path) {
    // Zeroize files in fixed-size chunks before deleting
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(len) = std::fs::metadata(&path).map(|m| m.len())
                    && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path)
                {
                    const CHUNK: usize = 8192;
                    let zeros = [0u8; CHUNK];
                    let mut remaining = len;
                    while remaining > 0 {
                        let n = std::cmp::min(remaining, CHUNK as u64) as usize;
                        let _ = f.write_all(&zeros[..n]);
                        remaining -= n as u64;
                    }
                    let _ = f.sync_all();
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    let _ = std::fs::remove_dir(dir);
}

fn run(
    namespace: &str,
    db_path_opt: &Option<String>,
    env_path: &str,
    docker_args: &[String],
) -> error::Result<i32> {
    validate_env_path(env_path)?;

    let (db_path, log_path) = resolve_paths(db_path_opt, namespace, &None)?;
    let mut log = match logger::Logger::open(&log_path) {
        Ok(l) => Some(l),
        Err(e) => {
            eprintln!("Warning: Could not open audit log: {e}");
            None
        }
    };

    let mut password = prompt_password()?;
    let mut content = decrypt_env_content(&db_path, &password, &mut log)?;
    password.zeroize();

    // Create secure temp dir and write .env
    let tmp_dir = create_secure_tmpdir()?;
    let env_file = tmp_dir.join(".env");

    std::fs::write(&env_file, content.as_bytes()).map_err(|e| {
        cleanup_tmpdir(&tmp_dir);
        error::EnvsGateError::InvalidInput(format!("Cannot write .env: {e}"))
    })?;
    content.zeroize();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o400));
    }

    // Register signal handler to clean up on Ctrl+C / SIGTERM
    let tmp_dir_for_signal = tmp_dir.clone();
    ctrlc::set_handler(move || {
        cleanup_tmpdir(&tmp_dir_for_signal);
        std::process::exit(130);
    })
    .map_err(|e| {
        cleanup_tmpdir(&tmp_dir);
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
            cleanup_tmpdir(&tmp_dir);
            return Err(error::EnvsGateError::InvalidInput(format!(
                "Failed to run docker: {e}"
            )));
        }
    };

    cleanup_tmpdir(&tmp_dir);

    Ok(status.code().unwrap_or(1))
}

fn metadata_json() -> String {
    format!(
        r#"{{"SchemaVersion":"0.1.0","Vendor":"torii","Version":"{}","ShortDescription":"Run containers with torii-encrypted env vars"}}"#,
        PLUGIN_VERSION
    )
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        PluginCommand::Metadata => {
            println!("{}", metadata_json());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_json_is_valid() {
        let json = metadata_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["SchemaVersion"], "0.1.0");
        assert_eq!(parsed["Vendor"], "torii");
        assert!(!parsed["ShortDescription"].as_str().unwrap().is_empty());
    }

    #[test]
    fn validate_env_path_valid() {
        assert!(validate_env_path("/secrets/.env").is_ok());
        assert!(validate_env_path("/app/config/.env").is_ok());
    }

    #[test]
    fn validate_env_path_rejects_comma() {
        assert!(validate_env_path("/secrets/.env,rw").is_err());
    }

    #[test]
    fn validate_env_path_rejects_relative() {
        assert!(validate_env_path("secrets/.env").is_err());
        assert!(validate_env_path(".env").is_err());
    }

    #[test]
    fn create_and_cleanup_tmpdir() {
        let dir = create_secure_tmpdir().unwrap();
        assert!(dir.exists());

        let file = dir.join("test.txt");
        std::fs::write(&file, b"secret data").unwrap();
        assert!(file.exists());

        cleanup_tmpdir(&dir);
        assert!(!dir.exists());
        assert!(!file.exists());
    }

    #[test]
    fn cleanup_zeroizes_file_content() {
        let dir = create_secure_tmpdir().unwrap();
        let file = dir.join("secret.env");
        std::fs::write(&file, b"API_KEY=supersecret\n").unwrap();

        // Read back to verify it was written
        let content = std::fs::read(&file).unwrap();
        assert!(content.starts_with(b"API_KEY"));

        cleanup_tmpdir(&dir);
        assert!(!file.exists());
    }
}
