use std::io::Write;
use std::path::Path;

use crate::crypto;
use crate::db;
use crate::error::{EnvsGateError, Result};

fn generate_env_content(db_path: &str, dek: &[u8; 32]) -> Result<Vec<u8>> {
    let conn = rusqlite::Connection::open(db_path)?;
    let vars = db::list_env_vars(&conn)?;
    let now = chrono::Local::now().naive_local();
    let mut content = String::new();

    for var in &vars {
        if let Some(ref exp) = var.expires_at {
            let expired = chrono::NaiveDateTime::parse_from_str(exp, "%Y-%m-%dT%H:%M:%S")
                .map(|dt| now > dt)
                .or_else(|_| {
                    chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d").map(|d| now.date() > d)
                })
                .unwrap_or(false);
            if expired {
                eprintln!("Warning: {} expired at {}", var.key_name, exp);
                continue;
            }
        }

        let plaintext = crypto::decrypt_value(dek, &var.nonce, &var.ciphertext)?;
        let value = String::from_utf8_lossy(&plaintext);
        content.push_str(&format!("{}={}\n", var.key_name, value));
    }

    Ok(content.into_bytes())
}

pub fn serve(
    db_path: &str,
    dek: &[u8; 32],
    env_path: &str,
    once: bool,
    timeout: Option<u64>,
) -> Result<()> {
    let path = Path::new(env_path);

    // Resolve to absolute path
    let path = if path.is_relative() {
        std::env::current_dir()
            .map_err(|e| EnvsGateError::Fuse(format!("Cannot get cwd: {e}")))?
            .join(path)
    } else {
        path.to_path_buf()
    };

    // Create named pipe (FIFO) - remove existing first, then create atomically
    let path_cstr = std::ffi::CString::new(path.to_str().unwrap())
        .map_err(|e| EnvsGateError::Fuse(format!("Invalid path: {e}")))?;

    let _ = std::fs::remove_file(&path);
    let ret = unsafe { libc::mkfifo(path_cstr.as_ptr(), 0o600) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Err(EnvsGateError::Fuse(format!(
                "File already exists at {}",
                path.display()
            )));
        }
        return Err(EnvsGateError::Fuse(format!(
            "mkfifo failed at {}: {}",
            path.display(),
            err
        )));
    }

    eprintln!("Serving virtual .env at: {}", path.display());
    eprintln!("Press Ctrl+C to stop");

    // Cleanup FIFO on Ctrl+C
    let path_clone = path.clone();
    ctrlc::set_handler(move || {
        let _ = std::fs::remove_file(&path_clone);
        eprintln!("\nStopped.");
        std::process::exit(0);
    })
    .map_err(|e| EnvsGateError::Fuse(format!("Cannot set Ctrl+C handler: {e}")))?;

    let db_path = db_path.to_string();
    let dek = *dek;

    // Loop: each iteration serves one reader
    loop {
        // FIFO open for writing blocks until a reader connects.
        // When timeout is set, use a background thread so we can time out.
        let file = if let Some(secs) = timeout {
            let path_clone = path.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = std::fs::OpenOptions::new().write(true).open(&path_clone);
                let _ = tx.send(result);
            });
            match rx.recv_timeout(std::time::Duration::from_secs(secs)) {
                Ok(result) => result,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    eprintln!("Timeout: no reader for {secs}s, stopping.");
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        } else {
            std::fs::OpenOptions::new().write(true).open(&path)
        };

        match file {
            Ok(mut f) => {
                match generate_env_content(&db_path, &dek) {
                    Ok(content) => {
                        let _ = f.write_all(&content);
                    }
                    Err(e) => {
                        let msg = format!("# error: {e}\n");
                        let _ = f.write_all(msg.as_bytes());
                    }
                }
                // f is dropped here, closing the write end → reader gets EOF
                if once {
                    break;
                }
            }
            Err(e) => {
                // FIFO was removed or other error
                if !path.exists() {
                    break;
                }
                eprintln!("Warning: pipe open failed: {e}");
            }
        }
    }

    Ok(())
}
