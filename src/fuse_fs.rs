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
    let mut has_been_read = false;

    // Loop: each iteration serves one reader
    loop {
        // Wait for a reader to connect.
        // When timeout is active (after first read), use O_NONBLOCK + poll
        // to avoid spawning threads and to make timeout reliably enforceable.
        let file = if let Some(secs) = timeout.filter(|_| has_been_read) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            loop {
                match open_fifo_nonblock(&path) {
                    Ok(Some(f)) => break Ok(f),
                    Ok(None) => {
                        // No reader yet — check deadline
                        if std::time::Instant::now() >= deadline {
                            eprintln!("Timeout: no reader for {secs}s, stopping.");
                            let _ = std::fs::remove_file(&path);
                            return Ok(());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(e) => break Err(e),
                }
            }
        } else {
            // Blocking open — waits indefinitely for a reader
            std::fs::OpenOptions::new().write(true).open(&path)
        };

        match file {
            Ok(mut f) => {
                has_been_read = true;
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

/// Serve pre-built .env content via named pipe.
pub fn serve_content(
    content: &str,
    env_path: &str,
    once: bool,
    timeout: Option<u64>,
) -> Result<()> {
    let path = Path::new(env_path);

    let path = if path.is_relative() {
        std::env::current_dir()
            .map_err(|e| EnvsGateError::Fuse(format!("Cannot get cwd: {e}")))?
            .join(path)
    } else {
        path.to_path_buf()
    };

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

    let path_clone = path.clone();
    ctrlc::set_handler(move || {
        let _ = std::fs::remove_file(&path_clone);
        eprintln!("\nStopped.");
        std::process::exit(0);
    })
    .map_err(|e| EnvsGateError::Fuse(format!("Cannot set Ctrl+C handler: {e}")))?;

    let content_bytes = content.as_bytes();
    let mut has_been_read = false;

    loop {
        let file = if let Some(secs) = timeout.filter(|_| has_been_read) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            loop {
                match open_fifo_nonblock(&path) {
                    Ok(Some(f)) => break Ok(f),
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            eprintln!("Timeout: no reader for {secs}s, stopping.");
                            let _ = std::fs::remove_file(&path);
                            return Ok(());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(e) => break Err(e),
                }
            }
        } else {
            std::fs::OpenOptions::new().write(true).open(&path)
        };

        match file {
            Ok(mut f) => {
                has_been_read = true;
                let _ = f.write_all(content_bytes);
                if once {
                    break;
                }
            }
            Err(e) => {
                if !path.exists() {
                    break;
                }
                eprintln!("Warning: pipe open failed: {e}");
            }
        }
    }

    Ok(())
}

/// Try to open a FIFO for writing with O_NONBLOCK.
/// Returns Ok(Some(file)) if a reader is connected, Ok(None) if ENXIO (no reader yet),
/// or Err for other failures.
fn open_fifo_nonblock(path: &Path) -> std::result::Result<Option<std::fs::File>, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.raw_os_error() == Some(libc::ENXIO) => Ok(None),
        Err(e) => Err(e),
    }
}
