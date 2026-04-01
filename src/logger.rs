use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::Path;

use chrono::Local;
use serde::{Deserialize, Serialize};

use crate::error::{EnvsGateError, Result};

const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024; // 10MB

/// Default log path
pub fn default_log_path() -> String {
    if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{home}/.torii/audit.log")
    } else {
        "torii-audit.log".into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub action: String,
    pub key: Option<String>,
    pub detail: Option<String>,
}

/// Sanitize a string for TSV output: replace tabs and newlines with spaces
fn sanitize_tsv(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

impl LogEntry {
    fn new(action: &str, key: Option<&str>, detail: Option<&str>) -> Self {
        Self {
            timestamp: Local::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
            action: action.to_string(),
            key: key.map(String::from),
            detail: detail.map(String::from),
        }
    }

    pub fn to_tsv(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            sanitize_tsv(&self.timestamp),
            sanitize_tsv(&self.action),
            sanitize_tsv(self.key.as_deref().unwrap_or("-")),
            sanitize_tsv(self.detail.as_deref().unwrap_or("-")),
        )
    }
}

pub struct Logger {
    file: File,
    path: String,
}

use std::os::unix::fs::OpenOptionsExt;

impl Logger {
    pub fn open(path: &str) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = Path::new(path).parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                EnvsGateError::InvalidInput(format!("Cannot create log directory: {e}"))
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| EnvsGateError::InvalidInput(format!("Cannot open log file: {e}")))?;

        // Enforce permissions on pre-existing files
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }

        Ok(Self {
            file,
            path: path.to_string(),
        })
    }

    fn check_rotate(&mut self) -> Result<()> {
        let metadata = self
            .file
            .metadata()
            .map_err(|e| EnvsGateError::InvalidInput(format!("Log metadata: {e}")))?;

        if metadata.len() >= MAX_LOG_SIZE {
            let rotated = format!("{}.old", self.path);
            std::fs::rename(&self.path, &rotated).map_err(|e| {
                EnvsGateError::InvalidInput(format!("Log rotate rename failed: {e}"))
            })?;

            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&self.path)
                .map_err(|e| EnvsGateError::InvalidInput(format!("Log rotate open: {e}")))?;
        }

        Ok(())
    }

    fn write_entry(&mut self, entry: &LogEntry) -> Result<()> {
        if let Err(e) = self.check_rotate() {
            eprintln!("Warning: log rotation failed: {e}");
        }

        let mut json = serde_json::to_string(entry)
            .map_err(|e| EnvsGateError::InvalidInput(format!("JSON serialize: {e}")))?;
        json.push('\n');

        // Single write call for atomicity on append-mode files
        use std::io::Write;
        self.file
            .write_all(json.as_bytes())
            .map_err(|e| EnvsGateError::InvalidInput(format!("Log write: {e}")))?;

        Ok(())
    }

    fn log(&mut self, entry: &LogEntry) {
        if let Err(e) = self.write_entry(entry) {
            eprintln!("Warning: audit log write failed: {e}");
        }
    }

    pub fn log_set(&mut self, key: &str, expires: Option<&str>) {
        let detail = expires.map(|e| format!("expires={e}"));
        self.log(&LogEntry::new("set", Some(key), detail.as_deref()));
    }

    pub fn log_get(&mut self, key: &str) {
        self.log(&LogEntry::new("get", Some(key), None));
    }

    pub fn log_list(&mut self) {
        self.log(&LogEntry::new("list", None, None));
    }

    pub fn log_delete(&mut self, key: &str) {
        self.log(&LogEntry::new("delete", Some(key), None));
    }

    pub fn log_serve(&mut self, env_path: &str, once: bool) {
        let detail = format!("path={env_path}, once={once}");
        self.log(&LogEntry::new("serve", None, Some(&detail)));
    }

    pub fn log_serve_read(&mut self, keys_count: usize) {
        let detail = format!("keys_served={keys_count}");
        self.log(&LogEntry::new("serve_read", None, Some(&detail)));
    }

    pub fn log_exec(&mut self, command: &str, keys_count: usize) {
        let detail = format!("cmd={command}, keys_injected={keys_count}");
        self.log(&LogEntry::new("exec", None, Some(&detail)));
    }

    pub fn log_auth_failed(&mut self) {
        self.log(&LogEntry::new("auth_failed", None, None));
    }

    pub fn log_expired(&mut self, key: &str) {
        self.log(&LogEntry::new("expired", Some(key), None));
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    Json,
    Tsv,
}

pub fn read_logs(path: &str, format: LogFormat) -> Result<()> {
    if !Path::new(path).exists() {
        return Err(EnvsGateError::InvalidInput("Log file not found".into()));
    }

    let file = File::open(path)
        .map_err(|e| EnvsGateError::InvalidInput(format!("Cannot open log file: {e}")))?;
    let reader = BufReader::new(file);

    if matches!(format, LogFormat::Tsv) {
        println!("TIMESTAMP\tACTION\tKEY\tDETAIL");
    }

    for line in reader.lines() {
        let line = line.map_err(|e| EnvsGateError::InvalidInput(format!("Read error: {e}")))?;
        match format {
            LogFormat::Json => println!("{line}"),
            LogFormat::Tsv => match serde_json::from_str::<LogEntry>(&line) {
                Ok(entry) => println!("{}", entry.to_tsv()),
                Err(e) => {
                    eprintln!("Warning: failed to parse log line: {e}");
                    println!("N/A\tparse_error\t-\t{}", sanitize_tsv(&line));
                }
            },
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_log_path_is_set() {
        let path = default_log_path();
        assert!(path.contains("torii"));
    }

    #[test]
    fn log_entry_to_tsv() {
        let entry = LogEntry::new("set", Some("API_KEY"), Some("expires=1h"));
        let tsv = entry.to_tsv();
        assert!(tsv.contains("set"));
        assert!(tsv.contains("API_KEY"));
        assert!(tsv.contains("expires=1h"));
    }

    #[test]
    fn log_entry_to_tsv_no_key() {
        let entry = LogEntry::new("list", None, None);
        let tsv = entry.to_tsv();
        assert!(tsv.contains("list"));
        assert!(tsv.contains("-\t-"));
    }

    #[test]
    fn log_entry_to_tsv_sanitizes_special_chars() {
        let entry = LogEntry::new(
            "set",
            Some("KEY\twith\ttabs"),
            Some("detail\nwith\nnewlines"),
        );
        let tsv = entry.to_tsv();
        assert!(!tsv.contains('\n'));
        assert_eq!(tsv.matches('\t').count(), 3);
    }

    #[test]
    fn log_entry_json_roundtrip() {
        let entry = LogEntry::new("get", Some("DB_URL"), None);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, "get");
        assert_eq!(parsed.key.as_deref(), Some("DB_URL"));
    }

    #[test]
    fn log_entry_json_with_special_chars() {
        let entry = LogEntry::new("set", Some("KEY\t\n\"evil\""), None);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.key.as_deref(), Some("KEY\t\n\"evil\""));
    }

    #[test]
    fn logger_writes_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let log_path_str = log_path.to_str().unwrap();

        let mut logger = Logger::open(log_path_str).unwrap();
        logger.log_set("KEY1", Some("1h"));
        logger.log_get("KEY1");
        logger.log_list();
        logger.log_delete("KEY1");
        logger.log_auth_failed();
        logger.log_expired("OLD_KEY");
        drop(logger);

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 6);

        let first: LogEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.action, "set");
        assert_eq!(first.key.as_deref(), Some("KEY1"));

        let last: LogEntry = serde_json::from_str(lines[5]).unwrap();
        assert_eq!(last.action, "expired");
    }

    #[test]
    fn logger_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let log_path_str = log_path.to_str().unwrap();

        let _logger = Logger::open(log_path_str).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&log_path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn logger_creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("subdir/nested/test.log");
        let log_path_str = log_path.to_str().unwrap();

        let mut logger = Logger::open(log_path_str).unwrap();
        logger.log_list();
        drop(logger);

        assert!(log_path.exists());
    }

    #[test]
    fn read_logs_tsv_format() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let log_path_str = log_path.to_str().unwrap();

        let mut logger = Logger::open(log_path_str).unwrap();
        logger.log_set("K", None);
        drop(logger);

        read_logs(log_path_str, LogFormat::Tsv).unwrap();
        read_logs(log_path_str, LogFormat::Json).unwrap();
    }

    #[test]
    fn read_logs_nonexistent_file() {
        assert!(read_logs("/tmp/nonexistent-torii-log-12345", LogFormat::Json).is_err());
    }

    #[test]
    fn open_logger_fails_on_invalid_path() {
        let result = Logger::open("/nonexistent/dir/that/shouldnt/exist/log.txt");
        assert!(result.is_err());
    }
}
