use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use chrono::Local;
use serde::{Deserialize, Serialize};

use crate::error::{EnvsGateError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub action: String,
    pub key: Option<String>,
    pub detail: Option<String>,
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
            self.timestamp,
            self.action,
            self.key.as_deref().unwrap_or("-"),
            self.detail.as_deref().unwrap_or("-"),
        )
    }
}

pub struct Logger {
    file: File,
}

impl Logger {
    pub fn open(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| EnvsGateError::InvalidInput(format!("Cannot open log file: {e}")))?;

        // Restrict log file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }

        Ok(Self { file })
    }

    fn write_entry(&mut self, entry: &LogEntry) -> Result<()> {
        let json = serde_json::to_string(entry)
            .map_err(|e| EnvsGateError::InvalidInput(format!("JSON serialize: {e}")))?;
        writeln!(self.file, "{json}")
            .map_err(|e| EnvsGateError::InvalidInput(format!("Log write: {e}")))?;
        Ok(())
    }

    pub fn log_set(&mut self, key: &str, expires: Option<&str>) {
        let detail = expires.map(|e| format!("expires={e}"));
        let entry = LogEntry::new("set", Some(key), detail.as_deref());
        let _ = self.write_entry(&entry);
    }

    pub fn log_get(&mut self, key: &str) {
        let entry = LogEntry::new("get", Some(key), None);
        let _ = self.write_entry(&entry);
    }

    pub fn log_list(&mut self) {
        let entry = LogEntry::new("list", None, None);
        let _ = self.write_entry(&entry);
    }

    pub fn log_delete(&mut self, key: &str) {
        let entry = LogEntry::new("delete", Some(key), None);
        let _ = self.write_entry(&entry);
    }

    pub fn log_serve(&mut self, env_path: &str, once: bool) {
        let detail = format!("path={env_path}, once={once}");
        let entry = LogEntry::new("serve", None, Some(&detail));
        let _ = self.write_entry(&entry);
    }

    pub fn log_serve_read(&mut self, keys_count: usize) {
        let detail = format!("keys_served={keys_count}");
        let entry = LogEntry::new("serve_read", None, Some(&detail));
        let _ = self.write_entry(&entry);
    }

    pub fn log_auth_failed(&mut self) {
        let entry = LogEntry::new("auth_failed", None, None);
        let _ = self.write_entry(&entry);
    }

    pub fn log_expired(&mut self, key: &str) {
        let entry = LogEntry::new("expired", Some(key), None);
        let _ = self.write_entry(&entry);
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
            LogFormat::Tsv => {
                if let Ok(entry) = serde_json::from_str::<LogEntry>(&line) {
                    println!("{}", entry.to_tsv());
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn log_entry_json_roundtrip() {
        let entry = LogEntry::new("get", Some("DB_URL"), None);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, "get");
        assert_eq!(parsed.key.as_deref(), Some("DB_URL"));
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
    fn read_logs_tsv_format() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let log_path_str = log_path.to_str().unwrap();

        let mut logger = Logger::open(log_path_str).unwrap();
        logger.log_set("K", None);
        drop(logger);

        // Should not error
        read_logs(log_path_str, LogFormat::Tsv).unwrap();
        read_logs(log_path_str, LogFormat::Json).unwrap();
    }

    #[test]
    fn read_logs_nonexistent_file() {
        assert!(read_logs("/tmp/nonexistent-torii-log-12345", LogFormat::Json).is_err());
    }
}
