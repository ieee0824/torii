#![cfg(feature = "fuse")]

use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, Request,
};
use rusqlite::Connection;

use crate::crypto;
use crate::db;
use crate::error::{EnvsGateError, Result};

const TTL: Duration = Duration::from_secs(0);
const ROOT_INO: u64 = 1;
const FILE_INO: u64 = 2;

struct EnvFuseFs {
    dek: [u8; 32],
    db_path: String,
    file_name: String,
    content_cache: Arc<Mutex<Option<Vec<u8>>>>,
}

impl EnvFuseFs {
    fn generate_content(&self) -> Vec<u8> {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return b"# error: could not open database\n".to_vec(),
        };

        let vars = match db::list_env_vars(&conn) {
            Ok(v) => v,
            Err(_) => return b"# error: could not read env vars\n".to_vec(),
        };

        let now = chrono::Local::now().date_naive();
        let mut content = String::new();

        for var in &vars {
            // Skip expired vars
            if let Some(ref exp) = var.expires_at {
                if let Ok(exp_date) = chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
                    if now > exp_date {
                        continue;
                    }
                }
            }

            match crypto::decrypt_value(&self.dek, &var.nonce, &var.ciphertext) {
                Ok(plaintext) => {
                    let value = String::from_utf8_lossy(&plaintext);
                    content.push_str(&format!("{}={}\n", var.key_name, value));
                }
                Err(_) => {
                    content.push_str(&format!("# error decrypting: {}\n", var.key_name));
                }
            }
        }

        content.into_bytes()
    }

    fn file_attr(&self, size: u64) -> FileAttr {
        FileAttr {
            ino: FILE_INO,
            size,
            blocks: 1,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn dir_attr() -> FileAttr {
        FileAttr {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

impl Filesystem for EnvFuseFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INO && name.to_str() == Some(&self.file_name) {
            let content = self.generate_content();
            let attr = self.file_attr(content.len() as u64);
            *self.content_cache.lock().unwrap() = Some(content);
            reply.entry(&TTL, &attr, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match ino {
            ROOT_INO => reply.attr(&TTL, &Self::dir_attr()),
            FILE_INO => {
                let content = self.generate_content();
                let attr = self.file_attr(content.len() as u64);
                *self.content_cache.lock().unwrap() = Some(content);
                reply.attr(&TTL, &attr);
            }
            _ => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(libc::ENOENT);
            return;
        }

        let entries = vec![
            (ROOT_INO, FileType::Directory, "."),
            (ROOT_INO, FileType::Directory, ".."),
            (FILE_INO, FileType::RegularFile, &self.file_name),
        ];

        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as i64, kind, name) {
                break;
            }
        }

        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        if ino == FILE_INO {
            reply.opened(0, fuser::consts::FOPEN_DIRECT_IO);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if ino != FILE_INO {
            reply.error(libc::ENOENT);
            return;
        }

        let content = self.generate_content();
        let offset = offset as usize;

        if offset >= content.len() {
            reply.data(&[]);
        } else {
            let end = (offset + size as usize).min(content.len());
            reply.data(&content[offset..end]);
        }
    }
}

pub fn serve(db_path: &str, dek: &[u8; 32], env_path: &str) -> Result<()> {
    let path = Path::new(env_path);
    let file_name = path
        .file_name()
        .unwrap_or(OsStr::new(".env"))
        .to_string_lossy()
        .to_string();

    let mount_dir = path.parent().unwrap_or(Path::new("."));

    let mount_dir = if mount_dir.is_relative() {
        std::env::current_dir()
            .map_err(|e| EnvsGateError::Fuse(format!("Cannot get cwd: {e}")))?
            .join(mount_dir)
    } else {
        mount_dir.to_path_buf()
    };

    let mount_point = mount_dir.join(format!(".envs-gate-mount-{}", std::process::id()));
    std::fs::create_dir_all(&mount_point)
        .map_err(|e| EnvsGateError::Fuse(format!("Cannot create mount point: {e}")))?;

    let fs = EnvFuseFs {
        dek: *dek,
        db_path: db_path.to_string(),
        file_name,
        content_cache: Arc::new(Mutex::new(None)),
    };

    eprintln!("Mounting virtual .env at: {}", mount_point.display());
    eprintln!(
        "Access your env file at: {}",
        mount_point.join(&fs.file_name).display()
    );
    eprintln!("Press Ctrl+C to unmount and exit");

    let mount_point_clone = mount_point.clone();
    ctrlc::set_handler(move || {
        eprintln!("\nUnmounting...");
        let _ = std::process::Command::new("umount")
            .arg(&mount_point_clone)
            .status();
        std::process::exit(0);
    })
    .map_err(|e| EnvsGateError::Fuse(format!("Cannot set Ctrl+C handler: {e}")))?;

    let options = vec![
        MountOption::RO,
        MountOption::FSName("envs-gate".to_string()),
        MountOption::AutoUnmount,
        MountOption::AllowOther,
    ];

    fuser::mount2(fs, &mount_point, &options)
        .map_err(|e| EnvsGateError::Fuse(format!("FUSE mount failed: {e}")))?;

    let _ = std::fs::remove_dir(&mount_point);

    Ok(())
}
