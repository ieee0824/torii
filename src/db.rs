use rusqlite::{Connection, params};

use crate::error::{EnvsGateError, Result};

pub struct VaultMetadata {
    pub salt: Vec<u8>,
    pub ek_kem: Vec<u8>,
    pub x25519_pub: Vec<u8>,
    pub ct_kem: Vec<u8>,
    pub x25519_eph: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

pub struct EncryptedEnvVar {
    pub key_name: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub expires_at: Option<String>,
}

pub fn open_or_create_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;

    // Restrict DB file to owner-only access
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS metadata (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            salt        BLOB NOT NULL,
            ek_kem      BLOB NOT NULL,
            x25519_pub  BLOB NOT NULL,
            ct_kem      BLOB NOT NULL,
            x25519_eph  BLOB NOT NULL,
            wrap_nonce  BLOB NOT NULL,
            wrapped_dek BLOB NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS env_vars (
            key_name    TEXT PRIMARY KEY,
            nonce       BLOB NOT NULL,
            ciphertext  BLOB NOT NULL,
            expires_at  TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;
    Ok(conn)
}

pub fn is_initialized(conn: &Connection) -> Result<bool> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM metadata", [], |row| row.get(0))?;
    Ok(count > 0)
}

pub fn store_metadata(conn: &Connection, meta: &VaultMetadata) -> Result<()> {
    conn.execute(
        "INSERT INTO metadata (id, salt, ek_kem, x25519_pub, ct_kem, x25519_eph, wrap_nonce, wrapped_dek)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            meta.salt,
            meta.ek_kem,
            meta.x25519_pub,
            meta.ct_kem,
            meta.x25519_eph,
            meta.wrap_nonce,
            meta.wrapped_dek,
        ],
    )?;
    Ok(())
}

pub fn load_metadata(conn: &Connection) -> Result<Option<VaultMetadata>> {
    let mut stmt = conn.prepare(
        "SELECT salt, ek_kem, x25519_pub, ct_kem, x25519_eph, wrap_nonce, wrapped_dek FROM metadata WHERE id = 1",
    )?;

    let mut rows = stmt.query([])?;
    match rows.next()? {
        Some(row) => Ok(Some(VaultMetadata {
            salt: row.get(0)?,
            ek_kem: row.get(1)?,
            x25519_pub: row.get(2)?,
            ct_kem: row.get(3)?,
            x25519_eph: row.get(4)?,
            wrap_nonce: row.get(5)?,
            wrapped_dek: row.get(6)?,
        })),
        None => Ok(None),
    }
}

pub fn upsert_env_var(
    conn: &Connection,
    key: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    expires_at: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO env_vars (key_name, nonce, ciphertext, expires_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key_name) DO UPDATE SET
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            expires_at = excluded.expires_at,
            updated_at = datetime('now')",
        params![key, nonce, ciphertext, expires_at],
    )?;
    Ok(())
}

pub fn get_env_var(conn: &Connection, key: &str) -> Result<Option<EncryptedEnvVar>> {
    let mut stmt = conn.prepare(
        "SELECT key_name, nonce, ciphertext, expires_at FROM env_vars WHERE key_name = ?1",
    )?;

    let mut rows = stmt.query(params![key])?;
    match rows.next()? {
        Some(row) => Ok(Some(EncryptedEnvVar {
            key_name: row.get(0)?,
            nonce: row.get(1)?,
            ciphertext: row.get(2)?,
            expires_at: row.get(3)?,
        })),
        None => Ok(None),
    }
}

pub fn list_env_vars(conn: &Connection) -> Result<Vec<EncryptedEnvVar>> {
    let mut stmt = conn.prepare(
        "SELECT key_name, nonce, ciphertext, expires_at FROM env_vars ORDER BY key_name",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(EncryptedEnvVar {
            key_name: row.get(0)?,
            nonce: row.get(1)?,
            ciphertext: row.get(2)?,
            expires_at: row.get(3)?,
        })
    })?;

    let mut vars = Vec::new();
    for row in rows {
        vars.push(row.map_err(EnvsGateError::Db)?);
    }
    Ok(vars)
}

pub fn delete_env_var(conn: &Connection, key: &str) -> Result<bool> {
    let affected = conn.execute("DELETE FROM env_vars WHERE key_name = ?1", params![key])?;
    Ok(affected > 0)
}
