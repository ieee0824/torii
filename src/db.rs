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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Connection {
        open_or_create_db(":memory:").unwrap()
    }

    #[test]
    fn fresh_db_is_not_initialized() {
        let conn = test_db();
        assert!(!is_initialized(&conn).unwrap());
    }

    #[test]
    fn load_metadata_empty_returns_none() {
        let conn = test_db();
        assert!(load_metadata(&conn).unwrap().is_none());
    }

    #[test]
    fn store_and_load_metadata_roundtrip() {
        let conn = test_db();
        let meta = VaultMetadata {
            salt: vec![1; 16],
            ek_kem: vec![2; 32],
            x25519_pub: vec![3; 32],
            ct_kem: vec![4; 32],
            x25519_eph: vec![5; 32],
            wrap_nonce: vec![6; 12],
            wrapped_dek: vec![7; 48],
        };
        store_metadata(&conn, &meta).unwrap();

        assert!(is_initialized(&conn).unwrap());

        let loaded = load_metadata(&conn).unwrap().unwrap();
        assert_eq!(loaded.salt, meta.salt);
        assert_eq!(loaded.ek_kem, meta.ek_kem);
        assert_eq!(loaded.x25519_pub, meta.x25519_pub);
        assert_eq!(loaded.wrapped_dek, meta.wrapped_dek);
    }

    #[test]
    fn store_metadata_twice_fails() {
        let conn = test_db();
        let meta = VaultMetadata {
            salt: vec![1; 16],
            ek_kem: vec![2; 32],
            x25519_pub: vec![3; 32],
            ct_kem: vec![4; 32],
            x25519_eph: vec![5; 32],
            wrap_nonce: vec![6; 12],
            wrapped_dek: vec![7; 48],
        };
        store_metadata(&conn, &meta).unwrap();
        assert!(store_metadata(&conn, &meta).is_err());
    }

    #[test]
    fn upsert_and_get_env_var() {
        let conn = test_db();
        upsert_env_var(&conn, "KEY1", b"nonce123456!", b"cipher", None).unwrap();

        let var = get_env_var(&conn, "KEY1").unwrap().unwrap();
        assert_eq!(var.key_name, "KEY1");
        assert_eq!(var.nonce, b"nonce123456!");
        assert_eq!(var.ciphertext, b"cipher");
        assert!(var.expires_at.is_none());
    }

    #[test]
    fn upsert_overwrites_existing() {
        let conn = test_db();
        upsert_env_var(&conn, "KEY1", b"nonce1_12byte", b"value1", None).unwrap();
        upsert_env_var(
            &conn,
            "KEY1",
            b"nonce2_12byte",
            b"value2",
            Some("2030-01-01"),
        )
        .unwrap();

        let var = get_env_var(&conn, "KEY1").unwrap().unwrap();
        assert_eq!(var.ciphertext, b"value2");
        assert_eq!(var.expires_at.as_deref(), Some("2030-01-01"));
    }

    #[test]
    fn get_nonexistent_key_returns_none() {
        let conn = test_db();
        assert!(get_env_var(&conn, "MISSING").unwrap().is_none());
    }

    #[test]
    fn list_env_vars_sorted() {
        let conn = test_db();
        upsert_env_var(&conn, "ZEBRA", b"nonce_12bytes", b"z", None).unwrap();
        upsert_env_var(&conn, "APPLE", b"nonce_12bytes", b"a", None).unwrap();
        upsert_env_var(&conn, "MANGO", b"nonce_12bytes", b"m", None).unwrap();

        let vars = list_env_vars(&conn).unwrap();
        let keys: Vec<&str> = vars.iter().map(|v| v.key_name.as_str()).collect();
        assert_eq!(keys, vec!["APPLE", "MANGO", "ZEBRA"]);
    }

    #[test]
    fn list_empty_returns_empty() {
        let conn = test_db();
        assert!(list_env_vars(&conn).unwrap().is_empty());
    }

    #[test]
    fn delete_existing_key() {
        let conn = test_db();
        upsert_env_var(&conn, "KEY1", b"nonce_12bytes", b"val", None).unwrap();
        assert!(delete_env_var(&conn, "KEY1").unwrap());
        assert!(get_env_var(&conn, "KEY1").unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_key_returns_false() {
        let conn = test_db();
        assert!(!delete_env_var(&conn, "MISSING").unwrap());
    }

    #[test]
    fn env_var_with_expires() {
        let conn = test_db();
        upsert_env_var(
            &conn,
            "TEMP",
            b"nonce_12bytes",
            b"val",
            Some("2025-12-31T23:59:59"),
        )
        .unwrap();
        let var = get_env_var(&conn, "TEMP").unwrap().unwrap();
        assert_eq!(var.expires_at.as_deref(), Some("2025-12-31T23:59:59"));
    }
}
