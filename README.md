# envs-gate

環境変数をハイブリッドポスト量子暗号（PQC）で保護するCLIツール。

SQLiteに暗号化して保存し、FUSE経由で仮想`.env`ファイルとして提供できる。

## 暗号化スキーム

**Wrapped DEK方式 + ハイブリッドKEM**

- パスワードから **Argon2id** で鍵素材を導出
- **ML-KEM-768**（NIST FIPS 203）+ **X25519** のハイブリッド鍵カプセル化
  - 両方の共有秘密を **HKDF-SHA256** で結合し、ラッピング鍵を生成
  - 量子コンピュータ **と** 古典コンピュータの両方を破らないと鍵を復元できない
- DEK（データ暗号化鍵）を **AES-256-GCM** でラップ
- 個々の環境変数もDEK + AES-256-GCMで暗号化（値ごとにランダムnonce）

## インストール

```bash
cargo install --path .
```

FUSE対応ビルド（macFUSEが必要）:

```bash
cargo install --path . --features fuse
```

## 使い方

### 環境変数の設定

```
envs-gate set -p <password> <NAME>=<VALUE>
```

有効期限付き:

```
envs-gate set -p <password> <NAME>=<VALUE> --expires 2025-06-30
```

### 環境変数の取得

```
envs-gate get -p <password> <NAME>
```

### 一覧表示

```
envs-gate list -p <password>
```

### 削除

```
envs-gate delete -p <password> <NAME>
```

### 仮想.envファイルの提供（FUSE）

```
envs-gate serve -p <password> -e .env
```

マウント中は指定パス配下に仮想`.env`ファイルが出現し、`cat`やアプリケーションから通常のファイルとして読める。Ctrl+Cでアンマウント。

## オプション

| フラグ | 説明 | デフォルト |
|---|---|---|
| `--db-path <path>` | SQLiteデータベースのパス | `envs-gate.db` |
| `-p, --password <pw>` | 暗号化パスワード | （必須） |
| `--expires <YYYY-MM-DD>` | 有効期限（`set`時） | なし |
| `-e, --env-path <path>` | 仮想.envのパス（`serve`時） | `.env` |

## 有効期限

- `get`: 期限切れのキーにアクセスするとエラー
- `list`: 期限切れのキーは `[EXPIRED]` 付きで表示
- `serve`: 起動時に期限切れのキーがあればエラーで終了

## FUSE について

`serve`コマンドにはFUSEが必要。

- **macOS**: [macFUSE](https://osxfuse.github.io/) をインストール
- **Linux**: `libfuse-dev`（Ubuntu/Debian）または `fuse-devel`（Fedora）をインストール

`--features fuse` を付けてビルドすること。
