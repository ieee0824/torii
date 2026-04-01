# torii

環境変数をハイブリッドポスト量子暗号（PQC）で保護するCLIツール。

SQLiteに暗号化して保存し、Named pipe経由で仮想`.env`ファイルとして提供できる。

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

## 使い方

### 対話モード

引数なしで起動すると対話モードに入る。

```
$ torii
Password: ********
? What do you want to do?
> Set environment variable
  Get environment variable
  List all variables
  Delete environment variable
  Serve virtual .env
  Exit
```

既存のDBに対してパスワードが間違っている場合は即座にエラー終了する。

### コマンドラインモード

#### 環境変数の設定

```
torii set -p <password> <NAME>=<VALUE>
```

有効期限付き:

```
torii set -p <password> <NAME>=<VALUE> --expires 1h
```

#### 環境変数の取得

```
torii get -p <password> <NAME>
```

#### 一覧表示

```
torii list -p <password>
```

#### 削除

```
torii delete -p <password> <NAME>
```

#### 仮想.envファイルの提供

```
torii serve -p <password> -e .env
```

1回読まれたら自動終了:

```
torii serve -p <password> -e .env --once
```

Named pipe（FIFO）として指定パスに仮想`.env`ファイルを作成する。
`cat`やアプリケーションから読み取ると、その瞬間に復号された環境変数が返される。
ディスクに平文は残らない。Ctrl+Cで停止・パイプ削除。

- FUSE不要、追加依存なし
- macOS / Linux 両対応（POSIX標準）
- 読み取りのたびに動的に復号（キャッシュなし）
- serve中に期限切れを検出した場合はstderrに警告を出力

## オプション

| フラグ | 説明 | デフォルト |
|---|---|---|
| `--db-path <path>` | SQLiteデータベースのパス | `torii.db` |
| `-p, --password <pw>` | 暗号化パスワード | （必須） |
| `--expires <duration>` | 有効期限（`set`時） | なし |
| `-e, --env-path <path>` | 仮想.envのパス（`serve`時） | `.env` |
| `--once` | 1回読まれたら終了（`serve`時） | off |

## 有効期限

`--expires` には以下の形式を指定できる:

| 形式 | 例 | 説明 |
|---|---|---|
| 相対（秒） | `30s` | 30秒後 |
| 相対（分） | `5m` | 5分後 |
| 相対（時間） | `1h` | 1時間後 |
| 相対（日） | `7d` | 7日後 |
| 日付 | `2025-12-31` | 指定日の23:59:59 |
| 日時 | `2025-12-31T23:59:59` | 指定日時 |

- `get`: 期限切れのキーにアクセスするとエラー
- `list`: 期限切れのキーは `[EXPIRED]` 付きで表示
- `serve`: 起動時に期限切れキーがあればエラー終了。serve中に期限切れになった場合は出力から除外しstderrに警告
