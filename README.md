# torii

環境変数をハイブリッドポスト量子暗号（PQC）で保護するCLIツール。

SQLiteに暗号化して保存し、Named pipe経由で仮想`.env`ファイルとして提供、またはコマンドの環境変数に直接注入できる。

## アーキテクチャ

```
                          torii
                ┌──────────────────────┐
                │   CLI / TUI          │
                │  (clap + dialoguer)  │
                └──────┬───────────────┘
                       │
              ┌────────▼────────┐
              │   Password      │
              │  (prompt input) │
              └────────┬────────┘
                       │
         ┌─────────────▼─────────────┐
         │      Crypto Engine        │
         │                           │
         │  Argon2id(password, salt) │
         │         │                 │
         │    ┌────▼────┐            │
         │    │ 64-byte │            │
         │    │  seed   │            │
         │    └──┬───┬──┘            │
         │       │   │               │
         │  ┌────▼┐ ┌▼─────────┐    │
         │  │X25519│ │ML-KEM-768│    │
         │  └──┬──┘ └────┬─────┘    │
         │     │         │          │
         │  ┌──▼─────────▼──┐      │
         │  │ HKDF-SHA256   │      │
         │  │ (hybrid KEM)  │      │
         │  └──────┬────────┘      │
         │         │               │
         │  ┌──────▼────────┐      │
         │  │  AES-256-GCM  │      │
         │  │  (DEK wrap)   │      │
         │  └──────┬────────┘      │
         │         │               │
         │     ┌───▼───┐           │
         │     │  DEK  │           │
         │     └───┬───┘           │
         │         │               │
         │  ┌──────▼────────┐      │
         │  │  AES-256-GCM  │      │
         │  │ (value encrypt)│     │
         └──┴───────────────┴──────┘
                       │
              ┌────────▼────────┐
              │   SQLite (0600) │
              │  ┌────────────┐ │
              │  │  metadata  │ │
              │  │ (keys,salt)│ │
              │  ├────────────┤ │
              │  │  env_vars  │ │
              │  │(encrypted) │ │
              │  └────────────┘ │
              └────────┬────────┘
                       │
              ┌────────▼────────────────────┐
              │                             │
              │   ┌─────────────────────┐   │
              │   │  Named Pipe (serve) │   │
              │   │  (FIFO, 0600)       │   │
              │   │                     │   │
              │   │ cat .env ──────────►│──►│──► KEY=VALUE
              │   │  (on demand         │   │    KEY=VALUE
              │   │   decryption)       │   │    ...
              │   └─────────────────────┘   │
              │                             │
              │   ┌─────────────────────┐   │
              │   │  Exec Mode          │   │
              │   │                     │   │
              │   │ Command.envs() ────►│──►│──► child process
              │   │  (direct inject     │   │    (env vars in
              │   │   + signal fwd)     │   │     memory only)
              │   └─────────────────────┘   │
              │                             │
              └─────────────────────────────┘
```

## 暗号化スキーム

**Wrapped DEK方式 + ハイブリッドKEM**

- パスワードから **Argon2id** で鍵素材を導出
- **ML-KEM-768**（NIST FIPS 203）+ **X25519** のハイブリッド鍵カプセル化
  - 両方の共有秘密を **HKDF-SHA256** で結合し、ラッピング鍵を生成
  - どちらか一方のアルゴリズムが将来的に危殆化しても、もう一方が安全であれば鍵は保護される
- DEK（データ暗号化鍵）を **AES-256-GCM** でラップ
- 個々の環境変数もDEK + AES-256-GCMで暗号化（値ごとにランダムnonce）

## インストール

```bash
cargo install --path .
```

## シェル補完

```bash
# bash
torii completions bash > ~/.bash_completion.d/torii

# zsh
torii completions zsh > ~/.zfunc/_torii

# fish
torii completions fish > ~/.config/fish/completions/torii.fish
```

## 使い方

パスワードは全コマンドで対話的にプロンプト入力される（プロセスリストに露出しない）。

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
torii set <NAME>=<VALUE>
```

有効期限付き:

```
torii set <NAME>=<VALUE> --expires 1h
```

#### 環境変数の取得

```
torii get <NAME>
```

#### 一覧表示

```
torii list
```

#### 削除

```
torii delete <NAME>
```

#### コマンドへの環境変数注入

```
torii exec -- node server.js
torii exec -- docker compose up
```

復号した環境変数を子プロセスの環境変数として直接注入して実行する。
ファイルシステムに一切痕跡を残さず（FIFOすら不要）、より直接的な方法。

- 環境変数は `std::process::Command::envs()` で子プロセスに注入
- 注入後、親プロセス側の平文は即座にzeroize
- SIGTERM/SIGINT を子プロセスにフォワーディング
- 子プロセスの終了コードをそのまま返す（シグナル終了時は128+signal）
- 期限切れチェックはexec前に1回実行、期限切れがあればエラー終了

#### 仮想.envファイルの提供

```
torii serve -e .env
```

1回読まれたら自動終了:

```
torii serve -e .env --once
```

Named pipe（FIFO）として指定パスに仮想`.env`ファイルを作成する。
`cat`やアプリケーションから読み取ると、その瞬間に復号された環境変数が返される。
ディスクに平文は残らない。Ctrl+Cで停止・パイプ削除。

- FUSE不要、追加依存なし
- macOS / Linux 両対応（POSIX標準）
- 読み取りのたびに動的に復号（キャッシュなし）
- serve中に期限切れを検出した場合はstderrに警告を出力

#### パスワードローテーション

```
torii rotate-password
```

旧パスワードで復号したDEKを新パスワードで再ラップする。DEKは変更されないため、全環境変数の再暗号化は不要で高速に完了する。

- 旧パスワードと新パスワードを対話的に入力（新パスワードは確認入力あり）
- DEK自体は変更されないため、暗号化された環境変数には影響なし
- 旧パスワードが間違っている場合はエラー終了（既存データは変更されない）

#### DEKローテーション

```
torii rotate-dek
```

新しいDEKを生成し、全環境変数を新DEKで再暗号化する。トランザクション内で原子的に実行されるため、途中で失敗しても既存データには影響しない。

- 全環境変数を旧DEKで復号→新DEKで再暗号化（値の数に比例）
- 新しいnonceが各値に対して生成される（nonce再利用防止）
- SQLiteトランザクションによる原子性保証（途中失敗時はロールバック）
- 有効期限は保持される

#### 監査ログの表示

```
torii logs                # TSV形式（デフォルト）
torii logs --format json  # JSON形式
```

## Namespace

プロジェクトごとにデータベースと監査ログを分離できる。

```
~/.torii/
  default/        # デフォルト namespace
    torii.db
    audit.log
  myproject/      # カスタム namespace
    torii.db
    audit.log
```

### 使い方

```
torii -n myproject set API_KEY=xxx    # myproject namespace に保存
torii -n myproject get API_KEY        # myproject namespace から取得
torii namespaces                      # namespace 一覧表示
```

- `--db-path` 未指定時、データベースは `~/.torii/<namespace>/torii.db` に保存される
- namespace ごとにパスワードは独立（別々のDEK）
- namespace 間のデータは完全に分離されている
- `--db-path` を明示指定した場合、namespace は無視される
- namespace 名は英数字、ハイフン、アンダースコアのみ（最大64文字）
- namespace ディレクトリはオーナーのみアクセス可（0700）

## オプション

| フラグ | 説明 | デフォルト |
|---|---|---|
| `--db-path <path>` | SQLiteデータベースのパス（namespace を上書き） | `~/.torii/default/torii.db` |
| `-n, --namespace <name>` | namespace 名 | `default` |
| `--log-path <path>` | 監査ログファイルのパス | namespace 内の `audit.log` |
| `--expires <duration>` | 有効期限（`set`時） | なし |
| `-e, --env-path <path>` | 仮想.envのパス（`serve`時） | `.env` |
| `--once` | 1回読まれたら終了（`serve`時） | off |

## セキュリティ

- パスワードはプロンプト入力のみ（`ps`コマンドで見えない）
- パスワード・DEK・鍵導出素材はメモリ上で使用後にzeroize
- DBファイルはオーナーのみ読み書き可（0600）
- namespace ディレクトリはオーナーのみアクセス可（0700）
- Named pipeもオーナーのみ読み書き可（0600）
- execモードでは注入後に親プロセス側の平文を即座にzeroize
- DEKローテーションはIMMEDIATEトランザクション内で原子的に実行（途中失敗時はロールバック）
- Linuxでは `/proc/<pid>/environ` 経由でプロセスオーナーとrootが環境変数を参照可能（OS制約）

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
- `exec`: 実行前に期限切れキーがあればエラー終了
