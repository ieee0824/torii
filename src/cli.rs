use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "torii",
    about = "Protect environment variables with hybrid PQC encryption"
)]
pub struct Cli {
    /// Path to the SQLite database file (overrides --namespace)
    #[arg(long)]
    pub db_path: Option<String>,

    /// Namespace for isolating databases
    #[arg(short = 'n', long, default_value = "default")]
    pub namespace: String,

    /// Path to the audit log file
    #[arg(long)]
    pub log_path: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Set an environment variable (KEY=VALUE)
    Set {
        /// KEY=VALUE pair
        key_value: String,

        /// Expiration date
        #[arg(long)]
        expires: Option<String>,
    },

    /// Get an environment variable
    Get {
        /// Variable name
        key: String,
    },

    /// List all environment variables
    List,

    /// Delete an environment variable
    Delete {
        /// Variable name
        key: String,
    },

    /// Serve a virtual .env file via named pipe
    Serve {
        /// Path for the virtual .env file
        #[arg(short = 'e', long = "env-path", default_value = ".env")]
        env_path: String,

        /// Exit after the first read
        #[arg(long)]
        once: bool,

        /// Exit after N seconds of inactivity since last read
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        timeout: Option<u64>,
    },

    /// Execute a command with decrypted environment variables injected
    Exec {
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Rotate password (re-wrap DEK with new password)
    RotatePassword,

    /// Rotate DEK (generate new DEK and re-encrypt all values)
    RotateDek,

    /// List all namespaces
    Namespaces,

    /// Generate shell completions
    Completions {
        /// Shell type (bash, zsh, fish, elvish, powershell)
        shell: clap_complete::Shell,
    },

    /// View audit logs
    Logs {
        /// Output format
        #[arg(long, default_value = "tsv")]
        format: String,
    },
}
