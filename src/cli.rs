use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "torii",
    about = "Protect environment variables with hybrid PQC encryption"
)]
pub struct Cli {
    /// Path to the SQLite database file
    #[arg(long, default_value = "torii.db")]
    pub db_path: String,

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
    },

    /// View audit logs
    Logs {
        /// Output format
        #[arg(long, default_value = "tsv")]
        format: String,
    },
}
