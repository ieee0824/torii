use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "envs-gate", about = "Protect environment variables with hybrid PQC encryption")]
pub struct Cli {
    /// Path to the SQLite database file
    #[arg(long, default_value = "envs-gate.db")]
    pub db_path: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Set an environment variable (KEY=VALUE)
    Set {
        #[arg(short, long)]
        password: String,

        /// KEY=VALUE pair
        key_value: String,

        /// Expiration date (YYYY-MM-DD)
        #[arg(long)]
        expires: Option<String>,
    },

    /// Get an environment variable
    Get {
        #[arg(short, long)]
        password: String,

        /// Variable name
        key: String,
    },

    /// List all environment variables
    List {
        #[arg(short, long)]
        password: String,
    },

    /// Delete an environment variable
    Delete {
        #[arg(short, long)]
        password: String,

        /// Variable name
        key: String,
    },

    /// Serve a virtual .env file via named pipe
    Serve {
        #[arg(short, long)]
        password: String,

        /// Path for the virtual .env file
        #[arg(short = 'e', long = "env-path", default_value = ".env")]
        env_path: String,
    },
}
