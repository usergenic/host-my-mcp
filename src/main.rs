use std::path::PathBuf;

use clap::{Parser, Subcommand};
use host_my_mcp::{
    Config,
    config::{AuthMode, LogFormat},
};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(
    name = "host-my-mcp",
    version,
    about = "One OAuth-protected MCP gateway in front of your local stdio MCP servers"
)]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(
        short,
        long,
        global = true,
        env = "HOST_MY_MCP_CONFIG",
        default_value = "host-my-mcp.yaml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the gateway (default).
    Serve,
    /// Validate the configuration and print the resolved mounts, then exit.
    Check,
    /// Print the protected-resource metadata documents the gateway will serve.
    Metadata,
}

fn init_logging(cfg: &Config) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.logging.level));
    let registry = tracing_subscriber::registry().with(filter);
    match cfg.logging.format {
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json().with_target(true))
            .init(),
        LogFormat::Text => registry
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    init_logging(&config);

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => host_my_mcp::http::serve(config).await,
        Command::Check => {
            println!("config OK: {}", cli.config.display());
            println!("public_url: {}", config.public_origin());
            println!(
                "auth: {}",
                match config.auth.mode() {
                    AuthMode::Disabled => "DISABLED".to_string(),
                    AuthMode::External =>
                        format!("external issuer {}", config.auth.issuer.as_ref().unwrap()),
                    AuthMode::BuiltIn => format!(
                        "built-in authorization server at {} (providers: {}; state_dir {})",
                        config.public_origin(),
                        config
                            .auth
                            .providers
                            .keys()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", "),
                        config.auth.state_dir().display()
                    ),
                }
            );
            if config.auth.mode() == AuthMode::BuiltIn {
                println!(
                    "  Google Cloud Console → Authorized redirect URI: {}{}",
                    config.public_origin(),
                    host_my_mcp::oauth::CALLBACK_PATH
                );
            }
            for (name, s) in &config.servers {
                println!(
                    "  {name}: {} -> {} {} (resource {}, lifecycle {:?}, users {:?})",
                    s.path(),
                    s.command,
                    s.args.join(" "),
                    s.resource(),
                    s.lifecycle,
                    s.allowed_users
                );
            }
            Ok(())
        }
        Command::Metadata => {
            let origin = config.public_origin();
            for (name, s) in &config.servers {
                let md = host_my_mcp::auth::ProtectedResourceMetadata::for_server(&config, name, s);
                println!(
                    "# {}",
                    host_my_mcp::auth::metadata::metadata_url(&origin, s.path())
                );
                println!("{}", serde_json::to_string_pretty(&md)?);
            }
            Ok(())
        }
    }
}
