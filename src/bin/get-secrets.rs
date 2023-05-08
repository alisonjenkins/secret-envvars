// use clap::Parser;
use secret_service::EncryptionType;
use secret_service::SecretService;
use std::error::Error;

// /// A program for storing and retrieving secret environment variables
// /// from the operating system keyring. This program is intended to be
// /// used to set environment variables for programs in the shell.
// #[derive(Parser, Debug)]
// #[command(author, version, about, long_about = None)]
// struct Args {
//     /// Add a secret to the keyring to be used as an environment variable.
//     #[clap(subcommand)]
//     save_secret: Secret,
// }

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ss = SecretService::connect(EncryptionType::Dh).await?;
    let collection = ss.get_default_collection().await?;

    let regex = regex::Regex::new(r#"^secret-envvar-(?P<envvar_name>.*)$"#)?;

    if collection.is_locked().await? {
        match collection.unlock().await {
            Ok(_) => {}
            Err(_) => {
                eprintln!("Failed to unlock keyring collection.");
                std::process::exit(1);
            }
        }
    }

    for secret in collection.get_all_items().await? {
        let label = &secret.get_label().await?.clone();
        let envvar_name = if let Some(captures) = regex.captures(label) {
            if let Some(envvar_name) = captures.name("envvar_name") {
                let envvar_name = envvar_name.clone().as_str();
                envvar_name
            } else {
                continue;
            }
        } else {
            continue;
        };

        let envvar_value = secret.get_secret().await?;
        let envvar_value = std::str::from_utf8(&envvar_value)?;

        println!("export {envvar_name}={envvar_value}");
    }

    Ok(())
}
