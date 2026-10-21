//! Mints everything Reflex needs to authenticate: a private CA, a server
//! certificate, and one certificate plus one token per client.
//!
//! ```text
//! ib-certgen --out certs --server-name 10.0.0.5 --client laptop-a --client laptop-b
//! ```
//!
//! Output:
//!   ca.pem / ca.key          the CA; both binaries pin ca.pem
//!   server.pem / server.key  for ib-server
//!   <id>.pem / <id>.key      for each ib-client
//!   <id>.token               the client's copy of its token
//!   tokens.txt               the server's `client_id token` list
//!
//! Private keys and tokens are written with mode 0600 on Unix. ca.key is only
//! needed to issue more certificates; keep it off the hosts that run Reflex.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

#[derive(Parser)]
#[command(
    name = "ib-certgen",
    about = "Mint a CA, server certificate, and per-client certificates and tokens for Reflex"
)]
struct Args {
    /// Directory to write into. Created if missing.
    #[arg(long, default_value = "certs")]
    out: PathBuf,
    /// Hostnames or IPs the server certificate is valid for. `localhost` and
    /// `127.0.0.1` are always included.
    #[arg(long = "server-name")]
    server_names: Vec<String>,
    /// Client ids to issue a certificate and token for. Repeat for each client.
    #[arg(long = "client", required = true)]
    clients: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out).with_context(|| format!("creating {}", args.out.display()))?;

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Reflex CA");
    let ca = ca_params.self_signed(&ca_key)?;
    write_public(&args.out.join("ca.pem"), &ca.pem())?;
    write_secret(&args.out.join("ca.key"), &ca_key.serialize_pem())?;

    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    names.extend(args.server_names.iter().cloned());
    issue(
        &args.out,
        "server",
        names,
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        &ca_key,
    )?;

    let mut tokens = String::new();
    for id in &args.clients {
        anyhow::ensure!(
            !id.is_empty() && !id.chars().any(char::is_whitespace),
            "client id '{id}' must be non-empty and contain no whitespace"
        );
        issue(
            &args.out,
            id,
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
        )?;
        let token = hex(&rand::random::<[u8; 32]>());
        write_secret(&args.out.join(format!("{id}.token")), &token)?;
        tokens.push_str(&format!("{id} {token}\n"));
    }
    write_secret(&args.out.join("tokens.txt"), &tokens)?;

    eprintln!(
        "[certgen] wrote CA, server certificate and {} client credential set(s) to {}",
        args.clients.len(),
        args.out.display()
    );
    Ok(())
}

/// Issue one leaf certificate signed by the CA and write `<name>.pem` and
/// `<name>.key`.
fn issue(
    out: &Path,
    name: &str,
    subject_alt_names: Vec<String>,
    purpose: ExtendedKeyUsagePurpose,
    ca: &Certificate,
    ca_key: &KeyPair,
) -> Result<()> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(subject_alt_names)?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.extended_key_usages = vec![purpose];
    let cert = params.signed_by(&key, ca, ca_key)?;
    write_public(&out.join(format!("{name}.pem")), &cert.pem())?;
    write_secret(&out.join(format!("{name}.key")), &key.serialize_pem())?;
    Ok(())
}

fn write_public(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

fn write_secret(path: &Path, contents: &str) -> Result<()> {
    write_public(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
