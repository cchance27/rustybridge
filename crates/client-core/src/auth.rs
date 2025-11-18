use std::{
    collections::HashMap, path::{Path, PathBuf}, sync::Arc
};

// Internal Result type alias
type Result<T> = crate::ClientResult<T>;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cbc::{
    Decryptor, cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7}
};
use des::TdesEde3;
use hex::FromHex;
use rpassword::{prompt_password, read_password};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::EncodePrivateKey};
use russh::{
    MethodSet, client::{self, AuthResult, KeyboardInteractiveAuthResponse}, keys::{self, Certificate, HashAlg, PrivateKeyWithHashAlg}
};
use ssh_core::session::SessionHandle;
use secrecy::{ExposeSecret, SecretString};
use tokio::{fs, task};
use tracing::{debug, info, warn};

use crate::ClientIdentity;

pub struct AuthPreferences<'a> {
    pub username: &'a str,
    pub password: Option<&'a SecretString>,
    pub prompt_password: bool,
    pub password_prompt: Option<&'a str>,
    pub identities: &'a [ClientIdentity],
    pub allow_keyboard_interactive: bool,
    pub use_agent_auth: bool,
    pub agent_socket: Option<&'a Path>,
}

pub async fn authenticate<H>(session: &mut SessionHandle<H>, prefs: AuthPreferences<'_>) -> Result<()>
where
    H: client::Handler + Send,
{
    let mut methods = Vec::new();

    if !prefs.identities.is_empty() {
        methods.push(AuthMethod::PublicKeys(load_identities(prefs.identities).await?));
    }

    if prefs.use_agent_auth {
        let socket = prefs
            .agent_socket
            .ok_or_else(|| crate::ClientError::Other("SSH agent requested but SSH_AUTH_SOCK is unset".to_string()))?;
        methods.push(AuthMethod::Agent {
            socket: socket.to_path_buf(),
        });
    }

    if let Some(password) = prefs.password {
        methods.push(AuthMethod::Password(password.clone()));
    } else if prefs.prompt_password {
        let prompt = prefs.password_prompt.unwrap_or("password: ");
        methods.push(AuthMethod::PasswordPrompt {
            prompt: prompt.to_string(),
        });
    }

    if prefs.allow_keyboard_interactive {
        methods.push(AuthMethod::KeyboardInteractive);
    }

    if methods.is_empty() {
        return Err(crate::ClientError::AuthFailed(
            "no authentication methods configured; supply a password, identity, --agent-auth, or --keyboard-interactive".to_string(),
        ));
    }

    let rsa_hash_hint = session.best_supported_rsa_hash().await.unwrap_or(None).flatten();

    for mut method in methods {
        let label = method.label();
        match method.authenticate(session, prefs.username, rsa_hash_hint).await {
            Ok(AuthResult::Success) => {
                info!(method = label, "authentication succeeded");
                return Ok(());
            }
            Ok(AuthResult::Failure { .. }) => {
                warn!(method = label, "authentication rejected by server");
            }
            Err(err) => {
                warn!(method = label, error = ?err, "authentication attempt failed");
            }
        }
    }

    Err(crate::ClientError::AuthFailed(
        "all authentication methods were rejected by the server".to_string(),
    ))
}

enum AuthMethod {
    Password(SecretString),
    PasswordPrompt { prompt: String },
    PublicKeys(Vec<LoadedIdentity>),
    Agent { socket: PathBuf },
    KeyboardInteractive,
}

impl AuthMethod {
    fn label(&self) -> &'static str {
        match self {
            AuthMethod::Password(_) => "password",
            AuthMethod::PasswordPrompt { .. } => "password",
            AuthMethod::PublicKeys(_) => "publickey",
            AuthMethod::Agent { .. } => "agent",
            AuthMethod::KeyboardInteractive => "keyboard-interactive",
        }
    }

    async fn authenticate<H>(&mut self, session: &mut SessionHandle<H>, username: &str, rsa_hint: Option<HashAlg>) -> Result<AuthResult>
    where
        H: client::Handler + Send,
    {
        match self {
            AuthMethod::Password(password) => session
                .authenticate_password(username.to_string(), password.expose_secret().to_string())
                .await
                .map_err(Into::into),
            AuthMethod::PasswordPrompt { prompt } => {
                let password = prompt_for_password(prompt).await?;
                session
                    .authenticate_password(username.to_string(), password.expose_secret().to_string())
                    .await
                    .map_err(Into::into)
            }
            AuthMethod::PublicKeys(keys) => authenticate_public_keys(session, username, keys, rsa_hint).await,
            AuthMethod::Agent { socket } => authenticate_via_agent(session, username, socket, rsa_hint).await,
            AuthMethod::KeyboardInteractive => authenticate_keyboard_interactive(session, username).await,
        }
    }
}

struct LoadedIdentity {
    key: Arc<keys::PrivateKey>,
    cert: Option<Certificate>,
}

async fn load_identities(identities: &[ClientIdentity]) -> Result<Vec<LoadedIdentity>> {
    let mut loaded = Vec::with_capacity(identities.len());
    for identity in identities {
        let key_data = fs::read_to_string(&identity.key_path)
            .await
            .map_err(crate::ClientError::Io)?;
        let key = Arc::new(load_private_key(&key_data, &identity.key_path)?);

        let cert = resolve_certificate(identity).await?;
        loaded.push(LoadedIdentity { key, cert });
    }
    Ok(loaded)
}

async fn resolve_certificate(identity: &ClientIdentity) -> Result<Option<Certificate>> {
    let (candidate, was_explicit) = if let Some(path) = identity.cert_path.clone() {
        (Some(path), true)
    } else {
        (default_cert_path(&identity.key_path), false)
    };
    if let Some(path) = candidate {
        if !path.exists() {
            if was_explicit {
                return Err(crate::ClientError::Other(format!(
                    "specified certificate {} does not exist",
                    path.display()
                )));
            }
            return Ok(None);
        }
        let blob = fs::read_to_string(&path).await.map_err(crate::ClientError::Io)?;
        let cert = Certificate::from_openssh(&blob).map_err(|e| crate::ClientError::Crypto(e.to_string()))?;
        return Ok(Some(cert));
    }
    Ok(None)
}

fn load_private_key(data: &str, path: &Path) -> Result<keys::PrivateKey> {
    match keys::PrivateKey::from_openssh(data) {
        Ok(key) => Ok(key),
        Err(_openssh_err) => match keys::decode_secret_key(data, None) {
            Ok(key) => Ok(key),
            Err(keys::Error::KeyIsEncrypted) => {
                let prompt = format!("Enter passphrase for {}: ", path.display());
                let passphrase = prompt_password(prompt)?;
                let key = keys::decode_secret_key(data, Some(&passphrase))
                    .map_err(|err| crate::ClientError::Crypto(format!("failed to decrypt {}: {err}", path.display())))?;
                Ok(key)
            }
            Err(_err) => {
                if let Some(key) = try_convert_legacy_pem(data, path)? {
                    return Ok(key);
                }
                Err(crate::ClientError::Crypto(format!(
                    "{} is not a valid OpenSSH or PEM private key",
                    path.display()
                )))
            }
        },
    }
}

fn try_convert_legacy_pem(data: &str, path: &Path) -> Result<Option<keys::PrivateKey>> {
    let Some(parts) = parse_rsa_pem(data) else {
        return Ok(None);
    };
    let PemParts { headers, body } = parts;
    let mut der = BASE64
        .decode(body)
        .map_err(|e| crate::ClientError::Crypto(format!("base64 decode error: {e}")))?;

    if is_encrypted(&headers) {
        der = decrypt_traditional_pem(&headers, &der, path)?;
    }

    let key = load_pkcs1(&der)?;
    Ok(Some(key))
}

struct PemParts {
    headers: HashMap<String, String>,
    body: String,
}

fn parse_rsa_pem(data: &str) -> Option<PemParts> {
    let begin = "-----BEGIN RSA PRIVATE KEY-----";
    let end = "-----END RSA PRIVATE KEY-----";
    let start = data.find(begin)? + begin.len();
    let end_idx = data.find(end)?;
    let section = &data[start..end_idx];
    let mut headers = HashMap::new();
    let mut body = String::new();
    let mut in_headers = true;
    let mut saw_header = false;
    for line in section.lines() {
        let line = line.trim();
        if in_headers {
            if line.is_empty() {
                if saw_header {
                    in_headers = false;
                }
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
                saw_header = true;
                continue;
            }
            in_headers = false;
        }
        if !line.is_empty() {
            body.push_str(line);
        }
    }
    Some(PemParts { headers, body })
}

fn is_encrypted(headers: &HashMap<String, String>) -> bool {
    matches!(headers.get("Proc-Type"), Some(value) if value.contains("ENCRYPTED"))
}

fn decrypt_traditional_pem(headers: &HashMap<String, String>, ciphertext: &[u8], path: &Path) -> Result<Vec<u8>> {
    let dek_info = headers
        .get("DEK-Info")
        .ok_or_else(|| crate::ClientError::Crypto(format!("missing DEK-Info header in {}", path.display())))?;
    let mut parts = dek_info.split(',');
    let algo = parts.next().unwrap_or_default().trim();
    let iv_hex = parts.next().unwrap_or_default().trim();
    let iv = Vec::from_hex(iv_hex).map_err(|_| crate::ClientError::Crypto(format!("invalid DEK-Info IV for {}", path.display())))?;
    match algo {
        "DES-EDE3-CBC" => decrypt_des_ede3(ciphertext, &iv, path),
        other => {
            Err(crate::ClientError::Crypto(format!(
                "unsupported PEM cipher {other} in {}",
                path.display()
            )))
        }
    }
}

fn decrypt_des_ede3(ciphertext: &[u8], iv: &[u8], path: &Path) -> Result<Vec<u8>> {
    if iv.len() < 8 {
        return Err(crate::ClientError::Crypto(format!(
            "invalid IV for DES-EDE3-CBC in {}",
            path.display()
        )));
    }
    let salt = &iv[..8];
    let prompt = format!("Enter passphrase for {}: ", path.display());
    let passphrase = prompt_password(prompt)?;
    let key = evp_bytes_to_key(passphrase.as_bytes(), salt, 24);
    let cipher = Decryptor::<TdesEde3>::new_from_slices(&key, &iv[..8])
        .map_err(|err| crate::ClientError::Crypto(format!("unable to init DES-EDE3 cipher: {err}")))?;
    let mut buf = ciphertext.to_vec();
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|err| crate::ClientError::Crypto(format!("failed to decrypt {}: {err}", path.display())))?
        .to_vec();
    Ok(decrypted)
}

fn evp_bytes_to_key(passphrase: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Option<[u8; 16]> = None;
    while key.len() < key_len {
        let mut data = Vec::new();
        if let Some(ref digest) = prev {
            data.extend_from_slice(digest);
        }
        data.extend_from_slice(passphrase);
        data.extend_from_slice(salt);
        let digest = md5::compute(&data).0;
        prev = Some(digest);
        key.extend_from_slice(&digest);
    }
    key.truncate(key_len);
    key
}

fn load_pkcs1(der: &[u8]) -> Result<keys::PrivateKey> {
    let rsa = RsaPrivateKey::from_pkcs1_der(der).map_err(|e| crate::ClientError::Crypto(format!("PKCS1 decode error: {e}")))?;
    let pkcs8 = rsa
        .to_pkcs8_pem(Default::default())
        .map_err(|e| crate::ClientError::Crypto(format!("PKCS8 encode error: {e}")))?;
    let key = keys::decode_secret_key(pkcs8.as_str(), None).map_err(|e| crate::ClientError::Crypto(e.to_string()))?;
    Ok(key)
}

fn default_cert_path(key_path: &Path) -> Option<PathBuf> {
    let cert = format!("{}-cert.pub", key_path.display());
    Some(PathBuf::from(cert))
}

async fn authenticate_public_keys<H>(
    session: &mut SessionHandle<H>,
    username: &str,
    identities: &[LoadedIdentity],
    rsa_hint: Option<HashAlg>,
) -> Result<AuthResult>
where
    H: client::Handler + Send,
{
    let mut last_failure: Option<AuthResult> = None;

    for identity in identities {
        debug!(key = ?identity.key.algorithm(), "attempting public-key auth");
        let result = if let Some(cert) = &identity.cert {
            session
                .authenticate_openssh_cert(username.to_string(), identity.key.clone(), cert.clone())
                .await
        } else {
            let hash_alg = if identity.key.algorithm().is_rsa() { rsa_hint } else { None };
            let key = PrivateKeyWithHashAlg::new(identity.key.clone(), hash_alg);
            session.authenticate_publickey(username.to_string(), key).await
        };

        match result {
            Ok(success) if success.success() => return Ok(success),
            Ok(other) => last_failure = Some(other),
            Err(err) => {
                warn!(error = ?err, "public-key authentication attempt failed");
            }
        }
    }

    Ok(last_failure.unwrap_or(AuthResult::Failure {
        remaining_methods: MethodSet::empty(),
        partial_success: false,
    }))
}

async fn authenticate_via_agent<H>(
    session: &mut SessionHandle<H>,
    username: &str,
    socket: &Path,
    rsa_hint: Option<HashAlg>,
) -> Result<AuthResult>
where
    H: client::Handler + Send,
{
    #[cfg(not(unix))]
    {
        warn!("agent authentication is not supported on this platform");
        return Ok(AuthResult::Failure {
            remaining_methods: MethodSet::empty(),
            partial_success: false,
        });
    }

    #[cfg(unix)]
    {
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(socket).await.map_err(crate::ClientError::Io)?;
        let mut agent = russh::keys::agent::client::AgentClient::connect(stream);

        let mut identities = agent
            .request_identities()
            .await
            .map_err(|e| crate::ClientError::Other(format!("failed to list identities from SSH agent: {e}")))?;
        if identities.is_empty() {
            return Err(crate::ClientError::AuthFailed("SSH agent has no loaded keys".to_string()));
        }

        debug!(count = identities.len(), "attempting agent-based authentication");

        for key in identities.drain(..) {
            let hash_alg = match key.algorithm() {
                keys::Algorithm::Rsa { .. } => rsa_hint,
                _ => None,
            };
            match session
                .authenticate_publickey_with(username.to_string(), key.clone(), hash_alg, &mut agent)
                .await
            {
                Ok(result) if result.success() => return Ok(result),
                Ok(result) => {
                    if matches!(result, AuthResult::Failure { .. }) {
                        continue;
                    }
                }
                Err(err) => {
                    warn!(error = ?err, "agent authentication attempt failed");
                }
            }
        }

        Ok(AuthResult::Failure {
            remaining_methods: MethodSet::empty(),
            partial_success: false,
        })
    }
}

async fn authenticate_keyboard_interactive<H>(session: &mut SessionHandle<H>, username: &str) -> Result<AuthResult>
where
    H: client::Handler + Send,
{
    let mut response = session
        .authenticate_keyboard_interactive_start(username.to_string(), Option::<String>::None)
        .await?;

    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => {
                return Ok(AuthResult::Success);
            }
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                });
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let answers = prompt_keyboard_inputs(&name, &instructions, &prompts).await?;
                response = session.authenticate_keyboard_interactive_respond(answers).await?;
            }
        }
    }
}

async fn prompt_keyboard_inputs(name: &str, instructions: &str, prompts: &[russh::client::Prompt]) -> Result<Vec<String>> {
    let mut responses = Vec::with_capacity(prompts.len());
    for prompt in prompts {
        let response = spawn_prompt(name, instructions, prompt).await?;
        responses.push(response);
    }
    Ok(responses)
}

async fn spawn_prompt(name: &str, instructions: &str, prompt: &russh::client::Prompt) -> Result<String> {
    let name = name.to_string();
    let instructions = instructions.to_string();
    let prompt_text = prompt.prompt.clone();
    let echo = prompt.echo;
    task::spawn_blocking(move || {
        if !name.is_empty() {
            println!("{name}");
        }
        if !instructions.is_empty() {
            println!("{instructions}");
        }
        print!("{}", prompt_text);
        use std::io::{self, Write};
        io::stdout().flush().ok();
        if echo {
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            Ok(input.trim_end_matches(['\r', '\n']).to_string())
        } else {
            read_password().map_err(Into::into)
        }
    })
    .await
    .map_err(|e| crate::ClientError::Other(format!("task join error: {e}")))?
}

async fn prompt_for_password(prompt: &str) -> Result<SecretString> {
    let prompt = prompt.to_string();
    task::spawn_blocking(move || {
        prompt_password(prompt)
            .map(|s| SecretString::new(s.into_boxed_str()))
            .map_err(Into::into)
    })
    .await
    .map_err(|e| crate::ClientError::Other(format!("task join error: {e}")))?
}
