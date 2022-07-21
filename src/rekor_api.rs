use rekor::apis::{configuration::Configuration, entries_api};
use rekor::models::{
    hashedrekord::{AlgorithmKind, Data, Hash, PublicKey, Signature, Spec},
    ProposedEntry,
    LogEntry,
};
use url::Url;

pub async fn create_log(hash: &str, public_key: &str, signature: &str) -> Result<LogEntry, rekor::apis::Error<entries_api::CreateLogEntryError>> {
    let configuration = Configuration::default();

    const KEY_FORMAT: &str = "x509";
    const API_VERSION: &str = "0.0.1";
    const URL: &str = "https://raw.githubusercontent.com/jyotsna-penumaka/rekor-rs/rekor-functionality/test_data/meg";

    let hash = Hash::new(
        AlgorithmKind::sha256,
        hash.to_string(),
    );
    let data = Data::new(
        hash,
        Url::parse(URL).unwrap(),
    );
    let public_key = PublicKey::new(
        public_key.to_string(),
    );
    let signature = Signature::new(
            KEY_FORMAT
            .to_string(),
        signature.to_string(),
        public_key,
    );
    let spec = Spec::new(signature, data);
    let proposed_entry = ProposedEntry::Hashedrekord {
        api_version: API_VERSION.to_string(),
        spec: spec,
    };

    let log_entry = entries_api::create_log_entry(&configuration, proposed_entry).await;
    println!("{:#?}", log_entry);
    Ok(log_entry.unwrap())
}