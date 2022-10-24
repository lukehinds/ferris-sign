use sigstore::rekor::apis::{configuration::Configuration, entries_api};
use sigstore::rekor::models::{
    hashedrekord::{AlgorithmKind, Data, Hash, PublicKey, Signature, Spec},
    LogEntry, ProposedEntry,
};

pub async fn create_log(
    hash: &str,
    public_key: &str,
    signature: &str,
) -> Result<LogEntry, anyhow::Error> {
    let configuration = Configuration::default();

    const API_VERSION: &str = "0.0.1";

    let hash = Hash::new(AlgorithmKind::sha256, hash.to_string());
    let data = Data::new(hash);
    let public_key = PublicKey::new(public_key.to_string());
    let signature = Signature::new(signature.to_string(), public_key);
    let spec = Spec::new(signature, data);
    let proposed_entry = ProposedEntry::Hashedrekord {
        api_version: API_VERSION.to_string(),
        spec,
    };

    let log_entry = entries_api::create_log_entry(&configuration, proposed_entry).await;
    Ok(log_entry?)
}

pub async fn get_entry_by_uuid(uuid: &str) -> Result<LogEntry, anyhow::Error> {
    let configuration = Configuration::default();

    let log_entry = entries_api::get_log_entry_by_uuid(&configuration, uuid).await;
    Ok(log_entry?)
}
