use data_encoding::HEXLOWER;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::{ec::EcGroup, ec::EcKey};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

pub fn create_keys() -> Result<(PKey<Private>, String), anyhow::Error> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key_pair = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(key_pair.clone())?;

    let public_key = key_pair.public_key();
    let ec_pub_key = EcKey::from_public_key(&group, public_key)?;
    let public_key_pem = &ec_pub_key.public_key_to_pem()?;
    Ok((private_key, String::from_utf8(public_key_pem.to_vec())?))
}

pub fn create_signer(key: &PKey<Private>) -> Result<Signer<'_>, openssl::error::ErrorStack> {
    let signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    Ok(signer)
}

pub fn sha256_digest(path: PathBuf) -> Result<String, anyhow::Error> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let digest = {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    Ok(HEXLOWER.encode(digest.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create_keys() {
        let (private_key, public_key_pem) = create_keys().unwrap();
        assert!(private_key.ec_key().is_ok());
        assert!(public_key_pem.contains("BEGIN PUBLIC KEY"));
    }
    // test signer
    #[test]
    fn test_create_signer() {
        let (private_key, _) = create_keys().unwrap();
        let mut signer = create_signer(&private_key).unwrap();
        assert!(signer.update(b"lolwut").is_ok());
    }
    // test sha256_digest
    #[test]
    fn test_sha256_digest() {
        let digest = sha256_digest(PathBuf::from("test_data/test_digest.txt")).unwrap();
        assert_eq!(
            digest,
            "6c3b04483dacd643f7cd12086d817e0a9233a2192ba2030c64049d2952f198b5"
        );
    }
}
