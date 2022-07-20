use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::{ec::EcGroup, ec::EcKey};

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
}
