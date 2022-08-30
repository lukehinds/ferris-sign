use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

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
