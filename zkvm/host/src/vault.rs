//! Authenticated snapshot encryption. Keys are provisioned separately from
//! wallet files; encryption alone does not detect replay of an old snapshot.
use std::{fs::{File, OpenOptions}, io::{self, Read, Write}, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::Path};
use ring::{aead, hkdf, rand::{SecureRandom, SystemRandom}};
use zeroize::Zeroizing;

const MAGIC: &[u8; 9] = b"ZKMOBENC1";
fn error() -> io::Error { io::Error::new(io::ErrorKind::InvalidData, "encrypted snapshot authentication failed") }

pub fn generate_key(path: &Path) -> io::Result<()> {
    let mut key = Zeroizing::new([0u8; 32]);
    SystemRandom::new().fill(key.as_mut()).map_err(|_| error())?;
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(key.as_ref())?; f.sync_all()?;
    File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()
}

pub fn load_key(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut f = File::open(path)?;
    if !f.metadata()?.is_file() || f.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "key file must be a private regular file (0600)"));
    }
    let mut key = Zeroizing::new([0;32]); f.read_exact(key.as_mut())?;
    let mut extra = [0u8;1];
    if f.read(&mut extra)? != 0 { return Err(error()); }
    Ok(key)
}

fn cipher(key: &[u8;32], salt: &[u8]) -> io::Result<aead::LessSafeKey> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(key);
    let mut derived = Zeroizing::new([0u8;32]);
    prk.expand(&[b"zkmob/wallet-snapshot/v1"], hkdf::HKDF_SHA256)
        .map_err(|_| error())?.fill(derived.as_mut()).map_err(|_| error())?;
    Ok(aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, derived.as_ref()).map_err(|_| error())?))
}

pub fn seal(key: &[u8;32], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    // A fresh 256-bit salt derives a separate key for every snapshot; the
    // fixed nonce is used only once per derived key, even after local rollback.
    let mut salt = [0u8;32]; SystemRandom::new().fill(&mut salt).map_err(|_| error())?;
    let mut header = MAGIC.to_vec(); header.extend_from_slice(&salt);
    let mut body = Zeroizing::new(plaintext.to_vec());
    cipher(key, &salt)?.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key([0;12]),
        aead::Aad::from(&header), &mut *body).map_err(|_| error())?;
    header.extend_from_slice(&body); Ok(header)
}

pub fn open(key: &[u8;32], ciphertext: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < 41 + 16 || &ciphertext[..9] != MAGIC { return Err(error()); }
    let mut body = Zeroizing::new(ciphertext[41..].to_vec());
    let len = cipher(key, &ciphertext[9..41])?.open_in_place(aead::Nonce::assume_unique_for_key([0;12]),
        aead::Aad::from(&ciphertext[..41]), &mut body).map_err(|_| error())?.len();
    body.truncate(len); Ok(body)
}
