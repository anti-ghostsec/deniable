use std::path::PathBuf;

use super::*;

/// Cheap enough for tests; real use takes [`Kdf::DEFAULT`] or more.
const FAST: Kdf = Kdf { memory_kib: 64, passes: 1, lanes: 1 };
/// Bounds that let [`FAST`] through, and nothing much bigger.
const TEST_BOUNDS: KdfBounds = KdfBounds { min: FAST, max: Kdf { memory_kib: 1024, passes: 4, lanes: 4 } };
const SALT: [u8; 16] = [7; 16];

fn key(password: &[u8]) -> Zeroizing<[u8; KEY]> {
    derive_key(password, &SALT, FAST, &TEST_BOUNDS).unwrap()
}

/// A folder of its own for one test, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut r = [0u8; 8];
        random_bytes(&mut r).unwrap();
        let dir = std::env::temp_dir().join(format!("vaultkit-{name}-{}-{:016x}", std::process::id(), u64::from_le_bytes(r)));
        fs::create_dir(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_same_password_and_salt_give_the_same_key() {
    assert_eq!(*key(b"correct horse"), *key(b"correct horse"));
    assert_ne!(*key(b"correct horse"), *key(b"correct horsf"));
    assert_ne!(*key(b"correct horse"), *derive_key(b"correct horse", &[8; 16], FAST, &TEST_BOUNDS).unwrap());
}

#[test]
fn costs_above_the_maximum_are_refused_before_deriving() {
    // Were these derived, Argon2 would try to allocate about 4 TiB and the
    // test would abort or hang: the bounds have to be checked first.
    let huge = Kdf { memory_kib: u32::MAX, passes: 1, lanes: 1 };
    assert!(matches!(derive_key(b"pw", &SALT, huge, &KdfBounds::DEFAULT), Err(Error::KdfOutOfBounds)));
    let slow = Kdf { passes: u32::MAX, ..Kdf::DEFAULT };
    assert!(matches!(derive_key(b"pw", &SALT, slow, &KdfBounds::DEFAULT), Err(Error::KdfOutOfBounds)));
    let wide = Kdf { lanes: 1 << 20, ..Kdf::DEFAULT };
    assert!(matches!(derive_key(b"pw", &SALT, wide, &KdfBounds::DEFAULT), Err(Error::KdfOutOfBounds)));
    let just_over = Kdf { memory_kib: TEST_BOUNDS.max.memory_kib + 1, ..FAST };
    assert!(matches!(derive_key(b"pw", &SALT, just_over, &TEST_BOUNDS), Err(Error::KdfOutOfBounds)));
}

#[test]
fn costs_below_the_minimum_are_refused() {
    let cheap = Kdf { memory_kib: 8, passes: 1, lanes: 1 };
    assert!(matches!(derive_key(b"pw", &SALT, cheap, &KdfBounds::DEFAULT), Err(Error::KdfOutOfBounds)));
    assert!(matches!(derive_key(b"pw", &SALT, FAST, &KdfBounds::DEFAULT), Err(Error::KdfOutOfBounds)));
    let no_passes = Kdf { passes: 0, ..FAST };
    assert!(matches!(derive_key(b"pw", &SALT, no_passes, &TEST_BOUNDS), Err(Error::KdfOutOfBounds)));
}

#[test]
fn the_default_bounds_take_the_usual_costs() {
    assert!(KdfBounds::DEFAULT.check(Kdf::DEFAULT).is_ok());
    assert!(KdfBounds::DEFAULT.check(Kdf::DESKTOP).is_ok());
    assert!(KdfBounds::DEFAULT.check(KdfBounds::DEFAULT.max).is_ok());
    assert!(KdfBounds::DEFAULT.check(KdfBounds::DEFAULT.min).is_ok());
}

#[test]
fn a_cost_argon2_cannot_run_is_refused() {
    // Within the bounds, but Argon2 needs 8 KiB per lane.
    let bounds = KdfBounds { min: Kdf { memory_kib: 8, passes: 1, lanes: 1 }, max: TEST_BOUNDS.max };
    let thin = Kdf { memory_kib: 16, passes: 1, lanes: 4 };
    assert!(matches!(derive_key(b"pw", &SALT, thin, &bounds), Err(Error::Kdf)));
}

#[test]
fn a_short_salt_is_refused() {
    assert!(matches!(derive_key(b"pw", &[1; MIN_SALT - 1], FAST, &TEST_BOUNDS), Err(Error::ShortSalt)));
}

#[test]
fn sealed_data_opens_with_the_same_key_and_header() {
    let key = key(b"pw");
    let sealed = seal(&key, b"HDR1", b"secret settings").unwrap();
    assert_eq!(sealed.len(), NONCE + b"secret settings".len() + TAG);
    assert!(!sealed.windows(6).any(|w| w == b"secret"));
    assert_eq!(open(&key, b"HDR1", &sealed).unwrap().as_slice(), b"secret settings");
    assert_eq!(open(&key, b"HDR1", &seal(&key, b"HDR1", b"").unwrap()).unwrap().as_slice(), b"");
}

#[test]
fn each_seal_takes_a_new_nonce() {
    let key = key(b"pw");
    assert_ne!(seal(&key, b"", b"same").unwrap(), seal(&key, b"", b"same").unwrap());
}

#[test]
fn a_wrong_key_fails() {
    let sealed = seal(&key(b"pw"), b"HDR1", b"data").unwrap();
    assert!(matches!(open(&key(b"pX"), b"HDR1", &sealed), Err(Error::Decrypt)));
}

#[test]
fn any_changed_byte_fails() {
    let key = key(b"pw");
    let header = *b"HDR1 salt and cost";
    let sealed = seal(&key, &header, b"some data to protect").unwrap();
    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0x01;
        assert!(matches!(open(&key, &header, &bad), Err(Error::Decrypt)), "byte {i} of the sealed data");
    }
    for i in 0..header.len() {
        let mut bad = header;
        bad[i] ^= 0x80;
        assert!(matches!(open(&key, &bad, &sealed), Err(Error::Decrypt)), "byte {i} of the header");
    }
    for len in 0..sealed.len() {
        assert!(matches!(open(&key, &header, &sealed[..len]), Err(Error::Decrypt)), "cut to {len} bytes");
    }
    let mut longer = sealed.clone();
    longer.push(0);
    assert!(matches!(open(&key, &header, &longer), Err(Error::Decrypt)));
}

#[test]
fn a_nonce_in_the_header_is_covered_too() {
    // Formats like `MAGIC | salt | cost | nonce | ciphertext`, sealed with
    // the whole header (nonce included) as associated data.
    let key = key(b"pw");
    let nonce = random_nonce().unwrap();
    let mut header = b"MAGIC".to_vec();
    header.extend_from_slice(&nonce);
    let sealed = seal_with_nonce(&key, &nonce, &header, b"payload").unwrap();
    assert_eq!(sealed.len(), b"payload".len() + TAG);
    assert_eq!(open_with_nonce(&key, &nonce, &header, &sealed).unwrap().as_slice(), b"payload");
    let mut other = nonce;
    other[0] ^= 1;
    assert!(open_with_nonce(&key, &other, &header, &sealed).is_err());
}

#[test]
fn a_whole_vault_file_round_trip() {
    // How an app would put the pieces together, with the cost read back
    // from its own header.
    let dir = TempDir::new("roundtrip");
    let path = dir.0.join("vault.bin");
    let mut salt = [0u8; 16];
    random_bytes(&mut salt).unwrap();
    let mut header = b"APP1".to_vec();
    for v in [FAST.memory_kib, FAST.passes, FAST.lanes] {
        header.extend_from_slice(&v.to_le_bytes());
    }
    header.extend_from_slice(&salt);
    let key = derive_key(b"1234", &salt, FAST, &TEST_BOUNDS).unwrap();
    let mut file = header.clone();
    file.extend_from_slice(&seal(&key, &header, b"{\"accounts\":[]}").unwrap());
    write_private_atomic(&path, &file).unwrap();

    let file = fs::read(&path).unwrap();
    let (header, sealed) = file.split_at(4 + 12 + 16);
    let num = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
    let kdf = Kdf { memory_kib: num(4), passes: num(8), lanes: num(12) };
    let key = derive_key(b"1234", &header[16..], kdf, &TEST_BOUNDS).unwrap();
    assert_eq!(open(&key, header, sealed).unwrap().as_slice(), b"{\"accounts\":[]}");
}

#[test]
fn write_private_atomic_replaces_the_file() {
    let dir = TempDir::new("replace");
    let path = dir.0.join("state.bin");
    write_private_atomic(&path, b"first").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"first");
    write_private_atomic(&path, b"second, longer").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"second, longer");
    write_private_atomic(&path, b"").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"");
    // No temporary files are left behind.
    let names: Vec<_> = fs::read_dir(&dir.0).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, vec![std::ffi::OsString::from("state.bin")]);
}

#[test]
fn write_private_atomic_needs_a_file_name_and_a_folder() {
    let dir = TempDir::new("errors");
    assert!(write_private_atomic(&dir.0.join("missing").join("x"), b"x").is_err());
    assert!(write_private_atomic(Path::new("/"), b"x").is_err());
}

#[cfg(unix)]
#[test]
fn write_private_atomic_makes_files_only_the_owner_can_read() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = TempDir::new("mode");
    let path = dir.0.join("secret.bin");
    // An existing file anyone could read is replaced by a private one.
    OpenOptions::new().write(true).create_new(true).mode(0o644).open(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    write_private_atomic(&path, b"secret").unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

    let fresh = dir.0.join("fresh.bin");
    write_private_atomic(&fresh, b"secret").unwrap();
    assert_eq!(fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn write_private_atomic_replaces_a_link_rather_than_writing_through_it() {
    let dir = TempDir::new("link");
    let target = dir.0.join("elsewhere");
    fs::write(&target, b"untouched").unwrap();
    let path = dir.0.join("vault.bin");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    write_private_atomic(&path, b"new").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"untouched");
    assert!(!fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&path).unwrap(), b"new");
}

#[test]
fn secret_vec_keeps_its_contents_as_it_grows() {
    let mut v = SecretVec::with_capacity(2);
    for i in 0..1000u32 {
        v.extend_from_slice(&i.to_le_bytes());
    }
    assert_eq!(v.len(), 4000);
    assert_eq!(&v[4..8], &1u32.to_le_bytes());
    v.truncate(8);
    assert_eq!(&*v, &[0, 0, 0, 0, 1, 0, 0, 0]);
    v.clear();
    assert!(v.is_empty());
}

#[test]
fn secret_vec_takes_writes_and_hides_its_contents_from_debug() {
    let mut v = SecretVec::from(b"abc".to_vec());
    write!(v, "def{}", 1).unwrap();
    assert_eq!(&*v, b"abcdef1");
    assert_eq!(format!("{v:?}"), "SecretVec(7 bytes)");
    assert_eq!(v.into_zeroizing().as_slice(), b"abcdef1");
}
