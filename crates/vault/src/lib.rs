//! The pieces of a password-sealed vault file, for apps that keep their own
//! file format. Each app decides what its header holds and where; this crate
//! does the parts that are easy to get wrong.
//!
//! * [`derive_key`]: Argon2id from a password, into a key that's wiped when
//!   dropped. The cost usually comes from the file itself, so it's checked
//!   against [`KdfBounds`] (a minimum *and* a maximum) before any memory is
//!   allocated: a planted file can neither weaken the key nor make the app
//!   allocate gigabytes before the seal has been checked.
//! * [`seal`] and [`open`]: XChaCha20-Poly1305 with the caller's header bytes
//!   as associated data, so changing any byte of the header (the salt, the
//!   cost, a version) fails the same way as a wrong password. What [`open`]
//!   returns is wiped when dropped.
//! * [`write_private_atomic`]: replaces a file so a crash leaves either the
//!   old file or the new one, never half of one. The temporary file is
//!   created readable by its owner only (0600 on Unix) from the moment it
//!   exists, not chmodded afterwards.
//! * [`SecretVec`]: a growable buffer for decrypted data that wipes itself
//!   when dropped, and wipes its old memory whenever it has to grow.
//!
//! # What it doesn't do
//!
//! * It has no file format. Nothing stops an app putting the cost or salt
//!   outside the bytes it passes as the header; then they aren't protected.
//! * Wiping covers this crate's buffers and what it hands out. Copies an app
//!   makes (a `String` from the plaintext, a parser's own buffers) are the
//!   app's to wipe. Nothing here keeps secrets out of swap or core dumps.
//! * On Windows the private file gets the folder's permissions (normally
//!   the user's profile, which other users can't read), and the folder
//!   isn't flushed after the rename, which Windows doesn't support.
//! * Nonces are random, 24 bytes: safe for any number of saves under one
//!   key. Rolling the whole file back to an older copy isn't detected.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
pub use zeroize::{Zeroize, Zeroizing};

/// Bytes in a key.
pub const KEY: usize = 32;
/// Bytes in a nonce.
pub const NONCE: usize = 24;
/// Bytes the seal adds after the ciphertext.
pub const TAG: usize = 16;
/// The shortest salt [`derive_key`] accepts.
pub const MIN_SALT: usize = 16;

/// Argon2id cost of turning a password into a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Kdf {
    /// 64 MiB and 3 passes: a phone can afford it. The same cost as
    /// `deniable::Kdf::DEFAULT`.
    pub const DEFAULT: Kdf = Kdf { memory_kib: 64 * 1024, passes: 3, lanes: 1 };
    /// 192 MiB and 3 passes: about a second per guess on a desktop.
    pub const DESKTOP: Kdf = Kdf { memory_kib: 192 * 1024, passes: 3, lanes: 1 };
}

/// The costs [`derive_key`] will accept. Both ends matter when the cost is
/// read from a file: too low and the file's password is cheap to guess, too
/// high and opening the file runs the app out of memory or time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfBounds {
    pub min: Kdf,
    pub max: Kdf,
}

impl KdfBounds {
    /// From 8 MiB and 1 pass up to 1 GiB, 16 passes and 8 lanes. An app whose
    /// files were made with more can give its own bounds.
    pub const DEFAULT: KdfBounds =
        KdfBounds { min: Kdf { memory_kib: 8 * 1024, passes: 1, lanes: 1 }, max: Kdf { memory_kib: 1024 * 1024, passes: 16, lanes: 8 } };

    /// Whether `kdf` is within these bounds, field by field.
    pub fn check(&self, kdf: Kdf) -> Result<()> {
        let within = |v: u32, lo: u32, hi: u32| lo <= v && v <= hi;
        if within(kdf.memory_kib, self.min.memory_kib, self.max.memory_kib)
            && within(kdf.passes, self.min.passes, self.max.passes)
            && within(kdf.lanes, self.min.lanes, self.max.lanes)
        {
            Ok(())
        } else {
            Err(Error::KdfOutOfBounds)
        }
    }
}

impl Default for KdfBounds {
    fn default() -> Self {
        KdfBounds::DEFAULT
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The Argon2id cost is outside the bounds given. Nothing was derived.
    KdfOutOfBounds,
    /// Argon2id refused the cost (fewer than 8 KiB per lane, say).
    Kdf,
    /// The salt is shorter than [`MIN_SALT`].
    ShortSalt,
    /// The seal doesn't check out. Deliberately the same whether the key is
    /// wrong, the header or ciphertext was changed, or the data is cut short.
    Decrypt,
    /// The system's random number source failed.
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "storage error: {e}"),
            Error::KdfOutOfBounds => f.write_str("key derivation cost out of range"),
            Error::Kdf => f.write_str("invalid key derivation cost"),
            Error::ShortSalt => f.write_str("salt too short"),
            Error::Decrypt => f.write_str("wrong password or damaged data"),
            Error::Random => f.write_str("no random numbers available"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            other => io::Error::other(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// A key from `password` with Argon2id. `kdf` is checked against `bounds`
/// first, so a cost read from an untrusted file allocates nothing until it
/// has passed.
pub fn derive_key(password: &[u8], salt: &[u8], kdf: Kdf, bounds: &KdfBounds) -> Result<Zeroizing<[u8; KEY]>> {
    bounds.check(kdf)?;
    if salt.len() < MIN_SALT {
        return Err(Error::ShortSalt);
    }
    let params = Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(KEY)).map_err(|_| Error::Kdf)?;
    let mut key = Zeroizing::new([0u8; KEY]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(password, salt, key.as_mut()).map_err(|_| Error::Kdf)?;
    Ok(key)
}

/// Fills `buf` from the system's random number source, for salts.
pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Random)
}

/// A fresh random nonce.
pub fn random_nonce() -> Result<[u8; NONCE]> {
    let mut nonce = [0u8; NONCE];
    random_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Seals `plain` under a fresh random nonce, with `header` as associated
/// data. Returns `nonce | ciphertext | tag`; the header itself isn't
/// included, so the app writes it wherever its format puts it.
pub fn seal(key: &[u8; KEY], header: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_nonce()?;
    let mut out = Vec::with_capacity(NONCE + plain.len() + TAG);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plain);
    let tag = cipher(key).encrypt_in_place_detached(XNonce::from_slice(&nonce), header, &mut out[NONCE..]).map_err(|_| Error::Decrypt)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens what [`seal`] returned, given the same header.
pub fn open(key: &[u8; KEY], header: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE + TAG {
        return Err(Error::Decrypt);
    }
    let (nonce, rest) = sealed.split_at(NONCE);
    open_with_nonce(key, nonce.try_into().unwrap(), header, rest)
}

/// Seals `plain` under `nonce`, for formats that keep the nonce inside the
/// header (so it's covered by the seal too). Returns `ciphertext | tag`.
/// The nonce must come from [`random_nonce`] and never be used twice with
/// one key: reusing one gives away both plaintexts.
pub fn seal_with_nonce(key: &[u8; KEY], nonce: &[u8; NONCE], header: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(plain.len() + TAG);
    out.extend_from_slice(plain);
    let tag = cipher(key).encrypt_in_place_detached(XNonce::from_slice(nonce), header, &mut out).map_err(|_| Error::Decrypt)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens `ciphertext | tag` sealed by [`seal_with_nonce`].
pub fn open_with_nonce(key: &[u8; KEY], nonce: &[u8; NONCE], header: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < TAG {
        return Err(Error::Decrypt);
    }
    let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG);
    // Decrypted where it will stay, so no plaintext is left in a buffer
    // that isn't wiped.
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    cipher(key).decrypt_in_place_detached(XNonce::from_slice(nonce), header, &mut plain, Tag::from_slice(tag)).map_err(|_| Error::Decrypt)?;
    Ok(plain)
}

fn cipher(key: &[u8; KEY]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

/// Replaces the file at `path` with `bytes`, so that after a crash or power
/// cut it holds either the old contents or the new, whole.
///
/// The bytes go to a new temporary file next to `path`, created readable and
/// writable by its owner only (mode 0600 on Unix, set as it's created) and
/// never through an existing file or link. It's flushed to the disk, renamed
/// over `path`, and then the folder is flushed so the rename itself lasts.
/// The folder must exist.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let (tmp, mut file) = create_private(dir, name)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(dir)
}

/// A new file in `dir` that only its owner can read, under a random name.
fn create_private(dir: &Path, name: &std::ffi::OsStr) -> io::Result<(PathBuf, File)> {
    for _ in 0..16 {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).map_err(io::Error::other)?;
        let mut tmp = OsString::from(".");
        tmp.push(name);
        tmp.push(format!(".{:016x}.tmp", u64::from_le_bytes(r)));
        let tmp = dir.join(tmp);
        let mut opts = OpenOptions::new();
        // create_new: fails rather than open a file or link already there.
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        match opts.open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free temporary file name"))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Bytes that are wiped when dropped. Unlike `Zeroizing<Vec<u8>>`, growing
/// it wipes the memory it moves out of, so no stray copy of the contents is
/// left behind; it can be written to like a file (`io::Write`), for
/// serialisers.
#[derive(Default)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    pub fn new() -> Self {
        SecretVec(Vec::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        SecretVec(Vec::with_capacity(capacity))
    }

    /// Makes room for `extra` more bytes. If the buffer has to move, the old
    /// memory is wiped.
    pub fn reserve(&mut self, extra: usize) {
        if self.0.capacity() - self.0.len() >= extra {
            return;
        }
        let want = self.0.len().checked_add(extra).expect("capacity overflow").max(self.0.capacity().saturating_mul(2));
        let mut grown = Vec::with_capacity(want);
        grown.extend_from_slice(&self.0);
        self.0.zeroize();
        self.0 = grown;
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.reserve(data.len());
        self.0.extend_from_slice(data);
    }

    /// Shortens it to `len` bytes, wiping the rest.
    pub fn truncate(&mut self, len: usize) {
        if len < self.0.len() {
            self.0[len..].zeroize();
            self.0.truncate(len);
        }
    }

    /// Wipes it and leaves it empty.
    pub fn clear(&mut self) {
        self.0.zeroize();
    }

    /// The contents, still wiped when dropped (though no longer when grown).
    pub fn into_zeroizing(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}

/// Takes over a buffer without copying it, so a `Vec` some other library
/// handed back is wiped from then on.
impl From<Vec<u8>> for SecretVec {
    fn from(v: Vec<u8>) -> Self {
        SecretVec(v)
    }
}

impl Deref for SecretVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for SecretVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Write for SecretVec {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVec({} bytes)", self.0.len())
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests;
