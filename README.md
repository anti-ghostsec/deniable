# deniable

Storage crates shared by Torus, The Sentinel Protocol, FerroOS, Enclave and
the desktop apps. They used to be copied from project to project; now each
project depends on a tagged version here.

| Crate | Folder | What it's for |
|---|---|---|
| `deniable` | `crates/deniable` | Encrypted volumes hidden in a container of random bytes |
| `vaultkit` | `crates/vault` | The pieces of an app's own password-sealed vault file |

Both are `MIT OR Apache-2.0`, Unix-first, and build for Linux, Windows,
macOS and Android.

## Using them

```toml
[dependencies]
deniable = { git = "https://github.com/anti-ghostsec/deniable", tag = "v0.1.0" }
vaultkit = { git = "https://github.com/anti-ghostsec/deniable", tag = "v0.1.0" }
```

To try a change here in a project before tagging it, point the project at
this folder for one command, without editing its `Cargo.toml`:

```sh
cargo --config 'patch."https://github.com/anti-ghostsec/deniable".deniable.path="../deniable/crates/deniable"' test
```

## `deniable`

Moved here unchanged from FerroOS (commit `2132e92`); the copies in Torus,
The Sentinel Protocol and Enclave were identical. The on-disk format is the
same, so existing containers open as before.

**What it guarantees.** Without the right password a container is
indistinguishable from random bytes: nothing says how many volumes it holds,
where they are, or how full they are, and a wrong password looks the same as
one that was never set. Each volume's key comes from Argon2id (or is given
directly), blocks are sealed with XChaCha20-Poly1305 and bound to their
position, saves survive a power cut (two superblocks, written alternately),
and writes never overwrite live data. Volumes can be layered, so giving up a
lower password leaves the ones above invisible. Cover writes make two copies
of a disk taken at different times hard to tell apart from a lower volume's
own use.

**What it doesn't.** Writing with only a lower volume unlocked can destroy
the volumes above it. Cover writes hide changes only as well as they can be
explained by the lower volumes; flash controllers can keep old blocks the
app can't reach. Someone who can write to the disk can roll a block back,
which is only noticed if it breaks the volume. The container's size, and
the fact that it exists, are visible. The Argon2id cost is given by the app,
not read from the container, so it must be the same every time.

The crate's own documentation (`crates/deniable/src/lib.rs`) has the detail.

## `vaultkit`

For apps that already have their own vault file (a magic number, the
Argon2id cost and salt, a nonce, ciphertext) and should keep that format.
It does the parts that are easy to get wrong:

- `Kdf` and `KdfBounds`, and `derive_key(password, salt, kdf, &bounds)`:
  Argon2id into a `Zeroizing<[u8; 32]>`. The cost is checked against a
  minimum **and** a maximum *before* Argon2 allocates anything, so a planted
  file can neither make the key cheap to guess nor make the app allocate
  gigabytes before the seal has been checked. `KdfBounds::DEFAULT` takes
  8 MiB × 1 pass up to 1 GiB × 16 passes × 8 lanes; salts must be at least
  16 bytes.
- `seal(key, header, plain)` / `open(key, header, sealed)`:
  XChaCha20-Poly1305 under a fresh random nonce, with the caller's header
  bytes as associated data, so changing any header byte fails just like a
  wrong password. `sealed` is `nonce | ciphertext | tag`.
  `seal_with_nonce` / `open_with_nonce` are for formats that keep the nonce
  inside the header. What `open` returns is wiped when dropped.
- `write_private_atomic(path, bytes)`: writes a new temporary file next to
  `path`, created with mode 0600 as it's opened (never chmodded afterwards,
  never through an existing file or link), flushes it, renames it over
  `path` and flushes the folder. After a crash the file is either the old
  one or the new one.
- `SecretVec`: a growable buffer that wipes itself when dropped and wipes
  its old memory whenever it grows; `From<Vec<u8>>` takes over a buffer
  another library returned without copying it, and it implements
  `io::Write` for serialisers.

**What it doesn't.** It has no file format: whatever the app leaves out of
the header bytes it passes isn't protected. Wiping covers this crate's
buffers and what it hands back, not copies the app makes, and nothing keeps
secrets out of swap or core dumps. On Windows the private file gets its
folder's permissions and the folder isn't flushed after the rename. Rolling
the whole file back to an older copy isn't detected.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Changes to `deniable` must keep its on-disk format; anything that changes
it needs a new format version and a major version here.
