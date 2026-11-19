# deniable

Storage crates meant to be shared between projects, so that fixes land in
one place.

**Who uses them today.** Only Enclave, and it doesn't depend on this
repository: it keeps a vendored copy of `deniable` in `native/deniable`
(this repository is private, and Enclave's public CI can't fetch it). That
copy is kept byte-identical to a tag here and carries the same version
number, so `diff -r crates/deniable ../Enclave/native/deniable` shows any
drift. Torus, The Sentinel Protocol and FerroOS don't use either crate;
the copies of `deniable` they once had are gone. Nothing uses `vaultkit`
yet.

| Crate | Folder | What it's for |
|---|---|---|
| `deniable` | `crates/deniable` | Encrypted volumes hidden in a container of random bytes |
| `vaultkit` | `crates/vault` | The pieces of an app's own password-sealed vault file |

Both are `MIT OR Apache-2.0`, Unix-first, and build for Linux, Windows,
macOS and Android.

## Using them

```toml
[dependencies]
deniable = { git = "https://github.com/anti-ghostsec/deniable", tag = "v0.3.0" }
vaultkit = { git = "https://github.com/anti-ghostsec/deniable", tag = "v0.3.0" }
```

To try a change here in a project before tagging it, point the project at
this folder for one command, without editing its `Cargo.toml`:

```sh
cargo --config 'patch."https://github.com/anti-ghostsec/deniable".deniable.path="../deniable/crates/deniable"' test
```

## Versions

- **v0.3.0** (`deniable`): two fixes.
  - **A failed unlock could destroy the whole container.** When a volume
    had lost one of its two superblocks and the container had no free
    place for a new one, unlocking it failed with `Full` but left a
    half-unlocked volume behind. The next save wrote that volume's
    superblock to block 0, over the container's salt, after which no
    password opened anything. A failed unlock now forgets everything it
    unlocked and gives back the blocks it claimed, and a save refuses to
    write a superblock to block 0.
  - **Cover writes leaked hidden-volume activity.** Their number was
    proportional to all the blocks a save wrote, hidden volumes' included,
    so someone with only a lower password could compare two copies of the
    disk and watch the unexplained changes grow with hidden writes. Now
    each save pads the number of blocks it changed to a target drawn at
    random between the cover budget and twice it, without regard to what
    was written. A save smaller than the budget looks the same whether or
    not a hidden volume wrote; a larger one shows its size.
    `set_cover(per_write, min)` is now `set_cover(budget)`, with a default
    of `DEFAULT_COVER` (256 blocks, 1 MiB per save).

  The on-disk format is unchanged: containers move between v0.2.0 and
  v0.3.0 freely.
- **v0.2.0** (`deniable`): a volume's two superblocks are told apart by a
  marker that cycles through three values instead of a count of saves, which
  told someone with a decoy password how often anything was saved. Containers
  from v0.1.0 open as they are and switch at their next save; once saved by
  v0.2.0 they can't be read by v0.1.0, so every project that shares
  containers moves together. A write, resize or save that fails part-way
  leaves a volume that opens (the old contents or the new). Costs outside
  8 MiB to 1 GiB, 1 to 16 passes and 1 to 4 lanes are refused before the
  device is touched, and container files are created private (0600).
- **v0.1.0**: the first tagged version.

## `deniable`

Moved here unchanged from FerroOS (commit `2132e92`). The on-disk format is
the same, so existing containers open as before.

**What it guarantees.** Without the right password a container is
indistinguishable from random bytes: nothing says how many volumes it holds,
where they are, or how full they are, and a wrong password looks the same as
one that was never set. Each volume's key comes from Argon2id (or is given
directly), blocks are sealed with XChaCha20-Poly1305 and bound to their
position, saves survive a power cut (two superblocks, written alternately),
and writes never overwrite live data. Volumes can be layered, so giving up a
lower password leaves the ones above invisible. Each save pads the blocks it
changed to a random target between the cover budget and twice it, so two
copies of a disk taken around a save show the same number of changes whether
or not a hidden volume wrote, as long as the save was smaller than the
budget.

**What it doesn't.** Writing with only a lower volume unlocked can destroy
the volumes above it. A save larger than the cover budget shows its real
size, and if the lower volumes didn't write that much, someone with their
password learns that something else did: keep hidden-volume saves smaller
than the budget, or raise it. Cover writes show that the container is in use. Flash controllers
can keep old blocks the app can't reach. Someone who can write to the disk can roll a block back,
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
