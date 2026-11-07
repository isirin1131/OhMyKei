# Public crypto regression data

- `wycheproof/`: unmodified test vectors from C2SP/Wycheproof. The pinned commit
  and SHA-256 hashes are in `manifest.json`; the upstream Apache-2.0 license is
  retained as `LICENSE`. These files are not relicensed under the repository MIT license.
- `nist/`: unmodified public NIST CAVP AES-256 ECB/CBC and byte-oriented SHA-256
  response files. `manifest.json` records each official archive URL/hash and
  selected member/hash. Running them is informal verification, not CAVP validation.

The vector drivers are offline and require no Python packages. Data is used only
by host tests, never embedded in firmware. See `docs/crypto-testing.md` for the
supported interface scope, exclusion counts, and update procedure.
