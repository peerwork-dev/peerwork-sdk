# Bundled ICU4C for historical protocol ordering

The SDK builds ICU4C 78.3 from the official Unicode source archive at build time and embeds a filtered en-US/root collation data archive in the Rust core. Installed Python wheels, Node addons, and CLI binaries must carry the resulting static code and data; they must not fetch ICU or use the consumer's installed ICU. The only product call site is UTF-16 string comparison for the tracked historical protocol composer. Changing its version, locale, data, or options can change signed protocol digests.

| Asset | SHA-256 | Provenance |
| --- | --- | --- |
| `icu4c-78.3-sources.tgz` | `3a2e7a47604ba702f345878308e6fefeca612ee895cf4a5f222e7955fabfe0c0` | Official Unicode ICU release 78.3 source asset, tag `release-78.3` (`21d1eb0`) |
| `icu4c-78.3-data.zip` | `9d8b3899096aeb83e4e21ef8a40fec9e03b28db18c48452efac882ce25a91e27` | Official Unicode ICU release 78.3 data source asset |
| `data-filter.json` | `6a3e964a0abca23b9677ddcac3bac053b7dbc6b6d563b709c8b985753077998b` | Local, measured additive filter for root/en-US collation and dependencies |
| `icudt78l.dat` | `790a1d07c4a9e4d7de4eab025cc97b54e0097de2ad94408d190ea55c37fcd7e5` | Generated from the above ICU source/data/filter, 2,086,192 bytes |
| `LICENSE` | `e55522d81edc687a341a4411e0776e54ca654e90147f354a90458aaced4116af` | Exact upstream Unicode License V3 text, applying to the bundled ICU assets |

The source tar is extracted with `--no-same-owner` into Cargo's `OUT_DIR`; `runConfigureICU` builds static, privately suffixed libraries (`peerwork`) on the target host. `crates/core/build.rs` checks the pinned source and embedded-data hashes before building. The Rust FFI passes original UTF-16 code units to `ucol_strcoll_78_peerwork`, initializes the aligned embedded data with `udata_setCommonData`, and disables ICU file data access. The filtered `.dat` was generated with ICU's data builder after adding the official data-source zip to `icu/source/data`, configuring with `ICU_DATA_FILTER_FILE=data-filter.json`, and running `make` in its data build directory; this table gives the exact expected output hash.

The direct conformance oracle is pinned to Node 24.20.0 / ICU 78.3 / default en-US and tests punctuation, case, supplementary code points, lone surrogates, canonical equivalence, and ignorable characters. A different Node locale or ICU release may sort differently. Current Linux x64 source-built validation does not establish macOS, Windows, musl, final wheel/addon symbol isolation, or historical inputs written under other host locales; those remain release gates.
