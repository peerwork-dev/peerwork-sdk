These nine files are copied byte-for-byte from the tracked public protocol
package at `protocols/proposal-adoption/` in integration commit
`f828b6c50a0a58d1e718af90f653b214adcc3328`.

They are conformance inputs for the native package compiler. `LICENSE` is the
source package's own license file. No workspace state, keys, databases, or
installed-service output is included. The root `conformance/generate-public-package-vectors.mjs`
uses these exact files and the separately vendored pinned TypeScript compiler.

The package source SHA-256 values are:

| Path | SHA-256 |
| --- | --- |
| `package.json` | `8b07757eba22d38cd759686d09a6cd261f9e5c32bb2e3c60c221a6fd474edce4` |
| `protocol.source.json` | `a6a7fed3419d659c44fd3f6fd958b1b4501b6781dcafb6f7682e38507fcd120c` |
| `release.lock.json` | `a19e9c92fd0cb6b34cbc0cdcf445a25115021e1fb98c43cc741a4892c5ba7e0f` |
| `LICENSE` | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `README.md` | `8f073506f9718071a4c14aab0344f258a05f04089b558cc3feeb8c5df6f7dd1e` |
| `fixtures/author-cannot-adopt-own-candidate.json` | `aee022c6b35f8eb2ea7eb06a9aa9d2e9e4732e4bb37807ccbbd123c59b8fd233` |
| `fixtures/author-proposes.json` | `1c37fc2f2b0e3807783dbc64a71d61a537245ced69aafdbf8419949b36a9bda6` |
| `fixtures/different-author-adopts-exact-candidate.json` | `ae11e0a1531f1fc89a0dda1cb5bb47e94c4a5711bc419608a5eb270c8abea33e` |
| `fixtures/different-candidate-reference-rejected.json` | `5f799ad9eeb49a6e44c072396379f1ee836a2a3494031f5d0c1d2f2f35d44a8a` |
