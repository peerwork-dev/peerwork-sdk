# Installed native PRIVATE Owner admission and readback

The scripted installed smoke passed in session `72524` (exit 0) on 2026-10-13. This is business/API evidence, not an Agent workflow-compliance test. No independent Agent was run, so instruction following remains unverified.

The immutable SDK source was `5e8c6c2a36cbbfa53e0dea4f2ecc4ff718d1dbeb` (`git archive` SHA-256 `e1680c0a4270153001249ff978df2c771513c6ab3075f69514de000f0cecb486`). The committed test was `0e2492c6f6b9e3b49a00265586f8979b53a8b208`, file SHA-256 `1cabdc0c236b7cd8bd0673c3684fcab1ba56b9b03cf0768610fd500c62c415da`. The test's externally supplied Owner source SHA-256 guard matched `5c40aa4a85aa38eb06955e956176ab123a39e44b9bc107e8abc334aa8d4b5b5a`; it did not derive an expected value from the extracted source. The test ran against the archive's `tests/reference-kernel-server.mjs`, with tracked reference root `/root/workdir/message/.worktrees/e2ee-main-integration-20261006` at `f828b6c50a0a58d1e718af90f653b214adcc3328`. The archive includes committed PRIVATE install staging source at `7c1337c`, but this test did not exercise PRIVATE install; it excludes uncommitted runtime installer work.

The Rust 1.89 offline locked CLI/Node release build `15636`, wheel build `49588`, and platform npm pack `91476` each exited 0. Artifact SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| CLI `peerwork` | `a6931ee0142bad521f506697088b3d593b5bcc363dbea4c75495fc3cec10b748` |
| Node native `.so` / installed `index.node` | `b0ad9a61f2e44e56edf19e8a546521b1e5a86ab9ac8b95188a34288796f5e8f9` |
| Python `manylinux_2_38_x86_64` wheel | `e1499786e6403d62e38105f166209048e2df22ac783f56b6d024ff805fe40dd3` |
| Node facade tarball | `a3a7e1a6536017f9c16c3cd836dce6dd6400b66ab1dbf5d49a11c7c43c169bcd` |
| Node platform tarball | `fa1cb595a84cc7fc326c034c32a4b96aed8cc183cf923ff9eb7f1fb9e14489cc` |
| Installed wheel `RECORD` | `2f14d30d185447dd0b3defe52634ef59f2d09a94ae1f98187141860bc59c2f93` |

The wheel and both npm tarballs were installed offline into fresh task-local venv/node directories before the service test. The first npm install invocation failed exit 127 because npm's `env node` shebang lacked the pinned Node binary on `PATH`; repeating the same offline install with `/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin` prepended passed. A diagnostic `import peerwork_sdk` failed because the distribution name is `peerwork-sdk` while its import module is `peerwork`; the installed `import peerwork` passed. These were invocation errors, not SDK business failures. The test used the correct pinned Node absolute path throughout.

The test created a PRIVATE workspace through the installed Python Owner client, created and published a distinct native recipient, and used an owner-side verified directory lookup certificate for a Node PRIVATE offer. Python native invitation consent accepted that offer. The service applied delivery while dropping the response; Python returned `PENDING`, a fresh Node client found the exact protected pending grant ID/hash, and CLI exact retry returned `AUTHORIZED` without another commit. Recipient receive returned `READY`. The Owner submitted encrypted `wiki.create`; Node reconciled one signed record effect, and the recipient's verified PRIVATE read returned the exact record ID, title `Native private member readback`, and body `Encrypted after grant`. CLI same-ID action retry did not advance the journal. The final signed sequence was 3; owner and recipient actor IDs differed. The local service process was terminated by the test finalizer.

This proves the installed three-language PRIVATE Owner admission/action/read path at this source and Linux glibc floor. It does not prove natural Agent compliance, PRIVATE package install, broad input parity, macOS/Windows execution, or lower glibc compatibility.
