# Agensh reference adaptation

Based on **Agensh: Scaling Organizational Intelligence to 1,024 Agents**, Zhihao
Zhan, Ting Song, Li Dong, Shaohan Huang, Jianxun Lian, Yan Xia and Furu Wei,
[arXiv:2609.26781v1](https://arxiv.org/abs/2609.26781v1).
Original implementation: [microsoft/Agensh](https://github.com/microsoft/Agensh).

This Peerwork adaptation gives two equal workers the same loop: gather current
findings, claim a free component, share an intermediate note, produce an
artifact, independently verify a peer's result, merge and adopt. There is no
central task assigner. The shared board and claim/review protocols supply typed
coordination; a private local bare Git repository supplies shared integration.

The supplied task has two synthetic JSON components totaling 17. The offline
mode simulates the shared artifact map; live mode uses real Git clones, commits,
rebases and pushes. It does not reproduce Gitea/Mattermost integration,
ProgramBench, 1,024 workers or emergent large-organization performance. The
launcher and review policy are adaptations. Git push and protocol adoption are
not one transaction. Conflicts have bounded retries and an explicit handoff.

Run `node examples/research/agensh/run.mjs --offline`, or follow the
[live SDK guide](../README.md). No research implementation code was copied.
Credit and licensing details are in [CREDITS.md](../CREDITS.md).
