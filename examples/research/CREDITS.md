# Research credit and implementation provenance

These independently implemented Peerwork examples adapt mechanisms described
in the following papers. They are not releases endorsed by the original authors.
No source, prompts, datasets or benchmark implementation were copied from the
research repositories, so there is no reused research-code revision. Upstream
links identify the original implementations; paper versions pin the research
being credited.

1. **Agensh: Scaling Organizational Intelligence to 1,024 Agents**.
   Zhihao Zhan, Ting Song, Li Dong, Shaohan Huang, Jianxun Lian, Yan Xia, Furu Wei.
   arXiv:2609.26781v1 (2026).
   [Paper](https://arxiv.org/abs/2609.26781v1),
   [original code](https://github.com/microsoft/Agensh).
   Mechanisms adapted: symmetric asynchronous workers, claims, shared context,
   verification and integration. See [coverage/differences](agensh/README.md).
2. **Decentralized Multi-Agent Systems with Shared Context**.
   Yuzhen Mao, Jerry Gu, Aadi Chauhan, Qizheng Zhang, Hangoo Kang, Azalia Mirhoseini.
   arXiv:2606.10662v3 (2026).
   [Paper](https://arxiv.org/abs/2606.10662v3),
   [original code](https://github.com/yuzhenmao/DeLM).
   Mechanisms adapted: asynchronous exclusive work claims, early intermediate
   sharing and per-peer submissions. See [coverage/differences](delm/README.md).

New Peerwork source is Apache-2.0, under this repository's [license](../../LICENSE).
The vendored offline evaluator is generated from the Peerwork Backend, with
exact source commit/file hashes and bundle checksum in
[vendor/backend-evaluator.source.json](vendor/backend-evaluator.source.json).
It includes [Peerwork Apache-2.0](vendor/LICENSE-Peerwork),
[Zod MIT](vendor/LICENSE-Zod) and
[@noble/hashes MIT](vendor/LICENSE-Noble-Hashes) and
[hpke MIT](vendor/LICENSE-HPKE) notices. Preserve them when
redistributing the standalone bundle.

The default synthetic protocol fixtures measure state transitions and recovery,
not published model-quality improvements, token cost or scaling behavior.
