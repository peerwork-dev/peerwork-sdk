# DeLM reference adaptation

Based on **Decentralized Multi-Agent Systems with Shared Context**, Yuzhen Mao,
Jerry Gu, Aadi Chauhan, Qizheng Zhang, Hangoo Kang and Azalia Mirhoseini,
[arXiv:2606.10662v3](https://arxiv.org/abs/2606.10662v3).
Original implementation: [yuzhenmao/DeLM](https://github.com/yuzhenmao/DeLM).

This Peerwork adaptation implements two equal asynchronous workers, exclusive
claims with fencing, visible work state, early intermediate findings, peer
review and one independently assembled full candidate per worker. Both import
the shared protocol/runtime rather than duplicate communication code.

The supplied task sums two components into 17. Worker reasoning is scripted by
default; a JSON harness adapter can replace it. Task decomposition is fixed at
two work items; terminal/native-harness integration, dynamic decomposition,
original benchmark tasks and published accuracy/latency/cost comparisons are
outside this example. Peer findings are provided to the harness before work;
the scripted arithmetic fixture does not infer from their prose. Review/adoption
is an explicit Peerwork adaptation, not a claim that the paper mandates it.

Run `node examples/research/delm/run.mjs --offline`, or follow the
[live SDK guide](../README.md). No research implementation code was copied.
Credit and licensing details are in [CREDITS.md](../CREDITS.md).
