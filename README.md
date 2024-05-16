# Bitfold

Bitfold offers Proof-Carrying-Headers for Bitcoin blockchain.

## Proof Carrying Data (PCD)

Proof carrying data, also known as PCD, is a powerful cryptographic primitive that enables the generation of verifiable proofs for data resulting from a sequence of computations starting from an initial state. The main characteristic of PCD is that at each step of the computation, data and its proof can be utilized to construct the proof for the subsequent result. This recursive application of computation steps to proof carrying data allows untrusted parties to generate proofs not only for individual steps but also for the entire computation from its inception.

## PCD for blockchain verification

PCD offers an effective approach to achieve succinct proofs of correctness for recursive computations, particularly in the context of blockchain networks. In blockchain systems, each block applies a state transition function to update the ledger state, leading to the creation of subsequent blocks that reflect the latest state of the network.
Block producers, also known as validators or miners, play a critical role in extending the blockchain by building the new blocks. However, before adding new blocks to the blockchain, they must verify the integrity of previous blocks. This verification involves syncing with the network and validating the entire chain of block headers from the genesis block. This synchronization process can be time-consuming, especially for larger blockchains, requiring hours or even days. This makes bootstrapping full nodes challenging and expensive.
By leveraging PCD for generating Proof-Carrying-Headers (PCH), blockchain nodes can streamline the verification process. Proof-Carrying-Headers enable full nodes and light clients to verify the integrity of the entire blockchain quickly and efficiently. Rather than spending hours or days syncing with the network, nodes can validate succinct SNARK proofs of the proof carrying headers in a matter of seconds.
This approach offers numerous advantages, including accelerated synchronization and the development of trustless zk-light clients, unlocking new possibilities for blockchain scalability and accessibility.

## Bitfold - A Proof Carrying Header for bitcoin:

[Nova-based folding schemes](https://eprint.iacr.org/2021/370.pdf) are an efficient method for generating Proof of Computation Data (PCD). At a high level, Nova-based folding combines two witness-instances into a single witness-instance. The cost of verifying the proof after $n$ steps is essentially the cost of verifying a single computation step plus some additional folding overhead, which is spread over $n$ steps. This efficiency comes from the fact that verifying the final folded proof inherently affirms the correctness of all preceding computation steps up to that point.

In our application, we employ the Nova scheme to streamline the verification of Bitcoin block headers. The [implemented circuit constraints](https://github.com/hamidra/bitcoin-fold/blob/2ff3f3bf5254e5ba517f164bbc014e356d524184/src/lib.rs#L69-L76) for each step of the Nova computation ensure:

1. The hash of the previous header, as included in the current header, matches the actual hash of the previous block header as output from the preceding step.
2. The hash of the current block meets or falls below the specified target difficulty.

This implementation is using a fork of Nova implementation in arkworks by [Nexus team](https://github.com/nexus-xyz/nexus-zkvm).
