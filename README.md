# BlokyzMint PoC

This is a small Foundry project for checking how `BlokyzMint` settles its raffle.

The point of the PoC is simple: once the VRF seed has arrived, the owner can post the Merkle root that decides who wins. The contract checks that a claimant belongs to that root, but it does not check that the root was calculated from the raffle entries, the VRF seed, or the allocator hash.

That means the code gives the owner the final say over the allocation. This PoC does not say that the owner has used that power unfairly; it shows that the contract permits it.

## Running it

Install Foundry, open this directory, and run:

```bash
forge test -vvv
```

To run the main example only:

```bash
forge test --match-test testOwnerCanChooseOnePayingEntrantAsTheOnlyWinner -vvvv
```

In that test, two wallets enter and pay the same amount. After the VRF result is set, the owner posts a root containing only one of them. That wallet claims an NFT, the other wallet gets `InvalidProof`, and the owner withdraws both entry payments.

There is another test showing an even simpler case: the owner can put a wallet with no raffle entries in the allocation root and give it the full raffle supply.

## Files

- `src/BlokyzMint.sol` is the contract under review.
- `test/BlokyzMintAudit.t.sol` contains the local PoCs.
- `foundry.toml` pins the compiler and build settings used by the contract.

## Live contract

The local source was compiled with Solidity `0.8.24` and compared read-only with the runtime code at:

`0x86fFb7988913E85A5A07d459a5165Ab1273CFE62`

The executable code matched after accounting for the constructor's immutable values and compiler metadata. No transaction was sent to the live contract while preparing this PoC.

## What would make this fair

If the team uses an off-chain allocator, they should publish the exact source code, dependencies, build instructions, and the exact data hashed by `allocatorHash` before asking for the VRF seed. After the draw, anyone should be able to replay that code using the public entry data and VRF seed, then compare the resulting Merkle root with the root posted on-chain.

That makes the draw publicly auditable. It does not make the current contract enforce fairness: the owner can still post a different root, and the contract will accept it. To remove that trust, the contract itself must either select winners from on-chain ticket data or verify a cryptographic proof that the off-chain root came from the complete entries, the VRF seed, and fixed allocation rules.
