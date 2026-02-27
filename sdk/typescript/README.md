### @ika.xyz/sdk — TypeScript SDK for Ika Network

⚠️ **Warning**: This package is currently in development and may have breaking changes.

## Overview

This package provides a TypeScript SDK for interacting with the Ika Network on Sui.

- New instance called IkaGrpcClient and IkaGrpcTransaction
- Query commands are all same as the original repo


### Install

Use bun (preferred):

```bash
git clone https://github.com/makimakiver/ika_makimakiver_edition.git
```

### Build (in this repo)

From the repo root:

```bash
pnpm install
cd sdk/typescript && pnpm build
```

### Creating a grpc client

`IkaGrpcClient` wraps a `SuiGrpcClient` and also provide the network config by calling getNetworkConfig() function

```ts
import { getNetworkConfig, IkaClient } from '@ika.xyz/sdk';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';

const client = new SuiGrpcClient({
  network: "testnet",
  baseUrl: "https://fullnode.testnet.sui.io:443",
});
const ikaClient = new IkaGrpcClient({
  suiClient: client,
  config: getNetworkConfig("testnet"), // mainnet / testnet
});

await ikaClient.initialize();
```

### Cryptography helpers

Exposed utilities under `client/cryptography`:

- `grpcPrepareDKGSecondRound(pp, dWallet, sessionId, encKey)` 
- `grpcPrepareDKGSecondRoundAsync(ikaClient, ...)`
- `grpcPrepareImportedKeyDWalletVerification(ikaClient, sessionId, userKeys, keypair)`

### Testing

The SDK has unit and integration tests under `test` that expect an Ika localnet to be running for
any tests that talk to the chain.

Start a localnet following the
[Setup Ika Localnet docs](https://docs.ika.xyz/docs/sdk/setup-localnet), which is equivalent to:

```bash
# Terminal 1 – Sui localnet
RUST_LOG="off,sui_node=info" sui start --with-faucet --force-regenesis --epoch-duration-ms 1000000000000000

# Terminal 2 – Ika localnet
cargo run --bin ika --release --no-default-features -- start
```

Then run the SDK tests, for example from the repo root:

```bash
pnpm --filter @ika.xyz/sdk test:unit
pnpm --filter @ika.xyz/sdk test:integration
```

End-to-end system tests live under `test/system-tests` and have their own setup and instructions in
`test/system-tests/README.md`; they are **not** run by the command above.

