# gRPC Client — Changes and New Files

This document describes the changes made to add `SuiGrpcClient` support alongside the existing `SuiClient` (JSON-RPC) implementation.

---

## Modified: `types.ts`

**Added `IkaGrpcClientOptions` interface** (lines 81–93).

`IkaClientOptions` already existed for the JSON-RPC client (`SuiClient`). The new interface is identical in shape but uses `SuiGrpcClient` from `@mysten/sui/grpc` as the client type:

```typescript
export interface IkaGrpcClientOptions {
    config: IkaConfig;
    suiClient: SuiGrpcClient;        // ← SuiGrpcClient instead of SuiClient
    timeout?: number;
    protocolPublicParameters?: { ... };
    cache?: boolean;
    encryptionKeyOptions?: EncryptionKeyOptions;
}
```

This interface is consumed by `IkaGrpcClient`'s constructor.

---

## Modified: `index.ts`

**Added two new exports:**

```typescript
export * from './ika-grpc-client.js';
export * from './grpc-utils.js';
```

This makes `IkaGrpcClient`, `grpcObjToBcs`, `grpcFetchAllDynamicFields`, and `GrpcDynamicFieldInfo` available to consumers of the `@ika.xyz/sdk` package without requiring direct internal imports.

> **Note on naming:** `grpc-utils.ts` exports functions named `grpcObjToBcs` and `grpcFetchAllDynamicFields` (with `grpc` prefix) to avoid name conflicts with the identically-named functions in `utils.ts` (`objResToBcs`, `fetchAllDynamicFields`), which use a different `SuiClient`-based signature and are also re-exported from `index.ts`.

---

## Created: `grpc-utils.ts`

A gRPC-specific counterpart to `utils.ts`. Contains two helpers used throughout `ika-grpc-client.ts`.

### `GrpcDynamicFieldInfo`

Type for dynamic field entries returned by `client.core.getDynamicFields`. The shape differs from the JSON-RPC `DynamicFieldInfo` — notably `name.bcs` is a raw `Uint8Array` instead of a pre-decoded string value.

```typescript
export type GrpcDynamicFieldInfo = {
    id: string;
    name: { type: string; bcs: Uint8Array | undefined };
    type: string;
};
```

### `grpcObjToBcs(obj)`

Extracts BCS bytes from a gRPC `getObject` / `batchGetObjects` response and returns them as a base64 string suitable for BCS deserializers (e.g. `SomeModule.Type.fromBase64(...)`).

Replaces the JSON-RPC `objResToBcs(resp: SuiObjectResponse)` which reads from `resp.data.bcs.bcsBytes`. The gRPC response has a different shape:

```typescript
// JSON-RPC shape (utils.ts)
resp.data?.bcs?.bcsBytes

// gRPC shape (grpc-utils.ts)
obj.response.object?.bcs?.value  // Uint8Array, converted via toBase64()
```

Throws `InvalidObjectError` if BCS data is absent.

### `grpcFetchAllDynamicFields(client, parentId)`

Paginates through all dynamic fields for a parent object using `client.core.getDynamicFields`. Handles the cursor loop automatically, stopping when `hasNextPage` is false or the cursor stops advancing.

Replaces the JSON-RPC `fetchAllDynamicFields(suiClient, parentId)` which used `suiClient.getDynamicFields`.

---

## Created: `ika-grpc-client.ts`

A new client class `IkaGrpcClient` that mirrors `IkaClient` but uses `SuiGrpcClient` for all on-chain reads instead of `SuiClient` JSON-RPC. It exposes an identical public API so it can be used as a drop-in alternative.

### Constructor

```typescript
new IkaGrpcClient({ suiClient, config, cache, encryptionKeyOptions }: IkaGrpcClientOptions)
```

Accepts a `SuiGrpcClient` instance (from `@mysten/sui/grpc`) via `IkaGrpcClientOptions`.

### Public methods (same API as `IkaClient`)

| Method | Description |
|---|---|
| `getDWallet(id)` | Fetch and decode a single DWallet object |
| `getPresign(id)` | Fetch a PresignSession object |
| `getEncryptedUserSecretKeyShare(id)` | Fetch an EncryptedUserSecretKeyShare object |
| `getPartialUserSignature(id)` | Fetch a PartialUserSignature object |
| `getSign(id)` | Fetch a SignSession object |
| `getMultipleDWallets(ids)` | Batch fetch multiple DWallet objects |
| `getOwnedDWalletCaps(address, limit, cursor)` | List DWalletCap objects owned by an address |
| `getActiveEncryptionKey(address)` | Simulate a tx to resolve the active encryption key |
| `getObjects()` | Fetch coordinator and system inner objects (with caching) |
| `getEncryptionKeys()` | Fetch all network encryption keys (with caching) |
| `getProtocolPublicParameters(...)` | Fetch or cache protocol public parameters for a curve |
| `invalidateCache()` | Clear all caches |
| `invalidateObjectCache()` | Clear only the coordinator/system inner cache |
| `invalidateEncryptionKeyCache()` | Clear only the encryption key cache |
| `invalidateProtocolPublicParametersCache(...)` | Clear protocol parameter cache, optionally scoped |

### Key gRPC API differences vs JSON-RPC

| Operation | JSON-RPC (`IkaClient`) | gRPC (`IkaGrpcClient`) |
|---|---|---|
| Fetch single object | `suiClient.getObject(...)` | `client.ledgerService.getObject({ objectId, readMask: { paths: ['bcs'] } })` |
| Batch fetch objects | `suiClient.multiGetObjects(ids)` | `client.ledgerService.batchGetObjects({ requests: ids.map(id => ({ objectId: id })), readMask: { paths: ['bcs'] } })` |
| List owned objects | `suiClient.getOwnedObjects(...)` | `client.stateService.listOwnedObjects({ owner, objectType, pageToken, pageSize, readMask })` |
| Fetch dynamic fields | `suiClient.getDynamicFields({ parentId })` | `client.core.getDynamicFields({ parentId, cursor })` |
| Simulate transaction | `suiClient.devInspectTransactionBlock(...)` | `client.transactionExecutionService.simulateTransaction({ transaction: { bcs: { value: txBytes } } })` |
| BCS extraction | `resp.data.bcs.bcsBytes` (string) | `obj.response.object?.bcs?.value` (Uint8Array → `toBase64()`) |
| Pagination cursor | String cursor passed directly | `listOwnedObjects`: cursor is `Uint8Array` (`fromBase64`/`toBase64` for encode/decode) |
| Shared object version | `owner.Shared.initial_shared_version` | `owner?.version` (bigint, cast to `Number(...)`) |
| Simulate result | `results[0].returnValues[0][0]` | `res.response.commandOutputs[0].returnValues[0].value?.value` |

### Transaction simulation for `getActiveEncryptionKey`

Because gRPC's `simulateTransaction` has no `sender` field, the sender must be embedded in the transaction bytes:

```typescript
tx.setSender(address);
const txBytes = await tx.build({ client: this.client.core });
const res = await this.client.transactionExecutionService.simulateTransaction({
    transaction: { bcs: { value: txBytes } },
});
```
