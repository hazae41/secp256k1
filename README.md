# Secp256k1

Secp256k1 adapter for WebAssembly and JS implementations

```bash
npm install --save-peer @hazae41/secp256k1
```

[**Node Package 📦**](https://www.npmjs.com/package/@hazae41/secp256k1)

## Features

### Current features
- 100% TypeScript and ESM
- No external dependencies

## Implementation

### WebAssembly

```bash
npm install @hazae41/secp256k1-wasm
```

```typescript
import { secp256k1 } from "@hazae41/secp256k1"
import { secp256k1Wasm } from "@hazae41/secp256k1-wasm"

await Secp256k1Wasm.load()

secp256k1.set(secp256k1.fromWasm(secp256k1Wasm))
```
