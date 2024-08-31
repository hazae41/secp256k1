# Secp256k1

Secp256k1 adapter for WebAssembly and JS implementations

```bash
npm i @hazae41/secp256k1
```

[**Node Package 📦**](https://www.npmjs.com/package/@hazae41/secp256k1)

## Features

### Current features
- 100% TypeScript and ESM
- No external dependencies

## Usage

### WebAssembly

```bash
npm i @hazae41/secp256k1.wasm
```

```typescript
import { Secp256k1 } from "@hazae41/secp256k1"
import { Secp256k1Wasm } from "@hazae41/secp256k1.wasm"

await Secp256k1Wasm.initBundled()

Secp256k1.set(Secp256k1.fromWasm(Secp256k1Wasm))
```

### Noble (JavaScript)

```bash
npm i @noble/curves
```

```typescript
import { Secp256k1 } from "@hazae41/secp256k1"
import * as Secp256k1Noble from "@noble/curves/secp256k1"

Secp256k1.set(Secp256k1.fromNoble(Secp256k1Noble))
```
