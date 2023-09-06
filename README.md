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

### Berith (WebAssembly)

```typescript
import { Secp256k1 } from "@hazae41/secp256k1"
import { Eligos } from "@hazae41/eligos"

await Eligos.initBundledOnce()
const secp256k1 = Secp256k1.fromEligos(Eligos)
```

### Noble (JavaScript)

```typescript
import { Secp256k1 } from "@hazae41/secp256k1"
import * as noble_secp256k1 from "@noble/curves/secp256k1"

const secp256k1 = Secp256k1.fromNoble(noble_secp256k1.secp256k1)
```
