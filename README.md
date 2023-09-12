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

### Eligos (WebAssembly)

```bash
npm i @hazae41/eligos
```

```typescript
import { Secp256k1 } from "@hazae41/secp256k1"

Secp256k1.set(await Secp256k1.fromEligos())
```

### Noble (JavaScript)

```bash
npm i @noble/curves
```

```typescript
import { Secp256k1 } from "@hazae41/secp256k1"

Secp256k1.set(Secp256k1.fromNoble())
```
