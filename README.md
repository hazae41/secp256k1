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

## Usage 

```tsx
const key = secp256k1.SecretKey.random()

const msg = crypto.getRandomValues(new Uint8Array(32))
const sig = key.sign(msg)

const pub = secp256k1.PublicKey.recover(msg, sig)
```