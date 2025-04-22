import { Box } from "@hazae41/box"
import { Secp256k1SignatureAndRecovery, Secp256k1SigningKey, Secp256k1VerifyingKey, Secp256k1Wasm } from "@hazae41/secp256k1.wasm"
import { BytesOrCopiable } from "libs/copiable/index.js"
import * as Abstract from "./abstract.js"
import { Adapter } from "./adapter.js"

export function fromWasm(wasm: typeof Secp256k1Wasm) {
  const { Memory, Secp256k1SigningKey, Secp256k1VerifyingKey } = wasm

  function getMemory(bytesOrCopiable: BytesOrCopiable) {
    if (bytesOrCopiable instanceof Memory)
      return Box.createAsDropped(bytesOrCopiable)
    if (bytesOrCopiable instanceof Uint8Array)
      return Box.create(new Memory(bytesOrCopiable))
    return Box.create(new Memory(bytesOrCopiable.bytes))
  }

  class SigningKey extends Abstract.SigningKey {

    constructor(
      readonly inner: Secp256k1SigningKey
    ) {
      super()
    }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: Secp256k1SigningKey) {
      return new SigningKey(inner)
    }

    static randomOrThrow() {
      return new SigningKey(Secp256k1SigningKey.random())
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Secp256k1SigningKey.from_bytes(memory.value)

      return new SigningKey(inner)
    }

    getVerifyingKeyOrThrow() {
      return VerifyingKey.create(this.inner.verifying_key())
    }

    signOrThrow(payload: BytesOrCopiable) {
      using memory = getMemory(payload)

      const inner = this.inner.sign_prehash_recoverable(memory.value)

      return new SignatureAndRecovery(inner)
    }

    exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  class VerifyingKey extends Abstract.VerifyingKey {

    constructor(
      readonly inner: Secp256k1VerifyingKey
    ) {
      super()
    }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: Secp256k1VerifyingKey) {
      return new VerifyingKey(inner)
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Secp256k1VerifyingKey.from_sec1_bytes(memory.value)

      return new VerifyingKey(inner)
    }

    static recoverOrThrow(hashed: BytesOrCopiable, signature: SignatureAndRecovery) {
      using memory = getMemory(hashed)

      const inner = Secp256k1VerifyingKey.recover_from_prehash(memory.value, signature.inner)

      return new VerifyingKey(inner)
    }

    exportCompressedOrThrow() {
      return this.inner.to_sec1_compressed_bytes()
    }

    exportUncompressedOrThrow() {
      return this.inner.to_sec1_uncompressed_bytes()
    }

  }

  class SignatureAndRecovery extends Abstract.SignatureAndRecovery {

    constructor(
      readonly inner: Secp256k1SignatureAndRecovery
    ) {
      super()
    }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: Secp256k1SignatureAndRecovery) {
      return new SignatureAndRecovery(inner)
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Secp256k1SignatureAndRecovery.from_bytes(memory.value)

      return new SignatureAndRecovery(inner)
    }

    exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  return { SigningKey, VerifyingKey, SignatureAndRecovery } satisfies Adapter
}