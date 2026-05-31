import type { secp256k1Wasm } from "@hazae41/secp256k1-wasm";

import { Abstract } from "../abstract/mod.ts";
import type { Adapter } from "../adapter/mod.ts";

export function fromWasm(wasm: typeof secp256k1Wasm): Adapter {

  class Memory extends Abstract.Memory {

    constructor(
      readonly inner: secp256k1Wasm.Memory
    ) {
      super()
    }

    [Symbol.dispose]() {
      this.inner[Symbol.dispose]()
    }

    static fromOrThrow(memory: Abstract.MemoryLike): Memory {
      if (memory instanceof Memory)
        return memory

      if (memory instanceof Uint8Array)
        return new Memory(new wasm.Memory(memory))

      if (memory.inner instanceof wasm.Memory)
        return new Memory(memory.inner)

      return new Memory(new wasm.Memory(memory.bytes))
    }

    get bytes() {
      return this.inner.bytes
    }

  }

  class Secp256k1SigningKey extends Abstract.Secp256k1SigningKey {

    constructor(
      readonly inner: secp256k1Wasm.Secp256k1SigningKey
    ) {
      super()
    }

    [Symbol.dispose]() {
      this.inner[Symbol.dispose]()
    }

    static randomOrThrow() {
      return new Secp256k1SigningKey(new wasm.Secp256k1SigningKey())
    }

    static importOrThrow(key: Memory) {
      if (key instanceof Memory === false)
        throw new Error()
      return new Secp256k1SigningKey(wasm.Secp256k1SigningKey.from_bytes(key.inner))
    }

    publishOrThrow() {
      return new Secp256k1VerifyingKey(this.inner.publish())
    }

    signOrThrow(payload: Memory) {
      if (payload instanceof Memory === false)
        throw new Error()
      return new Secp256k1SignatureAndRecovery(this.inner.sign_prehash_recoverable(payload.inner))
    }

    exportOrThrow() {
      return new Memory(this.inner.to_bytes())
    }

  }

  class Secp256k1VerifyingKey extends Abstract.Secp256k1VerifyingKey {

    constructor(
      readonly inner: secp256k1Wasm.Secp256k1VerifyingKey
    ) {
      super()
    }

    [Symbol.dispose]() {
      this.inner[Symbol.dispose]()
    }

    static importOrThrow(key: Memory) {
      if (key instanceof Memory === false)
        throw new Error()
      return new Secp256k1VerifyingKey(wasm.Secp256k1VerifyingKey.from_sec1_bytes(key.inner))
    }

    static recoverOrThrow(hashed: Memory, signature: Secp256k1SignatureAndRecovery) {
      if (hashed instanceof Memory === false)
        throw new Error()
      if (signature instanceof Secp256k1SignatureAndRecovery === false)
        throw new Error()
      return new Secp256k1VerifyingKey(wasm.Secp256k1VerifyingKey.recover_from_prehash(hashed.inner, signature.inner))
    }

    exportAsCompressedOrThrow() {
      return new Memory(this.inner.to_sec1_compressed_bytes())
    }

    exportAsUncompressedOrThrow() {
      return new Memory(this.inner.to_sec1_uncompressed_bytes())
    }

  }

  class Secp256k1SignatureAndRecovery extends Abstract.Secp256k1SignatureAndRecovery {

    constructor(
      readonly inner: secp256k1Wasm.Secp256k1SignatureAndRecovery
    ) {
      super()
    }

    [Symbol.dispose]() {
      this.inner[Symbol.dispose]()
    }

    static importOrThrow(key: Memory) {
      if (key instanceof Memory === false)
        throw new Error()
      return new Secp256k1SignatureAndRecovery(wasm.Secp256k1SignatureAndRecovery.from_rsv_bytes(key.inner))
    }

    exportOrThrow() {
      return new Memory(this.inner.to_rsv_bytes())
    }

  }

  return { Memory, Secp256k1SigningKey, Secp256k1VerifyingKey, Secp256k1SignatureAndRecovery }
}