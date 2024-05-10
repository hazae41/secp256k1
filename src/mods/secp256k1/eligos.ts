import { Box, BytesOrCopiable } from "@hazae41/box"
import { Eligos } from "@hazae41/eligos"
import { Adapter, Generic } from "./adapter.js"

export async function fromEligos(): Promise<Adapter> {
  await Eligos.initBundledOnce()

  function getMemory(bytesOrCopiable: BytesOrCopiable) {
    if (bytesOrCopiable instanceof Eligos.Memory)
      return Box.greedy(bytesOrCopiable)
    if (bytesOrCopiable instanceof Uint8Array)
      return Box.new(new Eligos.Memory(bytesOrCopiable))
    return Box.new(new Eligos.Memory(bytesOrCopiable.bytes))
  }

  class PrivateKey extends Generic.PrivateKey {

    constructor(
      readonly inner: Eligos.SigningKey
    ) {
      super()
    }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static create(inner: Eligos.SigningKey) {
      return new PrivateKey(inner)
    }

    static randomOrThrow() {
      return new PrivateKey(Eligos.SigningKey.random())
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Eligos.SigningKey.from_bytes(memory.inner)

      return new PrivateKey(inner)
    }

    getPublicKeyOrThrow() {
      return PublicKey.create(this.inner.verifying_key())
    }

    signOrThrow(payload: BytesOrCopiable) {
      using memory = getMemory(payload)

      const inner = this.inner.sign_prehash_recoverable(memory.inner)

      return new SignatureAndRecovery(inner)
    }

    exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  class PublicKey extends Generic.PublicKey {

    constructor(
      readonly inner: Eligos.VerifyingKey
    ) {
      super()
    }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static create(inner: Eligos.VerifyingKey) {
      return new PublicKey(inner)
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Eligos.VerifyingKey.from_sec1_bytes(memory.inner)

      return new PublicKey(inner)
    }

    static recoverOrThrow(hashed: BytesOrCopiable, signature: SignatureAndRecovery) {
      using memory = getMemory(hashed)

      const inner = Eligos.VerifyingKey.recover_from_prehash(memory.inner, signature.inner)

      return new PublicKey(inner)
    }

    exportCompressedOrThrow() {
      return this.inner.to_sec1_compressed_bytes()
    }

    exportUncompressedOrThrow() {
      return this.inner.to_sec1_uncompressed_bytes()
    }

  }

  class SignatureAndRecovery extends Generic.SignatureAndRecovery {

    constructor(
      readonly inner: Eligos.SignatureAndRecovery
    ) {
      super()
    }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static create(inner: Eligos.SignatureAndRecovery) {
      return new SignatureAndRecovery(inner)
    }

    exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  return { PrivateKey, PublicKey, SignatureAndRecovery }
}