import type { Eligos } from "@hazae41/eligos"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { Adapter } from "./secp256k1.js"

export function fromEligos(eligos: typeof Eligos): Adapter {

  class SigningKey {

    constructor(
      readonly inner: Eligos.SigningKey
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Eligos.SigningKey) {
      return new SigningKey(inner)
    }

    static tryRandom() {
      return tryCryptoSync(() => eligos.SigningKey.random()).mapSync(SigningKey.new)
    }

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => eligos.SigningKey.from_bytes(bytes)).mapSync(SigningKey.new)
    }

    tryGetPublicKey() {
      return tryCryptoSync(() => this.inner.verifying_key()).mapSync(VerifyingKey.new)
    }

    trySign(payload: Uint8Array) {
      return tryCryptoSync(() => this.inner.sign_prehash_recoverable(payload)).mapSync(SignatureAndRecovery.new)
    }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
    }

  }

  class VerifyingKey {

    constructor(
      readonly inner: Eligos.VerifyingKey
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Eligos.VerifyingKey) {
      return new VerifyingKey(inner)
    }

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => eligos.VerifyingKey.from_sec1_bytes(bytes)).mapSync(VerifyingKey.new)
    }

    static tryRecover(hashed: Uint8Array, signature: SignatureAndRecovery) {
      return tryCryptoSync(() => eligos.VerifyingKey.recover_from_prehash(hashed, signature.inner)).mapSync(VerifyingKey.new)
    }

    // tryVerify(payload: Uint8Array, signature: Signature) {
    //   return tryCryptoSync(() => this.inner.verify(payload, signature.inner))
    // }

    tryExportCompressed() {
      return tryCryptoSync(() => this.inner.to_sec1_compressed_bytes())
    }

    tryExportUncompressed() {
      return tryCryptoSync(() => this.inner.to_sec1_uncompressed_bytes())
    }

  }

  class SignatureAndRecovery {

    constructor(
      readonly inner: Eligos.SignatureAndRecovery
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Eligos.SignatureAndRecovery) {
      return new SignatureAndRecovery(inner)
    }

    // static tryImport(bytes: Uint8Array) {
    //   return tryCryptoSync(() => eligos.SignatureAndRecovery.from_bytes(bytes)).mapSync(Signature.new)
    // }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
    }

  }

  return { SigningKey, VerifyingKey, SignatureAndRecovery }
}