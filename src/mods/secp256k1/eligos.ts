import { Eligos } from "@hazae41/eligos"
import { Result } from "@hazae41/result"
import { Adapter } from "./adapter.js"
import { ConvertError, ExportError, GenerateError, ImportError, RecoverError, SignError } from "./errors.js"

export async function fromEligos(): Promise<Adapter> {
  await Eligos.initBundledOnce()

  class PrivateKey {

    constructor(
      readonly inner: Eligos.SigningKey
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Eligos.SigningKey) {
      return new PrivateKey(inner)
    }

    static tryRandom() {
      return Result.runAndWrapSync(() => {
        return Eligos.SigningKey.random()
      }).mapErrSync(GenerateError.from).mapSync(PrivateKey.new)
    }

    static tryImport(bytes: Uint8Array) {
      return Result.runAndWrapSync(() => {
        return Eligos.SigningKey.from_bytes(bytes)
      }).mapErrSync(ImportError.from).mapSync(PrivateKey.new)
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return this.inner.verifying_key()
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    trySign(payload: Uint8Array) {
      return Result.runAndWrapSync(() => {
        return this.inner.sign_prehash_recoverable(payload)
      }).mapErrSync(SignError.from).mapSync(SignatureAndRecovery.new)
    }

    tryExport() {
      return Result.runAndWrapSync(() => {
        return this.inner.to_bytes()
      }).mapErrSync(ExportError.from)
    }

  }

  class PublicKey {

    constructor(
      readonly inner: Eligos.VerifyingKey
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Eligos.VerifyingKey) {
      return new PublicKey(inner)
    }

    static tryImport(bytes: Uint8Array) {
      return Result.runAndWrapSync(() => {
        return Eligos.VerifyingKey.from_sec1_bytes(bytes)
      }).mapErrSync(ImportError.from).mapSync(PublicKey.new)
    }

    static tryRecover(hashed: Uint8Array, signature: SignatureAndRecovery) {
      return Result.runAndWrapSync(() => {
        return Eligos.VerifyingKey.recover_from_prehash(hashed, signature.inner)
      }).mapErrSync(RecoverError.from).mapSync(PublicKey.new)
    }

    // tryVerify(payload: Uint8Array, signature: Signature) {
    //   return tryCryptoSync(() => this.inner.verify(payload, signature.inner))
    // }

    tryExportCompressed() {
      return Result.runAndWrapSync(() => {
        return this.inner.to_sec1_compressed_bytes()
      }).mapErrSync(ExportError.from)
    }

    tryExportUncompressed() {
      return Result.runAndWrapSync(() => {
        return this.inner.to_sec1_uncompressed_bytes()
      }).mapErrSync(ExportError.from)
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
      return Result.runAndWrapSync(() => {
        return this.inner.to_bytes()
      }).mapErrSync(ExportError.from)
    }

  }

  return { PrivateKey, PublicKey, SignatureAndRecovery }
}