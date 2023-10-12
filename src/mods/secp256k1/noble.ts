import { BytesOrCopiable, Copied } from "@hazae41/box"
import { Ok, Result } from "@hazae41/result"
import { ProjPointType, RecoveredSignatureType } from "@noble/curves/abstract/weierstrass"
import { secp256k1 } from "@noble/curves/secp256k1"
import { Adapter } from "./adapter.js"
import { ConvertError, ExportError, GenerateError, ImportError, RecoverError, SignError, VerifyError } from "./errors.js"

export function fromNoble(): Adapter {

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static tryRandom() {
      return Result.runAndWrapSync(() => {
        return secp256k1.utils.randomPrivateKey()
      }).mapErrSync(GenerateError.from).mapSync(PrivateKey.new)
    }

    static tryImport(bytes: BytesOrCopiable) {
      return Result.assert(secp256k1.utils.isValidPrivateKey(getBytes(bytes)))
        .set(PrivateKey.new(getBytes(bytes).slice()))
        .mapErrSync(ImportError.from)
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return secp256k1.ProjectivePoint.fromPrivateKey(this.bytes)
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    trySign(payload: BytesOrCopiable) {
      return Result.runAndWrapSync(() => {
        return secp256k1.sign(getBytes(payload), this.bytes)
      }).mapErrSync(SignError.from).mapSync(SignatureAndRecovery.new)
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  class PublicKey {

    constructor(
      readonly inner: ProjPointType<bigint>
    ) { }

    [Symbol.dispose]() { }

    static new(inner: ProjPointType<bigint>) {
      return new PublicKey(inner)
    }

    static tryImport(bytes: BytesOrCopiable) {
      return Result.runAndWrapSync(() => {
        return secp256k1.ProjectivePoint.fromHex(getBytes(bytes))
      }).mapErrSync(ImportError.from).mapSync(PublicKey.new)
    }

    static tryRecover(hashed: BytesOrCopiable, signature: SignatureAndRecovery) {
      return Result.runAndWrapSync(() => {
        return signature.inner.recoverPublicKey(getBytes(hashed))
      }).mapErrSync(RecoverError.from).mapSync(PublicKey.new)
    }

    tryVerify(payload: BytesOrCopiable, signature: SignatureAndRecovery) {
      return Result.runAndWrapSync(() => {
        return secp256k1.verify(signature.inner, getBytes(payload), this.inner.toRawBytes())
      }).mapErrSync(VerifyError.from)
    }

    tryExportCompressed() {
      return Result.runAndWrapSync(() => {
        return this.inner.toRawBytes(true)
      }).mapErrSync(ExportError.from).mapSync(Copied.new)
    }

    tryExportUncompressed() {
      return Result.runAndWrapSync(() => {
        return this.inner.toRawBytes(false)
      }).mapErrSync(ExportError.from).mapSync(Copied.new)
    }

  }

  class SignatureAndRecovery {

    constructor(
      readonly inner: RecoveredSignatureType
    ) { }

    [Symbol.dispose]() { }

    static new(inner: RecoveredSignatureType) {
      return new SignatureAndRecovery(inner)
    }

    static tryImport(bytes: BytesOrCopiable) {
      const bytes2 = getBytes(bytes)

      return Result.runAndWrapSync(() => {
        return secp256k1.Signature.fromCompact(bytes2.subarray(0, 64)).addRecoveryBit(bytes2[64])
      }).mapErrSync(ImportError.from).mapSync(SignatureAndRecovery.new)
    }

    tryExport() {
      return Result.runAndWrapSync(() => {
        const rAndS = this.inner.toCompactRawBytes()
        const rAndSAndV = new Uint8Array(rAndS.length + 1)
        rAndSAndV.set(rAndS, 0)
        rAndSAndV[64] = this.inner.recovery
        return new Copied(rAndSAndV)
      }).mapErrSync(ExportError.from)
    }

  }

  return { PrivateKey, PublicKey, SignatureAndRecovery }
}