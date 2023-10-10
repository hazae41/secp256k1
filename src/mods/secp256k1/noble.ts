import { Box, Copiable, Copied } from "@hazae41/box"
import { Ok, Result } from "@hazae41/result"
import { ProjPointType, RecoveredSignatureType } from "@noble/curves/abstract/weierstrass"
import { secp256k1 } from "@noble/curves/secp256k1"
import { Adapter } from "./adapter.js"
import { ConvertError, ExportError, GenerateError, ImportError, RecoverError, SignError, VerifyError } from "./errors.js"

export function fromNoble(): Adapter {

  class PrivateKey {

    constructor(
      readonly bytes: Box<Copiable>
    ) { }

    [Symbol.dispose]() {
      this.bytes[Symbol.dispose]()
    }

    static new(bytes: Box<Copiable>) {
      return new PrivateKey(bytes)
    }

    static tryRandom() {
      return Result.runAndWrapSync(() => {
        return new Box(new Copied(secp256k1.utils.randomPrivateKey()))
      }).mapErrSync(GenerateError.from).mapSync(PrivateKey.new)
    }

    static tryImport(bytes: Box<Copiable>) {
      return Result.assert(secp256k1.utils.isValidPrivateKey(bytes.get().bytes))
        .mapErrSync(ImportError.from)
        .mapSync(() => PrivateKey.new(bytes))
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return secp256k1.ProjectivePoint.fromPrivateKey(this.bytes.get().bytes)
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    trySign(payload: Box<Copiable>) {
      return Result.runAndWrapSync(() => {
        return secp256k1.sign(payload.get().bytes, this.bytes.get().bytes)
      }).mapErrSync(SignError.from).mapSync(SignatureAndRecovery.new)
    }

    tryExport() {
      return new Ok(this.bytes.unwrap())
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

    static tryImport(bytes: Box<Copiable>) {
      return Result.runAndWrapSync(() => {
        return secp256k1.ProjectivePoint.fromHex(bytes.get().bytes)
      }).mapErrSync(ImportError.from).mapSync(PublicKey.new)
    }

    static tryRecover(hashed: Box<Copiable>, signature: SignatureAndRecovery) {
      return Result.runAndWrapSync(() => {
        return signature.inner.recoverPublicKey(hashed.get().bytes)
      }).mapErrSync(RecoverError.from).mapSync(PublicKey.new)
    }

    tryVerify(payload: Box<Copiable>, signature: SignatureAndRecovery) {
      return Result.runAndWrapSync(() => {
        return secp256k1.verify(signature.inner, payload.get().bytes, this.inner.toRawBytes())
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

    static tryImport(bytes: Box<Copiable>) {
      return Result.runAndWrapSync(() => {
        return secp256k1.Signature.fromCompact(bytes.get().bytes.subarray(0, 64)).addRecoveryBit(bytes.get().bytes[64])
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