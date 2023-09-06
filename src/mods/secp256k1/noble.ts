import { Ok } from "@hazae41/result"
import { ProjPointType, RecoveredSignatureType } from "@noble/curves/abstract/weierstrass"
import type { secp256k1 } from "@noble/curves/secp256k1"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { Adapter, Copied } from "./secp256k1.js"

export function fromNoble(noble: typeof secp256k1): Adapter {

  class SigningKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new SigningKey(bytes)
    }

    static tryRandom() {
      return tryCryptoSync(() => noble.utils.randomPrivateKey()).mapSync(SigningKey.new)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new SigningKey(bytes))
    }

    tryGetPublicKey() {
      return tryCryptoSync(() => noble.ProjectivePoint.fromPrivateKey(this.bytes)).mapSync(VerifyingKey.new)
    }

    trySign(payload: Uint8Array) {
      return tryCryptoSync(() => noble.sign(payload, this.bytes)).mapSync(SignatureAndRecovery.new)
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  class VerifyingKey {

    constructor(
      readonly inner: ProjPointType<bigint>
    ) { }

    [Symbol.dispose]() { }

    static new(inner: ProjPointType<bigint>) {
      return new VerifyingKey(inner)
    }

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => noble.ProjectivePoint.fromHex(bytes)).mapSync(VerifyingKey.new)
    }

    static tryRecover(hashed: Uint8Array, signature: SignatureAndRecovery) {
      return tryCryptoSync(() => signature.inner.recoverPublicKey(hashed)).mapSync(VerifyingKey.new)
    }

    tryVerify(payload: Uint8Array, signature: SignatureAndRecovery) {
      return tryCryptoSync(() => noble.verify(signature.inner, payload, this.inner.toRawBytes()))
    }

    tryExportCompressed() {
      return new Ok(new Copied(this.inner.toRawBytes(true)))
    }

    tryExportUncompressed() {
      return new Ok(new Copied(this.inner.toRawBytes(false)))
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

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => noble.Signature.fromCompact(bytes.subarray(0, 64)).addRecoveryBit(bytes[64])).mapSync(SignatureAndRecovery.new)
    }

    tryExport() {
      return tryCryptoSync(() => {
        const rAndS = this.inner.toCompactRawBytes()
        const rAndSAndV = new Uint8Array(rAndS.length + 1)
        rAndSAndV.set(rAndS, 0)
        rAndSAndV[64] = this.inner.recovery
        return new Copied(rAndSAndV)
      })
    }

  }

  return { SigningKey, VerifyingKey, SignatureAndRecovery }
}