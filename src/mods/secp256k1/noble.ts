import { BytesOrCopiable, Copied } from "@hazae41/box"
import { ProjPointType, RecoveredSignatureType } from "@noble/curves/abstract/weierstrass"
import { secp256k1 } from "@noble/curves/secp256k1"
import { Adapter, Generic } from "./adapter.js"

export function fromNoble(): Adapter {

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey extends Generic.PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) {
      super()
    }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static randomOrThrow() {
      return new PrivateKey(secp256k1.utils.randomPrivateKey())
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      const bytes2 = getBytes(bytes)

      if (!secp256k1.utils.isValidPrivateKey(bytes2))
        throw new Error("Invalid private key")

      return new PrivateKey(bytes2.slice())
    }

    getPublicKeyOrThrow() {
      return new PublicKey(secp256k1.ProjectivePoint.fromPrivateKey(this.bytes))
    }

    signOrThrow(payload: BytesOrCopiable) {
      return new SignatureAndRecovery(secp256k1.sign(getBytes(payload), this.bytes))
    }

    exportOrThrow() {
      return new Copied(this.bytes)
    }

  }

  class PublicKey extends Generic.PublicKey {

    constructor(
      readonly inner: ProjPointType<bigint>
    ) {
      super()
    }

    [Symbol.dispose]() { }

    static create(inner: ProjPointType<bigint>) {
      return new PublicKey(inner)
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      return new PublicKey(secp256k1.ProjectivePoint.fromHex(getBytes(bytes)))
    }

    static recoverOrThrow(hashed: BytesOrCopiable, signature: SignatureAndRecovery) {
      return new PublicKey(signature.inner.recoverPublicKey(getBytes(hashed)))
    }

    verifyOrThrow(payload: BytesOrCopiable, signature: SignatureAndRecovery) {
      return secp256k1.verify(signature.inner, getBytes(payload), this.inner.toRawBytes())
    }

    exportCompressedOrThrow() {
      return new Copied(this.inner.toRawBytes(true))
    }

    exportUncompressedOrThrow() {
      return new Copied(this.inner.toRawBytes(false))
    }

  }

  class SignatureAndRecovery extends Generic.SignatureAndRecovery {

    constructor(
      readonly inner: RecoveredSignatureType
    ) {
      super()
    }

    [Symbol.dispose]() { }

    static create(inner: RecoveredSignatureType) {
      return new SignatureAndRecovery(inner)
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      const bytes2 = getBytes(bytes)

      const inner = secp256k1.Signature.fromCompact(bytes2.subarray(0, 64)).addRecoveryBit(bytes2[64])

      return new SignatureAndRecovery(inner)
    }

    exportOrThrow() {
      const rAndS = this.inner.toCompactRawBytes()
      const rAndSAndV = new Uint8Array(rAndS.length + 1)
      rAndSAndV.set(rAndS, 0)
      rAndSAndV[64] = this.inner.recovery
      return new Copied(rAndSAndV)
    }

  }

  return { PrivateKey, PublicKey, SignatureAndRecovery }
}