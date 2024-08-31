import type { ProjPointType, RecoveredSignatureType } from "@noble/curves/abstract/weierstrass"
import type * as Secp256k1Noble from "@noble/curves/secp256k1"
import { BytesOrCopiable, Copied } from "libs/copiable/index.js"
import * as Abstract from "./abstract.js"
import { Adapter } from "./adapter.js"

export function fromNoble(noble: typeof Secp256k1Noble) {
  const { secp256k1 } = noble

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class SigningKey extends Abstract.SigningKey {

    constructor(
      readonly bytes: Uint8Array
    ) {
      super()
    }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new SigningKey(bytes)
    }

    static randomOrThrow() {
      return new SigningKey(secp256k1.utils.randomPrivateKey())
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      const bytes2 = getBytes(bytes)

      if (!secp256k1.utils.isValidPrivateKey(bytes2))
        throw new Error("Invalid private key")

      return new SigningKey(bytes2.slice())
    }

    getVerifyingKeyOrThrow() {
      return new VerifyingKey(secp256k1.ProjectivePoint.fromPrivateKey(this.bytes))
    }

    signOrThrow(payload: BytesOrCopiable) {
      return new SignatureAndRecovery(secp256k1.sign(getBytes(payload), this.bytes))
    }

    exportOrThrow() {
      return new Copied(this.bytes)
    }

  }

  class VerifyingKey extends Abstract.VerifyingKey {

    constructor(
      readonly inner: ProjPointType<bigint>
    ) {
      super()
    }

    [Symbol.dispose]() { }

    static create(inner: ProjPointType<bigint>) {
      return new VerifyingKey(inner)
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      return new VerifyingKey(secp256k1.ProjectivePoint.fromHex(getBytes(bytes)))
    }

    static recoverOrThrow(hashed: BytesOrCopiable, signature: SignatureAndRecovery) {
      return new VerifyingKey(signature.inner.recoverPublicKey(getBytes(hashed)))
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

  class SignatureAndRecovery extends Abstract.SignatureAndRecovery {

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

  return { SigningKey, VerifyingKey, SignatureAndRecovery } satisfies Adapter
}