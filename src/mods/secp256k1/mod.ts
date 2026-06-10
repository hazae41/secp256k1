// deno-lint-ignore-file no-namespace

import { load, Memory, Secp256k1Point, Secp256k1Scalar, Secp256k1SignatureAndRecovery, Secp256k1SigningKey, Secp256k1VerifyingKey } from "@hazae41/secp256k1-wasm";

await load()

export namespace Curve {

  export const order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n

}

export class SecretKey {

  /**
   * Do not use
   * @param inner 
   */
  constructor(
    readonly inner: Secp256k1SigningKey
  ) { }

  /**
   * Generate a random secret key
   * @returns 
   */
  static random(): SecretKey {
    return new SecretKey(new Secp256k1SigningKey())
  }

  /**
   * Import from 32 bytes
   * @param key 
   * @returns 
   */
  static import(key: Uint8Array): SecretKey {
    return new SecretKey(Secp256k1SigningKey.from_bytes(new Memory(key)))
  }

  /**
   * Export to 32 bytes
   * @returns 
   */
  export(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.inner.to_bytes().bytes)
  }

  /**
   * Publish this secret key to a public key
   * @returns 
   */
  publish(): PublicKey {
    return new PublicKey(this.inner.publish())
  }

  /**
   * Sign a message hash (32 bytes)
   * @param hashed 
   * @returns 
   */
  sign(hashed: Uint8Array): Signature {
    return new Signature(this.inner.sign_prehash_recoverable(new Memory(hashed)))
  }

}

export class PublicKey {

  constructor(
    readonly inner: Secp256k1VerifyingKey
  ) { }

  /**
   * Import from compressed (33 bytes) or uncompressed (65 bytes) SEC1 format
   * @param key 
   * @returns 
   */
  static import(key: Uint8Array): PublicKey {
    return new PublicKey(Secp256k1VerifyingKey.from_sec1_bytes(new Memory(key)))
  }

  /**
   * Recover a public key from a signature and the message hash (32 bytes)
   * @param hashed 
   * @param signature 
   * @returns 
   */
  static recover(hashed: Uint8Array, signature: Signature): PublicKey {
    return new PublicKey(Secp256k1VerifyingKey.recover_from_prehash(new Memory(hashed), signature.inner))
  }

  /**
   * Downcast this public key to a point
   * @returns 
   */
  downcast(): Point {
    return new Point(this.inner.to_point())
  }

  /**
   * Export to compressed (33 bytes) or uncompressed (65 bytes) SEC1 format
   * @param compressed 
   * @returns 
   */
  export(compressed: boolean): Uint8Array<ArrayBuffer> {
    if (compressed) {
      return new Uint8Array(this.inner.to_sec1_compressed_bytes().bytes)
    } else {
      return new Uint8Array(this.inner.to_sec1_uncompressed_bytes().bytes)
    }
  }

}

export class Signature {

  /**
   * Do not use
   * @param inner 
   */
  constructor(
    readonly inner: Secp256k1SignatureAndRecovery
  ) { }

  /**
   * Import from RSV format (32 + 32 + 1 = 65 bytes)
   * @param rsv 
   * @returns 
   */
  static import(rsv: Uint8Array): Signature {
    return new Signature(Secp256k1SignatureAndRecovery.from_rsv_bytes(new Memory(rsv)))
  }

  /**
   * Export to RSV format (32 + 32 + 1 = 65 bytes)
   * @returns 
   */
  export(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.inner.to_rsv_bytes().bytes)
  }

}

export class Point {

  /**
   * Do not use
   * @param inner 
   */
  constructor(
    readonly inner: Secp256k1Point
  ) { }

  /**
   * The generator point
   */
  static get generator(): Point {
    return new Point(Secp256k1Point.generator())
  }

  /**
   * True if this point is the identity point (aka point at infinity, aka zero point, aka neutral element)
   */
  get identity(): boolean {
    return this.inner.is_identity()
  }

  /**
   * Upcast this point to a public key
   * @returns 
   */
  upcast(): PublicKey {
    return new PublicKey(Secp256k1VerifyingKey.from_point(this.inner))
  }

  /**
   * Multiply this point by a scalar
   * @param scalar 
   * @returns 
   */
  mul(scalar: bigint): Point {
    const n = Uint8Array.fromHex(scalar.toString(16).padStart(64, "0"))

    const x = this.inner.multiply(Secp256k1Scalar.from_bytes(new Memory(n)))

    return new Point(x)
  }

  /**
   * Add another point to this point
   * @param other 
   * @returns 
   */
  add(other: Point): Point {
    return new Point(this.inner.add(other.inner))
  }

}