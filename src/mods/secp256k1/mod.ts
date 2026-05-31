import { secp256k1Wasm } from "@hazae41/secp256k1-wasm";

await secp256k1Wasm.load()

export class SecretKey {

  /**
   * Do not use
   * @param inner 
   */
  constructor(
    readonly inner: secp256k1Wasm.Secp256k1SigningKey
  ) { }

  /**
   * Generate a random secret key
   * @returns 
   */
  static random(): SecretKey {
    const { Secp256k1SigningKey } = secp256k1Wasm

    const inner = new Secp256k1SigningKey()

    return new SecretKey(inner)
  }

  /**
   * Import from 32 bytes
   * @param key 
   * @returns 
   */
  static import(key: Uint8Array): SecretKey {
    const { Memory, Secp256k1SigningKey } = secp256k1Wasm

    const inner = Secp256k1SigningKey.from_bytes(new Memory(key))

    return new SecretKey(inner)
  }

  /**
   * Export to 32 bytes
   * @returns 
   */
  export(): Uint8Array {
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
    const { Memory } = secp256k1Wasm

    const result = this.inner.sign_prehash_recoverable(new Memory(hashed))

    return new Signature(result)
  }

}

export class PublicKey {

  constructor(
    readonly inner: secp256k1Wasm.Secp256k1VerifyingKey
  ) { }

  /**
   * Import from compressed (33 bytes) or uncompressed (65 bytes) SEC1 format
   * @param key 
   * @returns 
   */
  static import(key: Uint8Array): PublicKey {
    const { Memory, Secp256k1VerifyingKey } = secp256k1Wasm

    const inner = Secp256k1VerifyingKey.from_sec1_bytes(new Memory(key))

    return new PublicKey(inner)
  }

  /**
   * Recover a public key from a signature and the message hash (32 bytes)
   * @param hashed 
   * @param signature 
   * @returns 
   */
  static recover(hashed: Uint8Array, signature: Signature): PublicKey {
    const { Memory, Secp256k1VerifyingKey } = secp256k1Wasm

    const result = Secp256k1VerifyingKey.recover_from_prehash(new Memory(hashed), signature.inner)

    return new PublicKey(result)
  }

  /**
   * Downcast this public key to a point
   * @returns 
   */
  downcast() {
    return new Point(this.inner.to_point())
  }

  /**
   * Export to compressed (33 bytes) or uncompressed (65 bytes) SEC1 format
   * @param compressed 
   * @returns 
   */
  export(compressed: boolean): Uint8Array {
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
    readonly inner: secp256k1Wasm.Secp256k1SignatureAndRecovery
  ) { }

  /**
   * Import from RSV format (32 + 32 + 1 = 65 bytes)
   * @param rsv 
   * @returns 
   */
  static import(rsv: Uint8Array): Signature {
    const { Memory, Secp256k1SignatureAndRecovery } = secp256k1Wasm

    const inner = Secp256k1SignatureAndRecovery.from_rsv_bytes(new Memory(rsv))

    return new Signature(inner)
  }

  /**
   * Export to RSV format (32 + 32 + 1 = 65 bytes)
   * @returns 
   */
  export(): Uint8Array {
    return new Uint8Array(this.inner.to_rsv_bytes().bytes)
  }

}

export class Point {

  /**
   * Do not use
   * @param inner 
   */
  constructor(
    readonly inner: secp256k1Wasm.Secp256k1Point
  ) { }

  /**
   * The generator point
   */
  static get generator(): Point {
    const { Secp256k1Point } = secp256k1Wasm

    const inner = Secp256k1Point.generator()

    return new Point(inner)
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
    const { Secp256k1VerifyingKey } = secp256k1Wasm

    const inner = Secp256k1VerifyingKey.from_point(this.inner)

    return new PublicKey(inner)
  }

  /**
   * Multiply this point by a scalar (32 bytes)
   * @param scalar 
   * @returns 
   */
  mul(scalar: Uint8Array): Point {
    const { Memory, Secp256k1Scalar } = secp256k1Wasm

    const i = Secp256k1Scalar.from_bytes(new Memory(scalar))
    const x = this.inner.multiply(i)

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