import { secp256k1Wasm } from "@hazae41/secp256k1-wasm";

await secp256k1Wasm.load()

export class SecretKey {

  constructor(
    readonly inner: secp256k1Wasm.Secp256k1SigningKey
  ) { }

  [Symbol.dispose]() {
    this.inner[Symbol.dispose]()
  }

  static random(): SecretKey {
    const { Secp256k1SigningKey } = secp256k1Wasm

    const inner = new Secp256k1SigningKey()

    return new SecretKey(inner)
  }

  static import(bytes: Uint8Array): SecretKey {
    const { Memory, Secp256k1SigningKey } = secp256k1Wasm

    const inner = Secp256k1SigningKey.from_bytes(new Memory(bytes))

    return new SecretKey(inner)
  }

  export(): Uint8Array {
    return this.inner.to_bytes().bytes
  }

  publish(): PublicKey {
    return new PublicKey(this.inner.publish())
  }

  sign(message: Uint8Array): Signature {
    const { Memory } = secp256k1Wasm

    const result = this.inner.sign_prehash_recoverable(new Memory(message))

    return new Signature(result)
  }

}

export class PublicKey {

  constructor(
    readonly inner: secp256k1Wasm.Secp256k1VerifyingKey
  ) { }

  [Symbol.dispose]() {
    this.inner[Symbol.dispose]()
  }

  static import(bytes: Uint8Array): PublicKey {
    const { Memory, Secp256k1VerifyingKey } = secp256k1Wasm

    const inner = Secp256k1VerifyingKey.from_sec1_bytes(new Memory(bytes))

    return new PublicKey(inner)
  }

  static recover(hashed: Uint8Array, signature: Signature): PublicKey {
    const { Memory, Secp256k1VerifyingKey } = secp256k1Wasm

    const result = Secp256k1VerifyingKey.recover_from_prehash(new Memory(hashed), signature.inner)

    return new PublicKey(result)
  }

  downcast() {
    return new Point(this.inner.to_point())
  }

  export(compressed: boolean): Uint8Array {
    if (compressed) {
      return this.inner.to_sec1_compressed_bytes().bytes
    } else {
      return this.inner.to_sec1_uncompressed_bytes().bytes
    }
  }

}

export class Signature {

  constructor(
    readonly inner: secp256k1Wasm.Secp256k1SignatureAndRecovery
  ) { }

  [Symbol.dispose]() {
    this.inner[Symbol.dispose]()
  }

  static import(bytes: Uint8Array): Signature {
    const { Memory, Secp256k1SignatureAndRecovery } = secp256k1Wasm

    const inner = Secp256k1SignatureAndRecovery.from_rsv_bytes(new Memory(bytes))

    return new Signature(inner)
  }

  export(): Uint8Array {
    return this.inner.to_rsv_bytes().bytes
  }

}

export class Point {

  constructor(
    readonly inner: secp256k1Wasm.Secp256k1Point
  ) { }

  [Symbol.dispose]() {
    this.inner[Symbol.dispose]()
  }

  static get generator(): Point {
    const { Secp256k1Point } = secp256k1Wasm

    const inner = Secp256k1Point.generator()

    return new Point(inner)
  }

  get identity(): boolean {
    return this.inner.is_identity()
  }

  upcast(): PublicKey {
    const { Secp256k1VerifyingKey } = secp256k1Wasm

    const inner = Secp256k1VerifyingKey.from_point(this.inner)

    return new PublicKey(inner)
  }

  mul(scalar: Uint8Array): Point {
    const { Memory, Secp256k1Scalar } = secp256k1Wasm

    const i = Secp256k1Scalar.from_bytes(new Memory(scalar))
    const x = this.inner.multiply(i)

    return new Point(x)
  }

  add(other: Point): Point {
    return new Point(this.inner.add(other.inner))
  }

}