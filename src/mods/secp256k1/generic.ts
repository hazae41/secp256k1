import { BytesOrCopiable, Copiable } from "@hazae41/box"

export abstract class PrivateKey implements Disposable {

  constructor(..._: any[]) { }

  abstract [Symbol.dispose](): void

  abstract getPublicKeyOrThrow(): PublicKey

  abstract signOrThrow(payload: BytesOrCopiable): SignatureAndRecovery

  abstract exportOrThrow(): Copiable

  static randomOrThrow(): PrivateKey {
    throw new Error("Method not implemented.")
  }

  static importOrThrow(bytes: BytesOrCopiable): PrivateKey {
    throw new Error("Method not implemented.")
  }

}

export abstract class PublicKey implements Disposable {

  constructor(..._: any[]) { }

  abstract [Symbol.dispose](): void

  // abstract verifyOrThrow(payload: Uint8Array, signature: SignatureAndRecovery): boolean

  abstract exportCompressedOrThrow(): Copiable

  abstract exportUncompressedOrThrow(): Copiable

  static importOrThrow(bytes: BytesOrCopiable): PublicKey {
    throw new Error("Method not implemented.")
  }

  static recoverOrThrow(hashed: BytesOrCopiable, signature: SignatureAndRecovery): PublicKey {
    throw new Error("Method not implemented.")
  }

}

export abstract class SignatureAndRecovery implements Disposable {

  constructor(..._: any[]) { }

  abstract [Symbol.dispose](): void

  abstract exportOrThrow(): Copiable
}