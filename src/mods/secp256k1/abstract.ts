import { BytesOrCopiable, Copiable } from "libs/copiable/index.js"

export abstract class SigningKey implements Disposable {

  constructor(..._: any[]) { }

  static randomOrThrow(): SigningKey {
    throw new Error("Method not implemented.")
  }

  static importOrThrow(bytes: BytesOrCopiable): SigningKey {
    throw new Error("Method not implemented.")
  }

  abstract [Symbol.dispose](): void

  abstract getVerifyingKeyOrThrow(): VerifyingKey

  abstract signOrThrow(payload: BytesOrCopiable): SignatureAndRecovery

  abstract exportOrThrow(): Copiable

}

export abstract class VerifyingKey implements Disposable {

  constructor(..._: any[]) { }

  static importOrThrow(bytes: BytesOrCopiable): VerifyingKey {
    throw new Error("Method not implemented.")
  }

  static recoverOrThrow(hashed: BytesOrCopiable, signature: SignatureAndRecovery): VerifyingKey {
    throw new Error("Method not implemented.")
  }

  abstract [Symbol.dispose](): void

  abstract exportCompressedOrThrow(): Copiable

  abstract exportUncompressedOrThrow(): Copiable

}

export abstract class SignatureAndRecovery implements Disposable {

  constructor(..._: any[]) { }

  static importOrThrow(bytes: BytesOrCopiable): SignatureAndRecovery {
    throw new Error("Method not implemented.")
  }

  abstract [Symbol.dispose](): void

  abstract exportOrThrow(): Copiable

}