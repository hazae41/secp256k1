// deno-lint-ignore-file no-namespace

export namespace Abstract {

  export type MemoryLike = Memory | Uint8Array

  export abstract class Memory implements Disposable {

    abstract [Symbol.dispose](): void

    abstract readonly inner: unknown

    abstract readonly bytes: Uint8Array

  }

  export namespace Memory {

    export interface Static {

      fromOrThrow(memory: MemoryLike): Memory

    }

  }

  export abstract class Secp256k1SigningKey implements Disposable {

    abstract [Symbol.dispose](): void

    abstract signOrThrow(payload: Memory): Secp256k1SignatureAndRecovery

    abstract publishOrThrow(): Secp256k1VerifyingKey

    abstract exportOrThrow(): Memory

  }

  export namespace Secp256k1SigningKey {

    export interface Static {

      randomOrThrow(): Secp256k1SigningKey

      importOrThrow(key: Memory): Secp256k1SigningKey

    }

  }

  export abstract class Secp256k1VerifyingKey implements Disposable {

    abstract [Symbol.dispose](): void

    abstract downcastOrThrow(): Secp256k1Point

    abstract exportAsCompressedOrThrow(): Memory

    abstract exportAsUncompressedOrThrow(): Memory

  }

  export namespace Secp256k1VerifyingKey {

    export interface Static {

      importOrThrow(key: Memory): Secp256k1VerifyingKey

      recoverOrThrow(hashed: Memory, signature: Secp256k1SignatureAndRecovery): Secp256k1VerifyingKey

    }

  }

  export abstract class Secp256k1SignatureAndRecovery implements Disposable {

    abstract [Symbol.dispose](): void

    abstract exportOrThrow(): Memory

  }

  export namespace Secp256k1SignatureAndRecovery {

    export interface Static {

      importOrThrow(signature: Memory): Secp256k1SignatureAndRecovery

    }

  }

  export abstract class Secp256k1Point implements Disposable {

    abstract [Symbol.dispose](): void

    abstract multiplyOrThrow(scalar: Secp256k1Scalar): Secp256k1Point

    abstract addOrThrow(point: Secp256k1Point): Secp256k1Point

    abstract checkOrThrow(): boolean

    abstract upcastOrThrow(): Secp256k1VerifyingKey

  }

  export namespace Secp256k1Point {

    export interface Static {

      generatorOrThrow(): Secp256k1Point

    }

  }

  export abstract class Secp256k1Scalar implements Disposable {

    abstract [Symbol.dispose](): void

    abstract exportOrThrow(): Memory

  }

  export namespace Secp256k1Scalar {

    export interface Static {

      importOrThrow(scalar: Memory): Secp256k1Scalar

    }

  }

}