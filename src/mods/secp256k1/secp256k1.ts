import { Cursor, CursorWriteError } from "@hazae41/cursor"
import { None, Option } from "@hazae41/option"
import { Ok, Result } from "@hazae41/result"
import { CryptoError } from "libs/crypto/crypto.js"
import { Promiseable } from "libs/promises/promiseable.js"

let global: Option<Adapter> = new None()

export function get() {
  return global.unwrap()
}

export function set(value?: Adapter) {
  global = Option.wrap(value)
}

export interface Copiable extends Disposable {
  readonly bytes: Uint8Array

  copyAndDispose(): Uint8Array

  trySize(): Result<number, never>

  tryWrite(cursor: Cursor): Result<void, CursorWriteError>
}

export class Copied implements Copiable {

  /**
   * A copiable that's already copied
   * @param bytes 
   */
  constructor(
    readonly bytes: Uint8Array
  ) { }

  [Symbol.dispose]() { }

  static new(bytes: Uint8Array) {
    return new Copied(bytes)
  }

  static from(buffer: ArrayBuffer) {
    return new Copied(new Uint8Array(buffer))
  }

  copyAndDispose() {
    return this.bytes
  }

  trySize(): Result<number, never> {
    return new Ok(this.bytes.length)
  }

  tryWrite(cursor: Cursor): Result<void, CursorWriteError> {
    return cursor.tryWrite(this.bytes)
  }

}

export interface SignatureAndRecovery extends Disposable {
  tryExport(): Promiseable<Result<Copiable, CryptoError>>
}

export interface VerifyingKey extends Disposable {
  // tryVerify(payload: Uint8Array, signature: SignatureAndRecovery): Promiseable<Result<boolean, CryptoError>>
  tryExportCompressed(): Promiseable<Result<Copiable, CryptoError>>
  tryExportUncompressed(): Promiseable<Result<Copiable, CryptoError>>
}

export interface SigningKey extends Disposable {
  tryGetPublicKey(): Promiseable<Result<VerifyingKey, CryptoError>>
  trySign(payload: Uint8Array): Promiseable<Result<SignatureAndRecovery, CryptoError>>
  tryExport(): Promiseable<Result<Copiable, CryptoError>>
}

export interface VerifyingKeyFactory {
  tryImport(bytes: Uint8Array): Promiseable<Result<VerifyingKey, CryptoError>>
  tryRecover(hashed: Uint8Array, signature: SignatureAndRecovery): Promiseable<Result<VerifyingKey, CryptoError>>
}

export interface SigningKeyFactory {
  tryRandom(): Promiseable<Result<SigningKey, CryptoError>>
  tryImport(bytes: Uint8Array): Promiseable<Result<SigningKey, CryptoError>>
}

export interface SignatureAndRecoveryFactory {
  // tryImport(bytes: Uint8Array): Promiseable<Result<SignatureAndRecovery, CryptoError>>
}

export interface Adapter {
  readonly SigningKey: SigningKeyFactory
  readonly VerifyingKey: VerifyingKeyFactory
  readonly SignatureAndRecovery: SignatureAndRecoveryFactory
}