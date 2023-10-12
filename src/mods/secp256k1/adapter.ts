import { BytesOrCopiable, Copiable } from "@hazae41/box"
import { None, Option } from "@hazae41/option"
import { Result } from "@hazae41/result"
import { ConvertError, ExportError, GenerateError, ImportError, RecoverError, SignError } from "./errors.js"

let global: Option<Adapter> = new None()

export function get() {
  return global.unwrap()
}

export function set(value?: Adapter) {
  global = Option.wrap(value)
}

export interface PrivateKey extends Disposable {
  tryGetPublicKey(): Result<PublicKey, ConvertError>
  trySign(payload: BytesOrCopiable): Result<SignatureAndRecovery, SignError>
  tryExport(): Result<Copiable, ExportError>
}

export interface PublicKey extends Disposable {
  // tryVerify(payload: Uint8Array, signature: SignatureAndRecovery): Promiseable<Result<boolean, CryptoError>>
  tryExportCompressed(): Result<Copiable, ExportError>
  tryExportUncompressed(): Result<Copiable, ExportError>
}

export interface SignatureAndRecovery extends Disposable {
  tryExport(): Result<Copiable, ExportError>
}

export interface PrivateKeyFactory {
  tryRandom(): Result<PrivateKey, GenerateError>
  tryImport(bytes: BytesOrCopiable): Result<PrivateKey, ImportError>
}

export interface PublicKeyFactory {
  tryImport(bytes: BytesOrCopiable): Result<PublicKey, ImportError>
  tryRecover(hashed: BytesOrCopiable, signature: SignatureAndRecovery): Result<PublicKey, RecoverError>
}

export interface SignatureAndRecoveryFactory {
  // tryImport(bytes: Uint8Array): Promiseable<Result<SignatureAndRecovery, CryptoError>>
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
  readonly SignatureAndRecovery: SignatureAndRecoveryFactory
}