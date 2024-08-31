import { None, Nullable, Option } from "@hazae41/option"
import { SignatureAndRecovery, SigningKey, VerifyingKey } from "./abstract.js"

let global: Option<Adapter> = new None()

export function get() {
  return global
}

export function set(value: Nullable<Adapter>) {
  global = Option.wrap(value)
}

export interface Adapter {
  readonly SigningKey: typeof SigningKey
  readonly VerifyingKey: typeof VerifyingKey
  readonly SignatureAndRecovery: typeof SignatureAndRecovery
} 