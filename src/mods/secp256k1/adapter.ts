import { None, Option } from "@hazae41/option"
import { PrivateKey, PublicKey, SignatureAndRecovery } from "./generic.js"

export * as Generic from "./generic.js"

let global: Option<Adapter> = new None()

export function get() {
  return global.unwrap()
}

export function set(value?: Adapter) {
  global = Option.wrap(value)
}

export interface Adapter {
  readonly PrivateKey: typeof PrivateKey
  readonly PublicKey: typeof PublicKey
  readonly SignatureAndRecovery: typeof SignatureAndRecovery
} 