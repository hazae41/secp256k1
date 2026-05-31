import type { Nullable } from "@/libs/nullable/mod.ts";
import { None, Option } from "@hazae41/result-and-option";
import type { Abstract } from "../abstract/mod.ts";

let global: Option<Adapter> = new None()

export function get(): Option<Adapter> {
  return global
}

export function set(value: Nullable<Adapter>) {
  global = Option.wrap(value)
}

export interface Adapter {

  readonly Memory: Abstract.Memory.Static

  readonly Secp256k1SigningKey: Abstract.Secp256k1SigningKey.Static

  readonly Secp256k1VerifyingKey: Abstract.Secp256k1VerifyingKey.Static

  readonly Secp256k1SignatureAndRecovery: Abstract.Secp256k1SignatureAndRecovery.Static

  readonly Secp256k1Scalar: Abstract.Secp256k1Scalar.Static

  readonly Secp256k1Point: Abstract.Secp256k1Point.Static

}