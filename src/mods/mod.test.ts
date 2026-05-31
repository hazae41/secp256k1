import { assert, test } from "@hazae41/phobos";

import { secp256k1Wasm } from "@hazae41/secp256k1-wasm";
import { fromWasm, get, set, } from "./mod.ts";

await secp256k1Wasm.load()

set(fromWasm(secp256k1Wasm))

test("signature", () => {
  const { Memory, Secp256k1SigningKey, Secp256k1VerifyingKey } = get().getOrThrow()

  const key = Secp256k1SigningKey.randomOrThrow()

  const pld = Memory.fromOrThrow(crypto.getRandomValues(new Uint8Array(32)))
  const sig = key.signOrThrow(pld)

  const pub = Secp256k1VerifyingKey.recoverOrThrow(pld, sig)

  assert(pub.exportAsCompressedOrThrow().bytes.toHex() === key.publishOrThrow().exportAsCompressedOrThrow().bytes.toHex())
})

test("arithmetic", () => {
  const { Memory, Secp256k1SigningKey, Secp256k1Point, Secp256k1Scalar } = get().getOrThrow()

  const key = Secp256k1SigningKey.randomOrThrow()

  const i = Secp256k1Scalar.importOrThrow(Memory.fromOrThrow(Uint8Array.fromHex("1234abcd".padStart(64, "0"))))

  const x = Secp256k1Point.generatorOrThrow().multiplyOrThrow(i)
  const y = key.publishOrThrow().downcastOrThrow()
  const z = x.addOrThrow(y)

  assert(z.checkOrThrow() === false)

  const pub = z.upcastOrThrow()

  console.log(pub.exportAsUncompressedOrThrow().bytes.toHex())
})