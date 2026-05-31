import { assert, test } from "@hazae41/phobos";

import { secp256k1Wasm } from "@hazae41/secp256k1-wasm";
import { fromWasm, get, set, } from "./mod.ts";

test("secp256k1", async () => {
  await secp256k1Wasm.load()

  set(fromWasm(secp256k1Wasm))

  const { Memory, Secp256k1SigningKey, Secp256k1VerifyingKey } = get().getOrThrow()

  const key = Secp256k1SigningKey.randomOrThrow()

  const pld = Memory.fromOrThrow(crypto.getRandomValues(new Uint8Array(32)))
  const sig = key.signOrThrow(pld)

  const pub = Secp256k1VerifyingKey.recoverOrThrow(pld, sig)

  assert(pub.exportAsCompressedOrThrow().bytes.toHex() === key.publishOrThrow().exportAsCompressedOrThrow().bytes.toHex())
})