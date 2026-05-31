import { assert, test } from "@hazae41/phobos";
import { secp256k1 } from "../mod.ts";

test("signature", () => {
  const key = secp256k1.SecretKey.random()

  const pld = crypto.getRandomValues(new Uint8Array(32))
  const sig = key.sign(pld)

  const pub = secp256k1.PublicKey.recover(pld, sig)

  assert(pub.export(true).toHex() === key.publish().export(true).toHex())
})

test("arithmetic", () => {
  const key = secp256k1.SecretKey.random()

  const i = Uint8Array.fromHex("1234abcd".padStart(64, "0"))

  const x = secp256k1.Point.generator.mul(i)
  const y = key.publish().downcast()
  const z = x.add(y)

  assert(z.identity === false)

  const pub = z.upcast()

  console.log(pub.export(true).toHex())
})