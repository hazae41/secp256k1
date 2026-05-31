import { assert, test } from "@hazae41/phobos";
import { secp256k1 } from "../mod.ts";

test("signature", () => {
  const key = secp256k1.SecretKey.random()

  const msg = crypto.getRandomValues(new Uint8Array(32))
  const sig = key.sign(msg)

  const pub = secp256k1.PublicKey.recover(msg, sig)

  assert(pub.export(true).toHex() === key.publish().export(true).toHex())
})

test("arithmetic", () => {
  const key = secp256k1.SecretKey.random()

  const x = secp256k1.Point.generator.mul(0x1234abcdn)
  const y = key.publish().downcast()
  const z = x.add(y)

  assert(z.identity === false)

  const pub = z.upcast()

  console.log(pub.export(true).toHex())
})