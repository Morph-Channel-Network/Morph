// Shared only by the development Fiber harness and its input-boundary tests.
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { secp256k1 } from "@noble/curves/secp256k1.js";

export function protectedPayerKeyFromEnv(environment = process.env) {
  if (Object.hasOwn(environment, "MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY")) {
    throw new Error("raw payer key input is unsupported; use MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE");
  }
  const path = environment.MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE;
  if (typeof path !== "string" || path.length === 0) {
    throw new Error("MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE is required");
  }
  return protectedPayerKeyFile(path);
}

export function protectedPayerKeyFile(path) {
  if (process.platform !== "linux" || typeof process.geteuid !== "function"
      || typeof constants.O_NOFOLLOW !== "number" || typeof constants.O_NONBLOCK !== "number") {
    throw new Error("protected payer key files are unsupported on this platform");
  }
  let fd;
  const buffer = Buffer.alloc(257);
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.geteuid() || (stat.mode & 0o077) !== 0
        || stat.size > 256) throw new Error("invalid protected file");
    const count = readSync(fd, buffer, 0, buffer.length, 0);
    if (count > 256) throw new Error("oversized protected file");
    const text = buffer.subarray(0, count).toString("utf8").replace(/^[\t-\r ]+|[\t-\r ]+$/g, "");
    const hex = text.startsWith("0x") ? text.slice(2) : text;
    if (!/^[0-9a-fA-F]{64}$/u.test(hex)) throw new Error("invalid key encoding");
    const key = Uint8Array.from(Buffer.from(hex, "hex"));
    try {
      secp256k1.getPublicKey(key, true);
    } catch {
      key.fill(0);
      throw new Error("invalid scalar");
    }
    return key;
  } catch {
    throw new Error("protected payer key file is invalid or inaccessible");
  } finally {
    buffer.fill(0);
    if (fd !== undefined) closeSync(fd);
  }
}
