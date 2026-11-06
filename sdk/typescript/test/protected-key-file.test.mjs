import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { protectedPayerKeyFile, protectedPayerKeyFromEnv } from "./protected-key-file.mjs";

// This scalar is a public, no-value fixture. Never use it for deployment funds.
const fixtureHex = "b4".repeat(32);
const fixtureBytes = Buffer.from(fixtureHex, "hex");
const harness = fileURLToPath(new URL("./fiber-devnet.mjs", import.meta.url));

function errorDoesNotEchoFixture(output) {
  assert.equal(output.includes(fixtureHex), false, "hex key appeared in error output");
  assert.equal(output.includes(fixtureBytes), false, "key bytes appeared in error output");
}

function harnessRejects(environment, message) {
  const child = spawnSync(process.execPath, [harness], {
    env: environment,
    timeout: 5000,
  });
  assert.equal(child.error, undefined, "harness must reject without blocking or making RPC calls");
  assert.equal(child.status, 1);
  const output = Buffer.concat([child.stdout, child.stderr]);
  errorDoesNotEchoFixture(output);
  assert.match(output.toString(), message);
  assert.doesNotMatch(output.toString(), /PAYEE_URL is required|fetch failed/);
}

if (process.platform === "linux") {
  const directory = mkdtempSync(join(tmpdir(), "morph-sdk-key-input-"));
  try {
    chmodSync(directory, 0o700);
    const keyPath = join(directory, "payer.key");
    writeFileSync(keyPath, `0x${fixtureHex}\n`, { mode: 0o600 });
    for (const mode of [0o600, 0o400]) {
      chmodSync(keyPath, mode);
      const key = protectedPayerKeyFromEnv({ MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE: keyPath });
      assert.deepEqual(Buffer.from(key), fixtureBytes);
      key.fill(0);
    }
    for (const mode of [0o640, 0o644, 0o777]) {
      chmodSync(keyPath, mode);
      harnessRejects({ MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE: keyPath }, /protected payer key file is invalid/);
    }
    chmodSync(keyPath, 0o600);
    const linkPath = join(directory, "payer-link.key");
    symlinkSync(keyPath, linkPath);
    harnessRejects({ MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE: linkPath }, /protected payer key file is invalid/);
    const nestedDirectory = join(directory, "directory");
    mkdirSync(nestedDirectory, { mode: 0o700 });
    harnessRejects({ MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE: nestedDirectory }, /protected payer key file is invalid/);
    const fifoPath = join(directory, "payer.fifo");
    const fifo = spawnSync("mkfifo", ["-m", "600", fifoPath]);
    assert.equal(fifo.error, undefined);
    assert.equal(fifo.status, 0);
    harnessRejects({ MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE: fifoPath }, /protected payer key file is invalid/);

    for (const content of [
      `0x${fixtureHex}${" ".repeat(257)}`,
      `${fixtureHex} ${fixtureHex}`,
      `${fixtureHex}\0`,
      "00".repeat(32),
      "ff".repeat(32),
      "not-a-private-key",
      Buffer.from([0xff]),
    ]) {
      writeFileSync(keyPath, content);
      harnessRejects({ MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE: keyPath }, /protected payer key file is invalid/);
    }
    harnessRejects({
      MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY: fixtureHex,
      MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE: keyPath,
    }, /raw payer key input is unsupported/);
    console.log("protected_payer_key_file_rejects_unsafe_inputs_before_rpc passed");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
} else {
  assert.throws(() => protectedPayerKeyFile("unused"), /unsupported on this platform/);
  console.log("protected_payer_key_file_fails_closed_on_unsupported_platform passed");
}
