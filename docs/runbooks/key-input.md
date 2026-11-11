# Protected private-key file input

Morph CLI and Morph Payment Gateway accept private signing keys only through
file paths.
Use the appropriate `*-private-key-file PATH` option or `*_PRIVATE_KEY_FILE`
environment variable. The environment value is a path, never key material. Raw
private-key arguments and raw-key environment variables are unsupported; there
is no stdin, file-descriptor or legacy raw-key fallback.

## Provision and retain the file

Provision keys through your existing secret-management process into a directory
controlled by the signing user. For example, create the destination directory
before provisioning, without putting the key bytes in a shell command:

```sh
umask 077
install -d -m 0700 /srv/morph/keys
# Provision /srv/morph/keys/alice.key securely with mode 0600 or 0400.
morph-cli multi-asset-session --session /srv/morph/alice.json inspect
# Run the key service in its supervised process (RPC-enabled devnet build):
morph-cli participant-signer-serve --config /srv/morph/alice/signer.json \
  --private-key-file /srv/morph/keys/alice.key
# From the ceremony process:
morph-cli multi-asset-session --session /srv/morph/alice.json sign --target update \
  --signer-config /srv/morph/alice/signer.json
```

Keep the directory, file and backups outside public evidence, source control,
logs and shared artifact directories. A key file does not replace the monotonic
signer journal; never restore an older journal or duplicate active authority.

The loader opens an ordinary file without following a leaf symlink and checks
the opened descriptor. It requires the current effective user's ownership and
no group or other permission bits: 0600 and 0400 are accepted; 0640, 0644 and
0777 are rejected. It rejects symlinks, directories, FIFOs and other special
files. The containing directory must also remain under the operator's control.
The CLI does not chmod or copy an explicitly selected file to repair unsafe
permissions. Provision an appropriately protected file before retrying.

The complete file is limited to 256 bytes, including surrounding whitespace.
It must contain one UTF-8 key with optional surrounding ASCII whitespace and no
embedded whitespace, NUL bytes or extra tokens. For secp256k1, use exactly 64 hex
digits with an optional `0x` prefix; zero and out-of-range scalars are rejected.
Biscuit roots use `ed25519-private/` or `secp256r1-private/` followed by 64 hex
digits. Use the format emitted by Morph Payment Gateway's explicit
`generate-key` operation.

Protected input is currently supported only on Linux filesystems enforcing the
checked ownership and POSIX permissions. Other platforms, including macOS, fail
closed. Mode bits alone do not establish equivalent confidentiality on macOS:
[Apple documents ACL grants evaluated before BSD permission fallback](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html).
A future platform implementation must validate its effective ACL boundary before
enabling key loading. Errors do not include file contents. In Rust, `SecretString` Debug output
is redacted and its owned storage is zeroized on drop; this does not guarantee
erasure of OS caches, swap or memory retained by upstream signing libraries.

Bilateral operational `sign` accepts `--signer-config`, not a private-key file.
Only the isolated service receives its protected key file. `sign-local` requires
the devnet build and is an explicit development choice, never a fallback.
See [external participant signing](external-participant-signer.md).

## Select the signing role

| Use | File option | Environment path |
| --- | --- | --- |
| Factory, child and delivery signing; explicit bilateral `sign-local` development command | `--private-key-file` | `MORPH_CHANNEL_PRIVATE_KEY_FILE` |
| Isolated participant service | `--private-key-file` | Explicit option |
| Devnet wallet or operator | `--private-key-file` | `MORPH_DEVNET_PRIVATE_KEY_FILE` |
| Devnet participant fixtures | `--alice-private-key-file`, `--bob-private-key-file` | `MORPH_ALICE_PRIVATE_KEY_FILE`, `MORPH_BOB_PRIVATE_KEY_FILE` |
| Hub signed invoices | `--invoice-private-key-file` | `MORPH_HUB_INVOICE_PRIVATE_KEY_FILE` |
| Invoice creation | `--payee-private-key-file` | Explicit option |
| Payment Gateway credential authority | `--biscuit-private-key-file` | `MORPH_PAYMENT_GATEWAY_BISCUIT_PRIVATE_KEY_FILE` |
| Payment Gateway receipts | `--receipt-private-key-file` | `MORPH_PAYMENT_GATEWAY_RECEIPT_PRIVATE_KEY_FILE` |

The command's `--help` identifies which role it needs. Supply only the key for
that role; participants and wallet signers retain independent authority.

## Disposable development fixtures

The native, publication-reliability and Fiber acceptance harnesses may stage
public, no-value development fixture files in a `mktemp` 0700 directory, with
0600 key files and exit cleanup. The directory is outside their public evidence
tree. A supplied `*_PRIVATE_KEY_FILE` path goes directly to the protected loader
and retains all permission checks. `MORPH_E2E_*_KEY_FILE` and
`MORPH_FIBER_*_KEY_FILE` select public fixture sources for these harnesses; do not
use their fixture-copy path for deployment credentials.

For an isolated development-only public fixture:

```sh
umask 077
key_dir="$(mktemp -d)"
trap 'rm -rf -- "$key_dir"' EXIT
printf '%064x\n' 2 >"$key_dir/fixture.key"
MORPH_DEVNET_PRIVATE_KEY_FILE="$key_dir/fixture.key" \
  morph-cli devnet --devnet-only derive-operator-pubkey --json
```

The scalar above is public and must never receive real assets. Morph Payment
Gateway's `generate-key` and `generate-receipt-key` intentionally return newly generated
material on stdout; capture that output privately. Its Fiber test harness uses
shell builtin `printf` to persist generated keys to 0600 files and passes only
paths to child processes. The SDK Fiber test accepts
`MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY_FILE`, applies the same safe-open,
owner, permission, size and scalar checks, and rejects the former raw-key
environment input.
