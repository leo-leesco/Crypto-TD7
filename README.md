# FrodoKEM implementation

Please check the latest version on [GitHub](https://github.com/leo-leesco/Crypto-TD7).

## Build

`cargo build` produces `frodokeygen`, `frodoencaps` and `frododecaps` in `target/debug`.

If you want the optimized version, run `cargo build --release`, and the executables can then be found in `target/release`.

## Requirements

`frodokeygen` expects and writes to :

- `<publickey_file_path>`
- `<secretkey_file_path>`

`frodoencaps` expects :

- `<publickey_file_path>`
- `<ciphertext_file_path>` (written to)
- `<sharedsecretkey_file_path>` (written to)

`frododecaps` expects :

- `<privatekey_file_path>`
- `<ciphertext_file_path>`
- `<sharedsecretkey_file_path>` (written to)

## Theoretical framework
