# Portable FreeBSD `geli`

## Supported Algorithms
- AES-XTS (128/256 key size)

## Supported Operations
- `dump`
- `init`
- `label`
- `attach`
- `backup`
- `restore`
- `resize`
- `version`

## Unsupported Encryption Algorithms
- AES-CBC
- Camellia-CBC
- NULL

## TODO
- Add support for **Authentication**.
- Add support for `setkey` and `delkey` commands.
