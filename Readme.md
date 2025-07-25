## Install dependencies

On a Linux system with a TPM 2.0 chip:

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libsodium-dev libsecp256k1-dev tpm2-tools
```

Make sure TPM is initialized:

```bash
tpm2_getrandom 8
```

*(Should print random bytes without error.)*

---

## Unpack and Build

```bash
unzip secure-sign-service.zip
cd secure-sign-service
mkdir build && cd build
cmake ..
make -j$(nproc)
```

This produces:

- `secure_sign_service` – the daemon
- `client` – the IPC test client

---

## Prepare Storage Directory

```bash
sudo mkdir -p /etc/secure/keys
sudo chmod 700 /etc/secure/keys
```

---

## Run the service

```bash
sudo ./secure_sign_service
```

- Runs as root (needed for TPM access and `/etc/secure/keys`).
- Creates `/tmp/sign_service.sock` with `0700` permissions.
- Checks for TPM persistent key handle `0x81000001`.
    - If missing, automatically creates and persists one.

---

## Store a private key

Use the client to send your key to the service.

- Keys must be hex-encoded (e.g., 64 bytes for Ed25519).

Example (fake Ed25519 key):

```bash
./client STORE_KEY ed25519 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
```

Response:

```text
Response: OK
```

The key is now encrypted with the TPM and stored at `/etc/secure/keys/ed25519.key`.

---

## Sign data

Send arbitrary data in hex to be signed:

```bash
./client SIGN ed25519 112233445566
```

Response:

```text
Response: <hex signature>
```

---

## Notes

- secp256k1 keys are stored the same way:
        ```bash
        ./client STORE_KEY secp256k1 <hex private key>
        ./client SIGN secp256k1 <hex data>
        ```
- Memory holding decrypted keys is `mlock()`’d and wiped after signing.
- The service runs until stopped with `Ctrl+C`.