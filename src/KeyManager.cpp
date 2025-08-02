#include "KeyManager.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <sys/mman.h>
#include <cstdlib>
#include <sodium.h>
#include <unistd.h>
#include <cstring>

static bool hasTPM() {
    #ifdef __APPLE__
        return false; // TPM not supported on macOS
    #else
        return (system("which tpm2_encryptdecrypt >/dev/null 2>&1") == 0);
    #endif
}

KeyManager::KeyManager(const std::string& path, const std::string& tpmHandle)
    : keyFilePath(path), tpmHandle(tpmHandle) {
    if(hasTPM()) {
        ensurePersistentKey();
    }
}

KeyManager::KeyManager(const std::string& path)
    : KeyManager::KeyManager(path, DEFAULT_TMP_HANDLE) {
    if(hasTPM()) {
        ensurePersistentKey();
    }
}

bool KeyManager::ensurePersistentKey() {
    std::stringstream checkCmd;
    checkCmd << "tpm2_readpublic -c " << tpmHandle << " >/dev/null 2>&1";
    if (system(checkCmd.str().c_str()) == 0) return true;

    std::cerr << "[TPM] Persistent key not found. Creating...\n";
    std::string cmd =
        "tpm2_createprimary -C o -G rsa -c primary.ctx && "
        "tpm2_evictcontrol -C o -c primary.ctx " + tpmHandle;
    return (system(cmd.c_str()) == 0);
}

bool KeyManager::encryptWithTPM(const std::vector<unsigned char>& in, std::vector<unsigned char>& out) {
    if (!hasTPM()) {
        // Fallback: AES-256-GCM with libsodium
        unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
        std::string secret = FALLBACK_SECRET;
        crypto_generichash(key, sizeof key,
                   reinterpret_cast<const unsigned char*>(secret.data()), secret.size(),
                   nullptr, 0);
        // crypto_aead_aes256gcm_keygen(key);
        unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
        randombytes_buf(nonce, sizeof nonce);

        std::vector<unsigned char> ciphertext(in.size() + crypto_aead_aes256gcm_ABYTES + sizeof nonce);
        memcpy(ciphertext.data(), nonce, sizeof nonce);

        unsigned long long clen;
        crypto_aead_aes256gcm_encrypt(ciphertext.data() + sizeof nonce, &clen,
                                      in.data(), in.size(),
                                      nullptr, 0, nullptr, nonce, key);

        ciphertext.resize(clen + sizeof nonce);
        out = ciphertext;
        sodium_memzero(key, sizeof key);
        return true;
    }

    std::string infile = "/tmp/tpm_in.bin", outfile = "/tmp/tpm_out.bin";
    std::ofstream fi(infile, std::ios::binary);
    fi.write((char*)in.data(), in.size());
    fi.close();

    std::stringstream cmd;
    cmd << "tpm2_encryptdecrypt -c " << tpmHandle << " -o " << outfile << " " << infile;
    if (system(cmd.str().c_str()) != 0) return false;

    std::ifstream fo(outfile, std::ios::binary);
    out.assign((std::istreambuf_iterator<char>(fo)), {});
    std::remove(infile.c_str());
    std::remove(outfile.c_str());
    return true;
}

bool KeyManager::decryptWithTPM(const std::vector<unsigned char>& in, std::vector<unsigned char>& out) {
    if (!hasTPM()) {
        // Fallback: AES-256-GCM decrypt (nonce is prepended to ciphertext)
        const unsigned char *nonce = in.data();
        const unsigned char *ciphertext = in.data() + crypto_aead_aes256gcm_NPUBBYTES;
        unsigned long long clen = in.size() - crypto_aead_aes256gcm_NPUBBYTES;

        unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
        std::string secret = FALLBACK_SECRET;

        crypto_generichash(key, sizeof key,
                   reinterpret_cast<const unsigned char*>(secret.data()), secret.size(),
                   nullptr, 0);
         // same issue: real deployment needs persistent key
        // crypto_aead_aes256gcm_keygen(key);
        out.resize(clen - crypto_aead_aes256gcm_ABYTES);

        unsigned long long decrypted_len;
        if (crypto_aead_aes256gcm_decrypt(out.data(), &decrypted_len,
                                          nullptr,
                                          ciphertext, clen,
                                          nullptr, 0,
                                          nonce, key) != 0) {
            sodium_memzero(key, sizeof key);
            return false;
        }
        out.resize(decrypted_len);
        sodium_memzero(key, sizeof key);
        return true;
    }
    // Symmetric decryption uses same command
    return encryptWithTPM(in, out);
}


// modify this to return the path to the key stored in the keymanager object
std::string KeyManager::keyPath(const std::string& type) {
    return keyFilePath;
}

bool KeyManager::encryptPrivateKeyFile() {
    std::string path = keyPath("");

    // Open the file for reading
    std::ifstream fileR(path, std::ios::binary);
    if (!fileR.is_open()) {
        std::cerr << "Failed to open file for reading: " << path << std::endl;
        return false;
    }

    // Read the file into rawKey
    std::vector<unsigned char> rawKey((std::istreambuf_iterator<char>(fileR)), {});
    fileR.close();

    // Encrypt
    std::vector<unsigned char> encrypted;
    if (!encryptWithTPM(rawKey, encrypted)) {
        std::cerr << "Encryption failed\n";
        return false;
    }

    // Write encrypted data back to same file
    std::ofstream fileW(path, std::ios::binary | std::ios::trunc);
    if (!fileW.is_open()) {
        std::cerr << "Failed to open file for writing: " << path << std::endl;
        return false;
    }

    fileW.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    fileW.close();

    // Set file permissions
    if (chmod(path.c_str(), 0600) != 0) {
        perror("chmod failed");
        return false;
    }

    return true;
}

bool KeyManager::decryptPrivateKeyFile() {
    std::string path = keyPath("");

    // Open the file for reading
    std::ifstream fileR(path, std::ios::binary);
    if (!fileR.is_open()) {
        std::cerr << "Failed to open file for reading: " << path << std::endl;
        return false;
    }

    // Read the file into encrypted buffer
    std::vector<unsigned char> encrypted((std::istreambuf_iterator<char>(fileR)), {});
    fileR.close();

    // Decrypt
    std::vector<unsigned char> decrypted;
    if (!decryptWithTPM(encrypted, decrypted)) {
        std::cerr << "Decryption failed\n";
        return false;
    }

    // Write decrypted data back to same file
    std::ofstream fileW(path, std::ios::binary | std::ios::trunc);
    if (!fileW.is_open()) {
        std::cerr << "Failed to open file for writing: " << path << std::endl;
        return false;
    }

    fileW.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    fileW.close();

    // Set secure permissions
    if (chmod(path.c_str(), 0600) != 0) {
        perror("chmod failed");
        return false;
    }

    return true;
}



std::vector<unsigned char> KeyManager::loadPrivateKey(const std::string& type) {
    std::cout << "Loading private key of type: " << type << std::endl;
    std::cout << "Key path: " << keyPath(type) << std::endl;

    std::ifstream file(keyPath(type), std::ios::binary);
    std::vector<unsigned char> encrypted((std::istreambuf_iterator<char>(file)), {});
    std::vector<unsigned char> decrypted;
    std::cout << "Encrypted key size: " << encrypted.size() << " bytes\n";
    decryptWithTPM(encrypted, decrypted);
    std::cout << "Decrypted key size: " << decrypted.size() << " bytes\n";
    mlock(decrypted.data(), decrypted.size());
    std::cout << "Key loaded and locked in memory\n";
    return decrypted;
}
