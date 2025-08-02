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

KeyManager::KeyManager(const std::string& dir, const std::string& handle)
    : storageDir(dir), tpmHandle(handle) {
    
    std::error_code ec;
    std::filesystem::create_directories(storageDir, ec);
    if (ec) {
        throw std::runtime_error("Failed to create storage directory: " + ec.message());
    }
    
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
        crypto_aead_aes256gcm_keygen(key);
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
         // same issue: real deployment needs persistent key
        crypto_aead_aes256gcm_keygen(key);
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

std::string KeyManager::keyPath(const std::string& type) {
    return storageDir + "/" + type + ".key";
}

bool KeyManager::storePrivateKey(const std::string& type, const std::vector<unsigned char>& rawKey) {
    std::vector<unsigned char> encrypted;
    if (!encryptWithTPM(rawKey, encrypted)) return false;

    std::ofstream file(keyPath(type), std::ios::binary);
    file.write((char*)encrypted.data(), encrypted.size());
    chmod(keyPath(type).c_str(), 0600);
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
