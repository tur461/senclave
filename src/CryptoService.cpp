#include "CryptoService.h"
#include <iostream>
#include <sodium.h>
#include <sys/mman.h>
#include <secp256k1.h>


CryptoService::CryptoService(const std::vector<unsigned char>& k, const std::string& t)
    : key(k), type(t) {}

std::vector<unsigned char> CryptoService::signData(const std::vector<unsigned char>& data) {
    std::cout << "Signing with key size: " << key.size() << " bytes, data size: " << data.size() << " bytes\n";

    if (type == "ed25519") {
        if (key.size() != crypto_sign_SECRETKEYBYTES) {
            throw std::runtime_error("Invalid Ed25519 key size: " + std::to_string(key.size()));
        }
        std::vector<unsigned char> sig(crypto_sign_BYTES);
        crypto_sign_detached(sig.data(), nullptr, data.data(), data.size(), key.data());
        return sig;
    } else if (type == "secp256k1") {
        unsigned char msg_hash[32];

        crypto_generichash(msg_hash, sizeof(msg_hash), data.data(), data.size(), nullptr, 0);
        
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        secp256k1_ecdsa_signature signature;
        
        if (!secp256k1_ecdsa_sign(ctx, &signature, msg_hash, key.data(), nullptr, nullptr)) {
            secp256k1_context_destroy(ctx);
            return {};
        }
        
        unsigned char sig[64];
        secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &signature);
        secp256k1_context_destroy(ctx);
        return std::vector<unsigned char>(sig, sig + 64);
    }
    return {};
}

void CryptoService::secureErase() {
    sodium_memzero(key.data(), key.size());
    munlock(key.data(), key.size());
    key.clear();
}
