#include "CryptoService.h"
#include <iostream>
#include <sodium.h>
#include <sys/mman.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>


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
        // unsigned char msg_hash[32];

        // // crypto_generichash(msg_hash, sizeof(msg_hash), data.data(), data.size(), nullptr, 0);
        // // this above line is commented out for signing safeTxnHash for gnosis safe
        // // and below check is for the same thing
        // if (data.size() != 32) {
        //     throw std::runtime_error("Expected 32-byte hash for secp256k1 signing");
        // }

        // secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        // secp256k1_ecdsa_signature signature;
        
        // if (!secp256k1_ecdsa_sign(ctx, &signature, msg_hash, key.data(), nullptr, nullptr)) {
        //     secp256k1_context_destroy(ctx);
        //     return {};
        // }
        
        // unsigned char sig[64];
        // secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &signature);
        // secp256k1_context_destroy(ctx);
        // return std::vector<unsigned char>(sig, sig + 64);

        if (data.size() != 32) {
            throw std::runtime_error("Expected 32-byte hash for secp256k1 signing");
        }

        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        secp256k1_ecdsa_signature signature;

        if (!secp256k1_ecdsa_sign(ctx, &signature, data.data(), key.data(), nullptr, nullptr)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to sign data");
        }

        // Serialize signature to compact form (64 bytes: r || s)
        unsigned char sig64[64];
        secp256k1_ecdsa_signature_serialize_compact(ctx, sig64, &signature);

        // Recover the public key to calculate v (27 or 28)
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key.data())) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to derive public key");
        }

        int recid = -1;
        secp256k1_ecdsa_recoverable_signature recoverable_sig;
        if (!secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_sig, data.data(),
                                            key.data(), nullptr, nullptr)) {
            secp256k1_context_destroy(ctx);
            throw std::runtime_error("Failed to create recoverable signature");
        }
        secp256k1_ecdsa_recoverable_signature_convert(ctx, &signature, &recoverable_sig);
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig64, &recid, &recoverable_sig);

        secp256k1_context_destroy(ctx);

        // Append v = recid + 27
        unsigned char v = static_cast<unsigned char>(recid + 27);

        std::vector<unsigned char> fullSig(sig64, sig64 + 64);
        fullSig.push_back(v);  // Add v as the 65th byte

        return fullSig; // r || s || v
    }
    return {};
}

void CryptoService::secureErase() {
    sodium_memzero(key.data(), key.size());
    munlock(key.data(), key.size());
    key.clear();
}
