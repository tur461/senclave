#pragma once
#include "Constants.h"
#include <string>
#include <vector>

class KeyManager {
public:
    KeyManager(const std::string& path);
    KeyManager(const std::string& path, const std::string& handle);

    bool encryptPrivateKeyFile();
    bool decryptPrivateKeyFile();
    std::vector<unsigned char> loadPrivateKey(const std::string& type);

private:
    std::string keyFilePath;
    std::string tpmHandle;

    bool ensurePersistentKey();
    bool encryptWithTPM(const std::vector<unsigned char>& in, std::vector<unsigned char>& out);
    bool decryptWithTPM(const std::vector<unsigned char>& in, std::vector<unsigned char>& out);
    std::string keyPath(const std::string& type);
};

