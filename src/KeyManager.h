#pragma once
#include <string>
#include <vector>

class KeyManager {
public:
    KeyManager(const std::string& storageDir, const std::string& tpmHandle = "0x81000001");
    bool storePrivateKey(const std::string& type, const std::vector<unsigned char>& rawKey);
    std::vector<unsigned char> loadPrivateKey(const std::string& type);
private:
    std::string storageDir;
    std::string tpmHandle;
    bool ensurePersistentKey();
    bool encryptWithTPM(const std::vector<unsigned char>& in, std::vector<unsigned char>& out);
    bool decryptWithTPM(const std::vector<unsigned char>& in, std::vector<unsigned char>& out);
    std::string keyPath(const std::string& type);
};
