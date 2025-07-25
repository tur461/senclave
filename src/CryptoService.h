#pragma once
#include <vector>
#include <string>

class CryptoService {
public:
    CryptoService(const std::vector<unsigned char>& key, const std::string& type);
    std::vector<unsigned char> signData(const std::vector<unsigned char>& data);
    void secureErase();
private:
    std::vector<unsigned char> key;
    std::string type;
};
