#pragma once
#include <string>
#include "KeyManager.h"

class IPCServer {
public:
    IPCServer(const std::string& socketPath, KeyManager& km);
    void run();
private:
    std::string socketPath;
    KeyManager& keyManager;
};
