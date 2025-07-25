#include "IPCServer.h"
#include "CryptoService.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <sodium.h>
#include <sys/stat.h> 
#include<pwd.h>

void dropPrivileges(const char* username = "nobody") {
    struct passwd* pw = getpwnam(username);
    if (pw) {
        if (setuid(pw->pw_uid) != 0) {
            std::cerr << "Failed to drop privileges to " << username << std::endl;
            exit(1);
        }
    }
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Hex string must have even length");
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}

IPCServer::IPCServer(const std::string& path, KeyManager& km)
    : socketPath(path), keyManager(km) {}

// static std::vector<unsigned char> hexToBytes(const std::string& hex) {
//     std::vector<unsigned char> bytes;
//     for (unsigned int i = 0; i < hex.length(); i += 2) {
//         std::string byteString = hex.substr(i, 2);
//         unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
//         bytes.push_back(byte);
//     }
//     return bytes;
// }

void IPCServer::run() {
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
    unlink(socketPath.c_str());
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    chmod(socketPath.c_str(), 0666);
     // Drop privileges to 'nobody' or specified user
    // dropPrivileges();
    listen(server_fd, 5);

    std::cout << "Listening on " << socketPath << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        char buffer[4096];
        ssize_t n = read(client_fd, buffer, sizeof(buffer));
        
        if (n <= 0) {
            close(client_fd);
            continue;
        }
        
        std::string cmd(buffer, buffer + n);
        
        if (cmd.size() > 4096) {
            write(client_fd, "FAIL: Command too long", 22);
            close(client_fd);
            continue;
        }
        
        std::istringstream iss(cmd);
        std::string action, type, hexdata;
        iss >> action >> type >> hexdata;

        if (action != "STORE_KEY" && action != "SIGN") {
            write(client_fd, "FAIL: Invalid action", 19);
            close(client_fd);
            continue;
        }

        if (type.empty() || type.size() > 32) {
            write(client_fd, "FAIL: Invalid type", 18);
            close(client_fd);
            continue;
        }

        if (hexdata.empty() || hexdata.size() > 4096) {
            write(client_fd, "FAIL: Invalid hexdata", 21);
            close(client_fd);
            continue;
        }
        // Validate hexdata contains only hex chars
        if (hexdata.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
            write(client_fd, "FAIL: Non-hex data", 18);
            close(client_fd);
            continue;
        }

        if (action == "STORE_KEY") {
            auto rawKey = hexToBytes(hexdata);
            bool ok = keyManager.storePrivateKey(type, rawKey);
            write(client_fd, ok ? "OK" : "FAIL", ok ? 2 : 4);
        } else if (action == "SIGN") {
            try {
                std::cout << "raw data size: " << hexdata.size() << " bytes\n";

                auto data = hexToBytes(hexdata);

                std::cout << "data size: " << data.size() << " bytes\n";

                if (data.empty()) {
                    write(client_fd, "FAIL: No data to sign", 22);
                    close(client_fd);
                    continue;
                }
                std::cout << "loading pvt key..\n";

                auto privKey = keyManager.loadPrivateKey(type);
                std::cout << "pvt key" << (privKey.empty() ? " not found" : " loaded") << "\n";

                if (privKey.empty()) {
                    write(client_fd, "FAIL: Key not found", 19);
                    close(client_fd);
                    continue;
                }
                CryptoService crypto(privKey, type);
                std::cout << "signing data...\n";
                auto sig = crypto.signData(data);
                std::cout << "signature size: " << sig.size() << " bytes\n";
                std::cout << "secure erasing key...\n";
                crypto.secureErase();
                std::cout << "key erased\n";

                std::ostringstream oss;
                for (unsigned char c : sig) oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
                auto sigHex = oss.str();
                write(client_fd, sigHex.c_str(), sigHex.size());
            } catch (const std::exception& e) {
                // send error back to client instead of crashing
                write(client_fd, e.what(), strlen(e.what()));
            }
            
        }
        close(client_fd);
    }
}
