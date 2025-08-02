#include "KeyManager.h"
#include "IPCServer.h"
#include <sodium.h>
#include <iostream>

void print_usage(const char* prog_name) {
    std::cerr << "Usage:\n"
              << "  " << prog_name << " enc <file>       # Encrypt private key file\n"
              << "  " << prog_name << " dec <file>       # Decrypt private key file\n"
              << "  " << prog_name << " run <key_path>   # Run with key path\n"
              << "  " << prog_name << " -h | --help      # Show help\n";
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        std::string arg1 = argv[1];
        if (arg1 == "-h" || arg1 == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Error: Invalid arguments.\n";
            print_usage(argv[0]);
            return 1;
        }
    } else if (argc == 3) {
        std::string command = argv[1];
        std::string filePath = argv[2];

        if (command == "enc") {
            KeyManager km(filePath);  
            if (!km.encryptPrivateKeyFile()) { // adjust args as needed
                std::cerr << "Encryption failed.\n";
                return 1;
            }
            std::cout << "File encrypted successfully.\n";
            return 0;
        } else if (command == "dec") {
            KeyManager km(filePath);  
            if (!km.decryptPrivateKeyFile()) { // adjust args as needed
                std::cerr << "Decryption failed.\n";
                return 1;
            }
            std::cout << "File decrypted successfully.\n";
            return 0;
        } else if (command == "run") {
            if (sodium_init() < 0) {
                std::cerr << "Error initializing libsodium.\n";
                return 1;
            }

            KeyManager km(filePath, "0x81000001");
            IPCServer server("/tmp/sign_service.sock", km);
            server.run();
            return 0;
        } else {
            std::cerr << "Error: Unknown command '" << command << "'.\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    std::cerr << "Error: Too many or too few arguments.\n";
    print_usage(argv[0]);
    return 1;
}
