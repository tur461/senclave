#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: client <STORE_KEY|SIGN> <type> <hexdata>\n";
        return 1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/sign_service.sock");

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    std::string msg = std::string(argv[1]) + " " + argv[2] + " " + argv[3];
    write(fd, msg.c_str(), msg.size());

    char buffer[4096];
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n > 0) std::cout << "Response: " << std::string(buffer, buffer + n) << "\n";

    close(fd);
    return 0;
}
