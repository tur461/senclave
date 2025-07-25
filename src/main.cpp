#include "KeyManager.h"
#include "IPCServer.h"
#include <sodium.h>

int main() {
    if (sodium_init() < 0) return 1;
    KeyManager km("/etc/secure/keys", "0x81000001");
    IPCServer server("/tmp/sign_service.sock", km);
    server.run();
    return 0;
}
