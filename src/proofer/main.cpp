#include "proofer.h"

int main() {
    Proofer proofer = Proofer();
    proofer.Wait4PrivateKey();
    usleep(2000);
    proofer.StartProof();
    return 1;
}
