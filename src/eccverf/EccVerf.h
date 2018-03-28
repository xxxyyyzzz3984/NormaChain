#include <iostream>
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"

using namespace CryptoPP;
using namespace std;

void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out = cout);
void test();
