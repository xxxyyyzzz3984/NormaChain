#include "eccverf/EccVerf.h"

using namespace CryptoPP;
using namespace std;

void test() {
    AutoSeededRandomPool prng;
    ECIES<ECP>::Decryptor d0(prng, ASN1::secp256r1());
    PrintPrivateKey(d0.GetKey());
}

void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out)
{
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Base precomputation (for public key calculation from private key)
    const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
    // Public Key (just do the exponentiation)
    const ECPPoint point = bpc.Exponentiate(params.GetGroupPrecomputation(), key.GetPrivateExponent());

    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;

    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;

    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;

    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;

    out << "Private Exponent (multiplicand): " << endl;
    out << "  " << std::hex << key.GetPrivateExponent() << endl;
}


