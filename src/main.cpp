#include "ecies/ecies.h"
#include "eccverify/eccverify.h"
#include "configparser/configparser.h"

using namespace std;

int main()
{
    ecies_example();
    ECCVerifier eccverf = ECCVerifier();
    eccverf.Serve();
	return 1;
}
