#ifndef KDC_H
#define KDC_H

#include <map>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <string>

#include "ecies/ecies.h"
#include "httpimpl/client_http.hpp"
#include "configparser/configparser.h"

using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;

class KDC {

public:
    KDC();
    void GenKeyAndDistribute();

private:
    int mVerifierOpenPort;
    int mProoferOpenPort;
    ConfigParser mConfigParser;
    std::vector<std::string> mVerifierIPList;
    std::string mProoferIP;
    char* mPublicKey;
    char* mPrivateKey;
};

#endif
