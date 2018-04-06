#ifndef PROOFER_H
#define PROOFER_H

#include <map>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>


#include "ecies/ecies.h"
#include "httpimpl/server_http.hpp"
#include "httpimpl/client_http.hpp"
#include "configparser/configparser.h"

// JSON library
#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;


class CryptexParts{
public:
    CryptexParts();
    std::string crpytbody;
    int cryptbody_len;
    std::string cryptkey;
    int cryptkey_len;
};

class Proofer
{

public:
    Proofer();
    void StartProof();

private:
    ConfigParser mConfigParser;
    int mVerifierOpenPort;
    int mProoferOpenPort;
    std::vector<std::string> mVerifierIPList;
    static void do_verify(std::string IP_Addr, std::string port);
    static std::string mPrivKey;
    static int mMyAnswer;
};



#endif
