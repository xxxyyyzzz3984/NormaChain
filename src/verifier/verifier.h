#ifndef ECCVERIFY_H
#define ECCVERIFY_H

#include <iostream>
#include <map>
#include <sstream>
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

class Verifier
{

public:
    Verifier();
    void Serve();
private:
    ConfigParser mConfigParser;
    int mOpenPort;
    static std::string mPublicKey;
    static std::string mCorrectAns;
    static bool mSelfDecision;
};

#endif
