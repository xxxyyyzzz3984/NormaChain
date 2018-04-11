#ifndef ECCVERIFY_H
#define ECCVERIFY_H

#include <iostream>
#include <map>
#include <sstream>
#include <fstream>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <time.h>
#include <cstdio>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <unistd.h>

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
    static int mOpenPort;
    static std::string mPublicKey;
    static std::string mCorrectAns;
    static bool mSelfDecision;
    static std::vector<bool> mAllConsortNodesDecisions;
    static std::vector<std::string> mConsortiumNodeIPs;
    std::string mInterface;
    static std::string mLocalIPv4;
    void getLocalIPv4();
    static void sendDecision2OtherConsortiumVerifiers();
    static void parse_consortium_nodes(std::string nodes_str);
};

#endif
