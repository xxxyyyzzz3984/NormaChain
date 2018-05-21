#ifndef AGENT_H
#define AGENT_H

#include <string>
#include <gmp.h>
#include <pbc/pbc.h>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/foreach.hpp>

#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "peks/peks.h"
#include "contract/contract.h"
#include "httpimpl/server_http.hpp"
#include "configparser/configparser.h"

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using namespace std;
using namespace boost::property_tree;

class Agent
{
public:
    Agent();
    Agent(string agent_info_path);
    void setIPAddr(string IPAddr);
    void setAddr(string Addr);
    void setOpenPort(string OpenPort);
    string getIPAddr();
    string getAddr();
    string getOpenPort();
    void Load_Agent_Info(string path);
    void serve();

private:
    map<uint64_t, vector<element_s>> mContract2TrapdoorMap;
    key mKey;
    pbc_param_t mParam;
    pairing_t mPairing;
    string mIPAddr;
    string mAddr;
    string mOpenPort;

    void __encrypt_contract(Contract contract);
    vector<Contract> mRecvContractList;
    void __recv_contract(HttpServer& server);
    void __recv_searchrequest(HttpServer& server);
    vector<uint64_t> __search_keyword(string keyword);
};

#endif
