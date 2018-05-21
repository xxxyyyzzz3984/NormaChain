#ifndef APPROVER_H
#define APPROVER_H

#include <string>
#include <vector>
#include <map>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>

#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "configparser/configparser.h"
#include "httpimpl/server_http.hpp"
#include "httpimpl/client_http.hpp"
#include "configparser/configparser.h"
#include "contract/contract.h"
#include "agent/agent.h"

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;

using namespace std;
using namespace boost::property_tree;

class Approver
{
public:
    Approver();
    Approver(string approver_info_filepath, string approver_list_filepath, string agent_info_filepath);
    void Load_Files(string approver_info_filepath, string approver_list_filepath, string agent_info_filepath);
    void setAddr(string Addr);
    void setIPAddr(string IPAddr);
    void setOpenPort(string openport);
    string getAddr();
    string getIPAddr();
    string getOpenPort();
    void serve();

private:
    string mSelfAddr;
    string mSelfOpenPort;
    string mSelfIPAddr;
    vector<Approver> mApproverList;
    void __waitforContract(HttpServer& serve);
    void __waitforApprovalRequest(HttpServer& server);
    void __waitforOtherDecisions(HttpServer& server);
    void __send_contract2agent();
    void __sendApprovalRequest();
    void __sendDecision2Others();
    Contract mContract;
    bool mDecision;
    string mDecision4Buyer;
    string mApproveRequestor;
    vector<bool>mAllApproverDecisions;
    Agent mAgent;
};

#endif
