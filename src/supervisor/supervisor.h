#ifndef SUOERVISOR_H
#define SUOERVISOR_H

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>

#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "agent/agent.h"
#include "httpimpl/client_http.hpp"

using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;
using namespace std;
using namespace boost::property_tree;

class Supervisor
{
public:
    Supervisor(string agent_info_path);
    void Load_Agent_Info(string agent_info_path);
    void SearchKeyword(string keyword);

private:
    Agent mAgent;
};

#endif
