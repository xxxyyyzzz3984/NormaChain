#ifndef SELLER_H
#define SELLER_H

#include <string>
#include <map>
#include <vector>
#include <sstream>

#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>


#include "configparser/configparser.h"
#include "httpimpl/server_http.hpp"

using namespace std;
using namespace boost::property_tree;

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;

class Seller
{
public:
    Seller();
    Seller(string seller_info_filepath);
    void Load_Seller_Info(string seller_info_filepath);

    void setAddr(string Addr);
    void setIPAddr(string IPAddr);
    void setOpenPort(string openport);
    string getAddr();
    string getIPAddr();
    string getOpenPort();

    double getPrice(string product);
    void waitforTransaction();

private:
    string mAddr;
    string mIPAddr;
    string mOpenPort;
    vector<string> mProductList;
    map<string, double> mProductMap;

};

#endif
