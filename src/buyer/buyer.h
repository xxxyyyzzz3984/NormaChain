#ifndef BUYER_H
#define BUYER_H

#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "configparser/configparser.h"
#include "contract/contract.h"
#include "seller/seller.h"
#include "httpimpl/client_http.hpp"

using namespace std;
using namespace boost::property_tree;

using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;

class Buyer
{
public:
    Buyer();
    Buyer(string Buyer_Info_File, string Sell_List_File);
    void Load_Info_File(string Buyer_Info_File, string Sell_List_File);
    void Transact(int seller_index, string product, string description);

private:
    string mSelfAddr;
    string mSelfIPAddr;
    vector<Seller> mSellerList;
    Contract mSelfContract;
    time_t mTimestamp;
    static double price;
    double __request_purchase(int seller_index, string product, string description);
    void __gen_contract(int seller_index, string product, double_t price,string description, time_t timestamp);
};

#endif
