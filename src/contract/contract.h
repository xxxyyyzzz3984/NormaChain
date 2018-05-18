#ifndef CONTRACT_H
#define CONTRACT_H

#include <string>
#include <ctime>
#include <map>
#include <iostream>
#include <sstream>
#include <boost/serialization/access.hpp>

#include "configparser/configparser.h"

using namespace std;

class Contract
{
public:
    Contract(string contract_path);
    Contract(uint64_t transaction_id, string buyer_addr,
             string seller_addr, double price, time_t transaction_timestamp,
             string description, string product);
    Contract();
    void parseContract(string contract_path);

    string getBuyerAddr();
    string getSellerAddr();
    string getProductInfo();
    double_t getPrice();
    time_t getTimeStamp();
    string getDescription();
    uint64_t getTransactionID();
    string genContractFileStr(uint64_t transaction_id, string buyer_addr,
                              string seller_addr, double price, time_t transaction_timestamp,
                              string description, string product);

    string genContractFileStr();

    Contract genContract(uint64_t transaction_id, string buyer_addr,
                                   string seller_addr, double price, time_t transaction_timestamp,
                                   string description, string product);
    Contract genContract();
    void setTransactionID(uint64_t ID);



private:
    friend class boost::serialization::access;
    uint64_t mTransactionID;
    string mBuyerAddr;
    string mSellerAddr;
    string mProduct;
    double_t mPrice;
    time_t mTransactionTimeStamp;
    string mDescription;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & mTransactionID;
        ar & mBuyerAddr;
        ar & mSellerAddr;
        ar & mProduct;
        ar & mPrice;
        ar & mTransactionTimeStamp;
        ar & mDescription;
    }
};

#endif
