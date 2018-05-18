#include "contract.h"

using namespace std;

Contract::Contract() {

}

Contract::Contract(string contract_path) {
    parseContract(contract_path);
}

Contract::Contract(uint64_t transaction_id, string buyer_addr,
                   string seller_addr, double price, time_t transaction_timestamp,
                   string description, string product) {

    this->mTransactionID = transaction_id;
    this->mBuyerAddr = buyer_addr;
    this->mSellerAddr = seller_addr;
    this->mPrice = price;
    this->mTransactionTimeStamp = transaction_timestamp;
    this->mDescription = description;
    this->mProduct = product;
}

// Parse the contract file
void Contract::parseContract(string contract_path) {
    ConfigParser contract_parser = ConfigParser();
    contract_parser.OpenFile(contract_path);
    map<string, string> parsed_map = contract_parser.Parse();

    if(parsed_map.size() >= 1) {
        mBuyerAddr = parsed_map["BUYER_ADDR"];
        mSellerAddr = parsed_map["SELLER_ADDR"];
        mProduct = parsed_map["PRODUCT"];
        mDescription = parsed_map["DESCRIPTION"];

        stringstream geek1(parsed_map["PRICE"]);
        geek1 >> this->mPrice;

        stringstream geek2(parsed_map["TRANSACTION_TIMESTAMP"]);
        geek2 >> this->mTransactionTimeStamp;

        stringstream geek3(parsed_map["TRANSACTION_ID"]);
        geek3 >> this->mTransactionID;

    }

    else {
            cout << "Contract file parse fails !!" << endl;
    }
}

string Contract::getBuyerAddr() {
    return this->mBuyerAddr;
}

string Contract::getSellerAddr() {
    return this->mSellerAddr;
}

double_t Contract::getPrice() {
    return this->mPrice;
}

time_t Contract::getTimeStamp() {
    return this->mTransactionTimeStamp;
}

string Contract::getDescription() {
    return this->mDescription;
}

string Contract::getProductInfo() {
    return this->mProduct;
}

uint64_t Contract::getTransactionID() {
    return this->mTransactionID;
}

void Contract::setTransactionID(uint64_t ID) {
    this->mTransactionID = ID;
}

string Contract::genContractFileStr(uint64_t transaction_id, string buyer_addr,
                                    string seller_addr, double price, time_t transaction_timestamp,
                                    string description, string product) {

    string contract_content = "";
    this->mTransactionID = transaction_id;
    this->mBuyerAddr = buyer_addr;
    this->mSellerAddr = seller_addr;
    this->mPrice = price;
    this->mTransactionTimeStamp = transaction_timestamp;
    this->mDescription = description;
    this->mProduct = product;

    contract_content += "TRANSACTION_ID=" + to_string(mTransactionID) + '\n';
    contract_content += "BUYER_ADDR=" + mBuyerAddr + '\n';
    contract_content += "SELLER_ADDR=" + mSellerAddr + '\n';
    contract_content += "PRODUCT=" + mProduct + '\n';
    contract_content += "PRICE=" + to_string(mPrice) + '\n';
    contract_content += "DESCRIPTION=" + mDescription + '\n';
    contract_content += "TRANSACTION_TIMESTAMP=" + to_string(mTransactionTimeStamp) + '\n';

    return contract_content;
}

string Contract::genContractFileStr() {

    string contract_content = "";

    contract_content += "TRANSACTION_ID=" + to_string(mTransactionID) + '\n';
    contract_content += "BUYER_ADDR=" + mBuyerAddr + '\n';
    contract_content += "SELLER_ADDR=" + mSellerAddr + '\n';
    contract_content += "PRODUCT=" + mProduct + '\n';
    contract_content += "PRICE=" + to_string(mPrice) + '\n';
    contract_content += "DESCRIPTION=" + mDescription + '\n';
    contract_content += "TRANSACTION_TIMESTAMP=" + to_string(mTransactionTimeStamp) + '\n';

    return contract_content;
}

Contract Contract::genContract(uint64_t transaction_id, string buyer_addr,
                               string seller_addr, double price, time_t transaction_timestamp,
                               string description, string product) {

    return Contract(transaction_id, buyer_addr, seller_addr, price, transaction_timestamp, description, product);
}

Contract Contract::genContract() {
   return *this;
}


