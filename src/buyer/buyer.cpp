#include "buyer.h"

using namespace std;

double Buyer::price = 0;

Buyer::Buyer() {
    this->mSelfContract = Contract();
}

Buyer::Buyer(string Buyer_Info_File, string Sell_List_File) {
    this->mSelfContract = Contract();
    Load_Info_File(Buyer_Info_File, Sell_List_File);
}

void Buyer::Load_Info_File(string Buyer_Info_File, string Sell_List_File) {
    ConfigParser buyer_parser= ConfigParser();
    buyer_parser.OpenFile(Buyer_Info_File);
    map<string, string> buyer_map = buyer_parser.Parse();

    if (buyer_map.size() > 0) {
        mSelfAddr = buyer_map["ADDR"];
        mSelfIPAddr = buyer_map["IP_ADDR"];
    }
    else {
        cout << "Parsing Buyer Info fails!" << endl;
    }

    ConfigParser sellerlist_parser= ConfigParser();
    sellerlist_parser.OpenFile(Sell_List_File);
    map<string, string> sellerlist_map = sellerlist_parser.Parse();

    //parse the seller list file
    if (sellerlist_map.size() > 0) {
        string prev_prefix = "";
        Seller seller_info;
        bool initialized = false;
        for(map<string,string>::iterator it = sellerlist_map.begin(); it != sellerlist_map.end(); ++it) {
            string seller_prefix;
            size_t pos = 0;
            string delimiter = "_";
            string key = it->first;
            string key_cp = key;
            while ((pos = key.find(delimiter)) != std::string::npos) {
                seller_prefix = key.substr(0, pos);
                key.erase(0, pos + delimiter.length());
            }

            if (prev_prefix != seller_prefix) {
                prev_prefix = seller_prefix;

                if (initialized) {
                    this->mSellerList.push_back(seller_info);
                }

                seller_info = Seller();
                if (key_cp.find("_ADDR") != std::string::npos) {
                    seller_info.setAddr(sellerlist_map[key_cp]);
                }
                initialized = true;
            }
            else {
                if (key_cp.find("_IPADDR") != std::string::npos) {
                    seller_info.setIPAddr(sellerlist_map[key_cp]);
                }

                if (key_cp.find("_OPENPORT") != std::string::npos) {
                    seller_info.setOpenPort(sellerlist_map[key_cp]);
                }
            }
        }
        this->mSellerList.push_back(seller_info);
    }
    else {
        cout << "Parsing Seller Info fails!" << endl;
    }

}

// send purchase request to seller
double Buyer::__request_purchase(int seller_index, string product, string description) {
    Seller target_seller = this->mSellerList[seller_index];

    HttpClient requestpurchase_client(target_seller.getIPAddr() + ":" + target_seller.getOpenPort());
    mTimestamp = std::time(nullptr);
    string request_json_str = "{\"product\": \""+ product + "\", "
                              "\"description\": \""+ description+ "\", \"timestamp\": \""+
            to_string(mTimestamp) + "\", \"buyer\": \"" + mSelfAddr + "\"}";

    cout << "sending requst " << request_json_str << endl;

    // send to the seller, waiting for the price
    requestpurchase_client.request("POST", "/purchase", request_json_str, [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
        if(!ec) {
            ptree pt;
            read_json(response->content, pt);
            Buyer::price = stod(pt.get<string>("price"));
            cout << "The price is " << pt.get<string>("price") << endl;
        }
      });
      requestpurchase_client.io_service->run();
      return price;
}

// generate contract
void Buyer::__gen_contract(int seller_index, string product, double_t price,string description, time_t timestamp) {

    // give a temporary transaction id, approver will update later
    mSelfContract = Contract(0, mSelfAddr, mSellerList[seller_index].getAddr(),
                                     price, timestamp, description, product);

}

// Transaction function
void Buyer::Transact(int seller_index, string product, string description) {
    double price = this->__request_purchase(seller_index, product, description);
    this->__gen_contract(seller_index, product, price, description, mTimestamp);

    // serialize the contract
    stringstream archive_stream;
    boost::archive::text_oarchive archive(archive_stream);
    archive << mSelfContract;

    // send to the approver
    // TODO: parse approver info
    HttpClient approver_client("10.42.0.1:6666");
    approver_client.request("POST", "/contract", archive_stream.str(), [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
        if(!ec) {
            ptree pt;
            read_json(response->content, pt);
            string decision = pt.get<string>("decision");
            cout << "The decision is " << decision << endl;
        }
      });
      approver_client.io_service->run();
}




