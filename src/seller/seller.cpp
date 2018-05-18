#include "seller.h"

Seller::Seller () {
}

Seller::Seller(string seller_info_filepath) {
    Load_Seller_Info(seller_info_filepath);
}

void Seller::Load_Seller_Info(string Seller_info_filepath) {
    ConfigParser seller_parser = ConfigParser();
    seller_parser.OpenFile(Seller_info_filepath);
    map<string, string> seller_map = seller_parser.Parse();

    if (seller_map.size() > 0) {
        mAddr = seller_map["ADDR"];
        mIPAddr = seller_map["IP_ADDR"];
        mOpenPort = seller_map["OPENPORT"];
        mProductMap.empty();

        string products = seller_map["PRODUCTS"];
        string prices = seller_map["PRICES"];
        std::stringstream product_ss(products);
        string one_product;
        while (product_ss.good())
        {
            getline( product_ss, one_product, ',' );
            mProductList.push_back(one_product);
        }

        std::stringstream price_ss(prices);
        double one_price;
        int index = 0;
        while (price_ss >> one_price)
        {
            mProductMap.insert(pair<string, double>(mProductList[index], one_price));
            if (price_ss.peek() == ',') {
                price_ss.ignore();
            }
            index++;
        }

    }
    else {
        cout << "Parsing Seller Info fails!" << endl;
    }
}

void Seller::setAddr(string Addr) {
    this->mAddr = Addr;
}

void Seller::setIPAddr(string IPAddr) {
    this->mIPAddr = IPAddr;
}

void Seller::setOpenPort(string openport) {
    this->mOpenPort = openport;
}

string Seller::getAddr() {
    return this->mAddr;
}

string Seller::getIPAddr() {
    return this->mIPAddr;
}

string Seller::getOpenPort() {
    return this->mOpenPort;
}

double Seller::getPrice(string product) {
    return this->mProductMap[product];
}

void Seller::waitforTransaction() {
    HttpServer server;
    server.config.port = stoi(mOpenPort);
    cout << "Waiting for transaction......" << endl;
    server.resource["^/purchase$"]["POST"] = [this](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
          ptree pt;
          read_json(request->content, pt);

          string product = pt.get<string>("product");
          string buyer_addr = pt.get<string>("buyer");
          cout << "Requesting to purchase " << product
               << "from buyer " << buyer_addr << endl;

          string response_str = "{\"price\": \"" + to_string(getPrice(product)) + "\"}";

          *response << "HTTP/1.1 200 OK\r\n"
                    << "Content-Length: " << response_str.length() << "\r\n\r\n"
                    << response_str;
        }
        catch(const exception &e) {
          *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
        }
    };

    thread server_thread([&server]() {
        // Start server
        server.start();
    });
    server_thread.join();
}
