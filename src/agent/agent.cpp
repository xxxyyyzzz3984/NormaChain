#include "agent.h"
using namespace std;

Agent::Agent() {
    init_pbc_param_pairing(mParam, mPairing);
    double P = mpz_get_d(mPairing->r);
    KeyGen(&mKey, mParam, mPairing);
}

Agent::Agent(string agent_info_path) {
    init_pbc_param_pairing(mParam, mPairing);
    double P = mpz_get_d(mPairing->r);
    KeyGen(&mKey, mParam, mPairing);
    this->Load_Agent_Info(agent_info_path);
}

void Agent::Load_Agent_Info(string path) {
    ConfigParser agent_parser= ConfigParser();
    agent_parser.OpenFile(path);
    map<string, string> agent_map = agent_parser.Parse();

    if (agent_map.size() > 0) {
        mAddr = agent_map["ADDR"];
        mIPAddr = agent_map["IP_ADDR"];
        mOpenPort = agent_map["OPENPORT"];
    }
    else {
        cout << "Parsing Approver Info fails!" << endl;
    }
}

void Agent::__encrypt_contract(Contract contract) {
    string product = contract.getProductInfo();
    string description = contract.getDescription();
    vector<string> description_words;

    vector<element_s> trapdoor_list;
    description_words.clear();

    // parse desription based on
    std::stringstream description_ss(description);
    string one_word_description;
    while (description_ss.good())
    {
        getline(description_ss, one_word_description, ' ' );
        description_words.push_back(one_word_description);
    }

    // generate a trapdoor for product
    char *hashedW = (char*) malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
    element_t Tw;    // trapdoor word
    element_t H1_W1;
    char* product_char = (char*) product.c_str();
    sha512(product_char, (int)strlen(product_char), hashedW);
    element_init_G1(H1_W1, mPairing);
    element_from_hash(H1_W1, hashedW, (int)strlen(hashedW));
    Trapdoor(Tw, mPairing, mKey.priv, H1_W1);
    free(hashedW);
    hashedW = NULL;
    element_s tmp = {Tw->field, Tw->data};
    trapdoor_list.push_back(tmp);

    // generate trapdoors for description
    for (int i = 0; i < description_words.size(); i++) {
        char *hashedW = (char*) malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
        element_t Tw;    // trapdoor word
        element_t H1_W1;
        char* description_word = (char*) description_words[i].c_str();
        sha512(description_word, (int)strlen(description_word), hashedW);
        element_init_G1(H1_W1, mPairing);
        element_from_hash(H1_W1, hashedW, (int)strlen(hashedW));
        Trapdoor(Tw, mPairing, mKey.priv, H1_W1);
        free(hashedW);
        hashedW = NULL;
        element_s tmp = {Tw->field, Tw->data};
        trapdoor_list.push_back(tmp);
    }

    this->mContract2TrapdoorMap.insert(pair<uint64_t, vector<element_s>>(contract.getTransactionID(), trapdoor_list));
    vector<>
}

void Agent::__save_trapdoorlist2file() {

}

void Agent::__recv_contract(HttpServer &server) {
    server.resource["^/contract$"]["POST"] = [this](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
            string recv_string = request->content.string();
            stringstream iarchive_stream;
            iarchive_stream << recv_string;
            boost::archive::text_iarchive iarchive(iarchive_stream);
            Contract recv_contract = Contract();
            iarchive >> recv_contract;

            string response_str = "Contract received!";
            cout << response_str << endl;
            *response << "HTTP/1.1 200 OK\r\n"
                      << "Content-Length: " << response_str.length() << "\r\n\r\n"
                      << response_str;

            uint64_t Transaction_ID = (uint64_t) mRecvContractList.size();
            recv_contract.setTransactionID(Transaction_ID);
            mRecvContractList.push_back(recv_contract);
            __encrypt_contract(recv_contract);
        }
        catch(const exception &e) {
          *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
        }
    };
}

vector<uint64_t> Agent::__search_keyword(string keyword) {
    pair<uint64_t, vector<element_s>> it;
    vector<uint64_t> Transaction_IDs;
    BOOST_FOREACH(it, mContract2TrapdoorMap) {
        uint64_t Transaction_ID;
        vector<element_s> trapdoor_list = mContract2TrapdoorMap[Transaction_ID];
        for(int i=0; i<trapdoor_list.size(); i++) {
            element_t Tw = {trapdoor_list[i].field, trapdoor_list[i].data};
            char* keyword_c = (char*) keyword.c_str();
            int match = Test(keyword_c, (int)strlen(keyword_c), &mKey.pub, Tw, mPairing);
            if(match) {
                Transaction_IDs.push_back(Transaction_ID);
                break;
            }
        }

    }
    return Transaction_IDs;
}

void Agent::__recv_searchrequest(HttpServer &server) {
    thread search_request_thread([this, &server] {
    server.resource["^/searchrequest$"]["POST"] = [this](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
            ptree pt;
            read_json(request->content, pt);
            string keyword;
            keyword = pt.get<string>("keyword");
            cout << "Recieve a search request with keyword " << keyword << endl;

            //serialize the transaction id vector and send to supervisor
            vector<uint64_t> found_trans_id_list = __search_keyword(keyword);
            stringstream archive_stream;
            boost::archive::text_oarchive archive(archive_stream);
            archive << found_trans_id_list;

            *response << "HTTP/1.1 200 OK\r\n"
                      << "Content-Length: " << archive_stream.str().length() << "\r\n\r\n"
                      << archive_stream.str();
        }
        catch(const exception &e) {
          *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
        }
    };
    });
    search_request_thread.detach();
}

void Agent::serve() {
    HttpServer server;
    server.config.port = stoi(mOpenPort);
    this->__recv_searchrequest(server);
    this->__recv_contract(server);
    thread server_thread([&server]() {
        // Start server
        server.start();
    });
    server_thread.join();
}

void Agent::test() {
    Contract contract = Contract(10, "123", "123", 100, 123, "this is a description", "bread");
    __encrypt_contract(contract);
}

void Agent::setAddr(string Addr) {
    mAddr = Addr;
}

void Agent::setIPAddr(string IPAddr) {
    mIPAddr = IPAddr;
}

void Agent::setOpenPort(string OpenPort) {
    mOpenPort = OpenPort;
}

string Agent::getAddr() {
    return mAddr;
}

string Agent::getIPAddr() {
    return mIPAddr;
}

string Agent::getOpenPort() {
    return mOpenPort;
}

//void Agent::__write_encrypted_contract(string path) {
//    cout << "test write " << endl;

//    // serialize the vector element_s struct (encrypted contract)
//    stringstream archive_stream;
//    boost::archive::text_oarchive archive(archive_stream);
//    archive << mContract2TrapdoorMap[0];

////    ofstream output_file(path, ios::binary);
////    output_file << archive_stream.str();
//    cout << archive_stream.str() << endl;
////    output_file.close();
//}


