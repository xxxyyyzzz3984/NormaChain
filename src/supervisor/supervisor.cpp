#include "supervisor.h"

Supervisor::Supervisor(string agent_info_path) {
    this->Load_Agent_Info(agent_info_path);
}

void Supervisor::Load_Agent_Info(string agent_info_path) {
    // parse agent info file
    ConfigParser agent_parser= ConfigParser();
    agent_parser.OpenFile(agent_info_path);
    map<string, string> agent_map = agent_parser.Parse();

    if (agent_map.size() > 0) {
        mAgent.setAddr( agent_map["ADDR"] );
        mAgent.setIPAddr( agent_map["IP_ADDR"] );
        mAgent.setOpenPort(agent_map["OPENPORT"]);
    }
    else {
        cout << "Parsing Agent Info fails!" << endl;
    }
}

void Supervisor::SearchKeyword(string keyword) {
    HttpClient requestsearch_client(mAgent.getIPAddr() + ":" + mAgent.getOpenPort());

    string request_json_str = "{\"keyword\": \"" + keyword + "\"}";

    cout << "sending requst to search keyword " << keyword << endl;

    // send to the seller, waiting for the price
    requestsearch_client.request("POST", "/searchrequest", request_json_str, [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
        if(!ec) {
            string recv_string = response->content.string();
            stringstream iarchive_stream;
            iarchive_stream << recv_string;
            boost::archive::text_iarchive iarchive(iarchive_stream);
            vector<uint64_t> Transaction_IDs;
            iarchive >> Transaction_IDs;
            if(Transaction_IDs.size() < 1) {
                cout << "The keyword is not found in the transaction chain.";
            }
            else {
                cout << "The keyword is found in Transactions with id: ";
                for(int i = 0; i<Transaction_IDs.size(); i++) {
                    cout << Transaction_IDs[i];
                    if(i != Transaction_IDs.size() - 1) {
                        cout << ", ";
                    }
                    else {
                        cout << ".";
                    }
                }

            }
            cout << endl;
        }
      });
      requestsearch_client.io_service->run();
}
