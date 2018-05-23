#include "approver.h"

using namespace std;

Approver::Approver() {
    mDecision = false;
    mDecision4Buyer = "";
    mApproveRequestor = "";
}

Approver::Approver(string approver_info_filepath, string approver_list_filepath, string agent_info_filepath) {
    mDecision = false;
    mDecision4Buyer = "";
    mApproveRequestor = "";
    Load_Files(approver_info_filepath, approver_list_filepath, agent_info_filepath);
}

void Approver::Load_Files(string approver_info_filepath, string approver_list_filepath, string agent_info_filepath) {
    ConfigParser approver_parser= ConfigParser();
    approver_parser.OpenFile(approver_info_filepath);
    map<string, string> approver_map = approver_parser.Parse();

    if (approver_map.size() > 0) {
        mSelfAddr = approver_map["ADDR"];
        mSelfIPAddr = approver_map["IP_ADDR"];
        mSelfOpenPort = approver_map["OPENPORT"];
    }
    else {
        cout << "Parsing Approver Info fails!" << endl;
    }

    ConfigParser approverlist_parser= ConfigParser();
    approverlist_parser.OpenFile(approver_list_filepath);
    map<string, string> approverlist_map = approverlist_parser.Parse();
    //parse the approver list file
    if (approverlist_map.size() > 0) {
        string prev_prefix = "";
        Approver approver_info;
        bool initialized = false;
        for(map<string,string>::iterator it = approverlist_map.begin(); it != approverlist_map.end(); ++it) {
            string approver_prefix;
            size_t pos = 0;
            string delimiter = "_";
            string key = it->first;
            string key_cp = key;
            while ((pos = key.find(delimiter)) != std::string::npos) {
                approver_prefix = key.substr(0, pos);
                key.erase(0, pos + delimiter.length());
            }

            if (prev_prefix != approver_prefix) {
                prev_prefix = approver_prefix;

                if (initialized) {
                    this->mApproverList.push_back(approver_info);
                }

                approver_info = Approver();
                if (key_cp.find("_ADDR") != std::string::npos) {
                    approver_info.setAddr(approverlist_map[key_cp]);
                }
                initialized = true;
            }
            else {
                if (key_cp.find("_IPADDR") != std::string::npos) {
                    approver_info.setIPAddr(approverlist_map[key_cp]);
                }

                if (key_cp.find("_OPENPORT") != std::string::npos) {
                    approver_info.setOpenPort(approverlist_map[key_cp]);
                }
            }
        }

        this->mApproverList.push_back(approver_info);
    }
    else {
        cout << "Parsing Seller Info fails!" << endl;
    }

    // parse agent info file
    ConfigParser agent_parser= ConfigParser();
    agent_parser.OpenFile(agent_info_filepath);
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

// wait for the contract
void Approver::__waitforContract(HttpServer& server) {

    cout << "Waiting for contracts......" << endl;
    server.resource["^/contract$"]["POST"] = [this](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
            string recv_string = request->content.string();
            stringstream iarchive_stream;
            iarchive_stream << recv_string;
            boost::archive::text_iarchive iarchive(iarchive_stream);
            mContract = Contract();
            iarchive >> mContract;
            cout << "Received contract from buyer " << mContract.getBuyerAddr() << endl;
            __sendApprovalRequest();

            while(true) {
                if (mDecision4Buyer != "") {
                    break;
                }
                usleep(1);
            }

            string decision_str = "{\"decision\": \"";
            decision_str += mDecision4Buyer + "\"}";
            cout << "Send decision " << mDecision4Buyer << "back to buyer" << endl;
            *response << "HTTP/1.1 200 OK\r\n"
                      << "Content-Length: " << decision_str.length() << "\r\n\r\n"
                      << decision_str;
        }
        catch(const exception &e) {
          *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
        }

        mAllApproverDecisions.clear();
        mDecision4Buyer = "";
        mDecision = false;
        //send contract to agent
        __send_contract2agent();

    };


}

// wait for the approval request from an approver
void Approver::__waitforApprovalRequest(HttpServer& server) {

    cout << "Waiting for approval requests......" << endl;
    server.resource["^/approvalrequests$"]["POST"] = [this](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
              ptree pt;
              read_json(request->content, pt);

              string approver_addr = pt.get<string>("Approver_Addr");
              for (int i = 0; i < mApproverList.size(); i++) {
                  // legitimate approver
                  approver_addr.erase(remove(approver_addr.begin(), approver_addr.end(), '\n'), approver_addr.end());
                  if (approver_addr.find(mApproverList[i].getAddr()) != std::string::npos) {
                      mApproveRequestor = approver_addr;
                      mDecision = true;
                      break;
                  }
              }
              mAllApproverDecisions.push_back(mDecision);
              this->__sendDecision2Others();

              thread check_concensus_thread([response, this] {
                  int approved_count = 0;
                  int deny_count = 0;
                  while (true) {
                      if (mAllApproverDecisions.size() > 0
                              && mAllApproverDecisions.size() >= mApproverList.size()-1) {
                          break;
                      }
                      usleep(1);
                  }

                  // get all the decisions, see if concensus. reply to the proofer and clear the decision stack
                 for (int i = 0; i < mAllApproverDecisions.size(); i++) {
                      if (mAllApproverDecisions[i]) {
                          approved_count++;
                      }
                      else {
                          deny_count++;
                      }
                 }

                 string decision_str = "{\"Decision\":\"";
                 if (approved_count > deny_count) {
                     cout << "Approval Concensus Reached!!" << endl;
                     decision_str += "True";
                 }
                 else {
                     cout << "Denial Concensus Reached!!" << endl;
                     decision_str += "False";
                 }
                 mApproveRequestor = "";
                 mAllApproverDecisions.clear();
                 mDecision = false;
                 decision_str += "\"}";

                 *response << "HTTP/1.1 200 OK\r\n"
                           << "Content-Length: " << decision_str.length() << "\r\n\r\n"
                           << decision_str;
             });
             check_concensus_thread.detach();
        }
        catch(const exception &e) {
          *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
        }
    };

}

// wait for other approvers' decisions
void Approver::__waitforOtherDecisions(HttpServer& server) {
    // Accept decisions from other nodes
    server.resource["^/otherdecision$"]["POST"] = [this](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
                ptree pt;
                read_json(request->content, pt);
                string other_des;
                other_des = pt.get<string>("decision");
                cout << "Recieve a decision " << other_des << endl;
                string response_str = "Decision received !";
                            *response << "HTTP/1.1 200 OK\r\n"
                                      << "Content-Length: " << response_str.length() << "\r\n\r\n"
                                      << response_str;

                if(other_des.find("true") != std::string::npos
                        || other_des.find("True") != std::string::npos) {
                    this->mAllApproverDecisions.push_back(true);
                }
                else {
                   this->mAllApproverDecisions.push_back(false);
                }
        }

        catch(const exception &e) {
                *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
        }
    };
}

void Approver::__sendApprovalRequest() {
         for (int i = 0; i < mApproverList.size(); i++) {
             if(mApproverList[i].getAddr().find(mSelfAddr) != string::npos) {
                 continue;
             }
            thread request_approval_thread([i, this] {
                HttpClient approvalrequest_client(mApproverList[i].getIPAddr() + ":" + mApproverList[i].getOpenPort());
                string request_json_str = "{\"Approver_Addr\": \"" + mSelfAddr +"\"}";
                approvalrequest_client.request("POST", "/approvalrequests", request_json_str, [this](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
                    if(!ec) {
                        ptree pt;
                        read_json(response->content, pt);
                        string decision_str = pt.get<string>("Decision");
                        mDecision4Buyer = decision_str;
                        cout << "The decision is " << decision_str << endl;
                    }
                  });
                  approvalrequest_client.io_service->run();
            });
            request_approval_thread.detach();
         }

}

//TODO: send contract to agent
void Approver::__send_contract2agent() {
    // serialize the contract
    stringstream archive_stream;
    boost::archive::text_oarchive archive(archive_stream);
    archive << mContract;

    // send to the approver
    HttpClient agent_client(mAgent.getIPAddr() + ":" + mAgent.getOpenPort());
    agent_client.request("POST", "/contract", archive_stream.str(),
                         [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
      });
     agent_client.io_service->run();
}

// send decision to other approvers
void Approver::__sendDecision2Others() {
    // HttpClient* client_verifier[Verifier::mConsortiumNodeIPs.size()];
    for (int i = 0; i<mApproverList.size(); i++) {
        if (mApproverList[i].getAddr().find(mSelfAddr) != std::string::npos ||
                mApproveRequestor.find(mApproverList[i].getAddr()) != std::string::npos) {
            continue;
        }
        // skip self and the requestor
        thread send_other_thread([i, this] {

            string decision_str = "{\"decision\": \"";
            if (mDecision) {
                decision_str += "true\"}";
            }
            else {
                decision_str += "false\"}";
            }
            HttpClient client_verifier(mApproverList[i].getIPAddr()+":"+mApproverList[i].getOpenPort());
            cout << "send decision to " << mApproverList[i].getAddr() << " " << endl;
            client_verifier.request("POST", "/otherdecision", decision_str, [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
                if(!ec) {
                }
              });
            client_verifier.io_service->run();
        });
        send_other_thread.detach();
    }
}

void Approver::serve() {
    HttpServer server;
    server.config.port = stoi(mSelfOpenPort);
    __waitforContract(server);
    __waitforApprovalRequest(server);
    __waitforOtherDecisions(server);
    thread server_thread([&server]() {
        // Start server
        server.start();
    });
    server_thread.join();
}

void Approver::setAddr(string Addr) {
    this->mSelfAddr = Addr;
}

void Approver::setIPAddr(string IPAddr) {
    this->mSelfIPAddr = IPAddr;
}

void Approver::setOpenPort(string openport) {
    this->mSelfOpenPort = openport;
}

string Approver::getAddr() {
    return this->mSelfAddr;
}

string Approver::getIPAddr() {
    return this->mSelfIPAddr;
}

string Approver::getOpenPort() {
    return this->mSelfOpenPort;
}
