#include "proofer.h"

using namespace std;
using namespace boost::property_tree;

string Proofer::mPrivKey = "";
string Proofer::mDecision = "";

CryptexParts::CryptexParts() {
    this->cryptbody_len = 0;
    this->cryptkey = "";
    this->cryptkey_len = 0;
}

Proofer::Proofer() {
    this->mConfigParser = ConfigParser();
    this->mVerifierOpenPort = 0;

    // First open the config file of verifier
    // to confirm the open port of verifier
    mConfigParser.OpenFile("../config/verifer.config");
    map<string, string> parsed_map = this->mConfigParser.Parse();

    if(parsed_map.size() >= 1) {
        stringstream geek(parsed_map["OPEN_PORT"]);
        geek >> this->mVerifierOpenPort;
    }
    else {
        cout << "Verifier config file parse fails !!" << endl;
    }

    //Second, open the proofer config file
    // to maintain the open port for receiving private key from KDC
    mConfigParser.OpenFile("../config/proofer.config");
    parsed_map.clear();
    parsed_map = this->mConfigParser.Parse();
    if(parsed_map.size() >= 1) {
        stringstream geek(parsed_map["OPEN_PORT"]);
        geek >> this->mProoferOpenPort;
    }
    else {
        cout << "Proofer config file parse fails !!" << endl;
    }


    //Third, open the node_ip list config file
    // to maintain a list of IP addresses of all verifier
    mConfigParser.OpenFile("../config/node_ip.config");
    parsed_map.clear();
    parsed_map = this->mConfigParser.Parse();
    for(map<string,string>::iterator it = parsed_map.begin(); it != parsed_map.end(); ++it) {
        if (it->first.find("verifier") != std::string::npos) {
            this->mVerifierIPList.push_back(parsed_map[it->first]);
        }
    }
}

/* Open a port and accept the private key from key-distribution center and to prove myself
 *
 * The key distribution acceptance rules:
 * (1). The key is passed in a JSON formate: {"Private_Key":"xxxx"} at http://localhost:port/privatekey
 * (2). The key has to be sent in POST method
 *
 *The proofer rules:
 *(1). The proofer has to send a request to a verifer upon the link http://verifierip:port/verifyme
 *(2). Then the verifier will respond a random number encrypted with ECIES public key in the format of
 * cryptex4transmit object type
 *(3). Then the proofer uses the private key to decrypt the ciphtertext and passes the plaintext number back to verifier
 * upon the linke http://verifierip:port/answer with the format of {"plaintext":"xxxx"}
*/
void Proofer::Wait4PrivateKey() {

    HttpServer server;
    server.config.port = mProoferOpenPort;

    // Accepting public key from key distribution center
    cout << "Waiting for the private key from KDC......" << endl;
    server.resource["^/privatekey$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
                ptree pt;
                read_json(request->content, pt);
                Proofer::mPrivKey = pt.get<string>("Private_Key");

                if (Proofer::mPrivKey != "") {
                    string response_str = "Private Key Accepted Successfully !!";
                    *response << "HTTP/1.1 200 OK\r\n"
                              << "Content-Length: " << response_str.length() << "\r\n\r\n"
                              << response_str;
                }
                else {
                    string response_str = "Private Key Accepted Failed !!";
                    *response << "HTTP/1.1 200 OK\r\n"
                              << "Content-Length: " << response_str.length() << "\r\n\r\n"
                              << response_str;
                }
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

    // check if the private key has been retrieved, if yes, stop server and detach server thread
    while(true) {
        if (Proofer::mPrivKey != "") {
            server.stop();
            server_thread.detach();
            cout << "Private key received, stopping the key-receiving thread" << endl;
            break;
        }
        else {
            usleep(300);
        }
    }

}

// wait couples seconds after receiving the private key
void Proofer::StartProof() {
    // Send verify request to all verifiers in different threads asynchronously
    thread verify_thread[this->mVerifierIPList.size()];
    for (int i = 0; i<this->mVerifierIPList.size(); i++) {
        verify_thread[i] = thread(Proofer::do_verify, mVerifierIPList[i], to_string(this->mVerifierOpenPort));
    }

    for (int i = 0; i<this->mVerifierIPList.size(); i++) {
        verify_thread[i].join();
    }
}

// Asynchronous request
// TODO: Send verify request to all verifiers
void Proofer::do_verify(string IP_Addr, string port) {

    int answer;
    HttpClient client_requestverify(IP_Addr+":"+port);
    client_requestverify.request("POST", "/verifyme", "", [&answer](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
        if(!ec) {
            string recv_string = response->content.string();
            cryptex4transmit deserialized_cryptex = cryptex4transmit();
            stringstream iarchive_stream;
            iarchive_stream << recv_string;
            boost::archive::text_iarchive iarchive(iarchive_stream);
            iarchive >> deserialized_cryptex;
            vector<char> cryptex_body_vec = deserialized_cryptex.cryptex_body_vec;
            vector<char> cryptex_key_vec = deserialized_cryptex.cryptex_key_vec;
            uint64_t body_len = deserialized_cryptex.body_len;
            uint64_t key_len = deserialized_cryptex.key_len;

            char* cryptex_body = reinterpret_cast<char*>(cryptex_body_vec.data());
            char* cryptex_key = reinterpret_cast<char*>(cryptex_key_vec.data());


            unsigned char * original = NULL;

            if (!(original = ecies_decrypt_by_parts((char*) Proofer::mPrivKey.c_str(), (unsigned char*)cryptex_key,
                            key_len,
                            (unsigned char*) cryptex_body, body_len))) {
                cout << "The decryption process failed!" << endl;

            }
            else {
                    cout << "The decrypted data is " << original << endl;
                    answer = atoi((const char*)original);
            }
        }
      });
    client_requestverify.io_service->run();


    // send answer to the verifier
    HttpClient client_ans(IP_Addr+":"+port);
    string answer_str = "{\"plaintext\":\"" + to_string(answer);
    answer_str += "\"}";
    cout << "send " << answer_str << " to " << IP_Addr << endl;
    client_ans.request("POST", "/answer", answer_str, [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
        if(!ec) {

            // TODO: wait for concensus dicision from the verifiers
            ptree pt;
            read_json(response->content, pt);
            string decision;
            decision = pt.get<string>("Decision");
            cout << "The decision is " << decision << endl;
            Proofer::mDecision = decision;
        }
    });
    client_ans.io_service->run();

    HttpClient client_end(IP_Addr+":"+port);
    client_end.request("POST", "/endround", "",
                       [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {if(!ec) {}});
    client_end.io_service->run();
}
