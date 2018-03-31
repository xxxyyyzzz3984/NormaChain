#include "proofer.h"

using namespace std;
using namespace boost::property_tree;

std::string Proofer::mPrivKey = "";

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
 * {"cryptkey":"xxxx","cryptkey_len":xx,"cryptbody":xxx,"cryptbody_len":xx} (cryptex structure)
 *(3). Then the proofer uses the private key to decrypt the ciphtertext and passes the plaintext number back to verifier
 * upon the linke http://verifierip:port/answer with the format of {"plaintext":"xxxx"}
*/
void Proofer::StartProof() {

//    HttpServer server;
//    server.config.port = mProoferOpenPort;

//    // Accepting public key from key distribution center
//    cout << "Waiting for the private key from KDC......" << endl;
//    server.resource["^/privatekey$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
//        try {
//                ptree pt;
//                read_json(request->content, pt);
//                Proofer::mPrivKey = pt.get<string>("Private_Key");

//                if (Proofer::mPrivKey != "") {
//                    string response_str = "Private Key Accepted Successfully !!";
//                    *response << "HTTP/1.1 200 OK\r\n"
//                              << "Content-Length: " << response_str.length() << "\r\n\r\n"
//                              << response_str;
//                }
//                else {
//                    string response_str = "Private Key Accepted Failed !!";
//                    *response << "HTTP/1.1 200 OK\r\n"
//                              << "Content-Length: " << response_str.length() << "\r\n\r\n"
//                              << response_str;
//                }
//            }
//        catch(const exception &e) {
//                *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
//                    << e.what();
//            }
//    };

//    thread server_thread([&server]() {
//        // Start server
//        server.start();
//    });

//    // check if the private key has been retrieved, if yes, stop server and detach server thread
//    while(true) {
//        if (Proofer::mPrivKey != "") {
//            server.stop();
//            server_thread.detach();
//            cout << "Private key received, stopping the key-receiving thread" << endl;
//            break;
//        }
//        else {
//            usleep(300);
//        }
//    }

    // TODO: Send verify request to all verifiers
//    thread verify_thread[this->mVerifierIPList.size()];
//    for (int i = 0; i<this->mVerifierIPList.size(); i++) {
//        verify_thread[i] = thread(Proofer::do_verify, "127.0.0.1", to_string(this->mVerifierOpenPort));
//        cout<< "test" << endl;
//    }

//    for (int i = 0; i<this->mVerifierIPList.size(); i++) {
//        verify_thread[i].join();
//    }

    Proofer::do_verify("127.0.0.1", to_string(this->mVerifierOpenPort));

}

// Asynchronous request
// TODO: Send verify request to all verifiers
void Proofer::do_verify(string IP_Addr, string port) {

        HttpClient client(IP_Addr+":"+port);


        client.request("POST", "/verifyme", "", [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
            if(!ec) {
                CryptexParts cryptparts = CryptexParts();

                ptree pt;
                read_json(response->content, pt);

                cryptparts.cryptkey = pt.get<string>("cryptkey");
                stringstream geek_keylen(pt.get<string>("cryptkey_len"));
                geek_keylen >> cryptparts.cryptkey_len;
                cryptparts.crpytbody = pt.get<string>("cryptbody");
                stringstream geek_bodylen(pt.get<string>("cryptbody_len"));
                geek_bodylen >> cryptparts.cryptbody_len;

                unsigned char * original = NULL;
                char hex_priv[] = "013A1DABB6EA5863EB27722325905447CF0702B45B0418D4AEE055DF0D96AA7930D6D24362CEA7E789FF585D4E38451876815239D556CBC6D6EA158C762A6BB3FD35";
                if (!(original = ecies_decrypt_by_parts((char*) hex_priv, (unsigned char*)cryptparts.cryptkey.c_str(),
                                                        cryptparts.cryptkey_len,
                                                        (unsigned char*) cryptparts.crpytbody.c_str(), cryptparts.cryptbody_len))) {
                    cout << "The decryption process failed!" << endl;
                }
                else {
                    cout << "The original data is " << original << endl;
                }
            }
          });

        client.io_service->run();

}
