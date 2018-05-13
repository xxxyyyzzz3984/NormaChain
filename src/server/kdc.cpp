#include "kdc.h"

using namespace std;

KDC::KDC() {

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

        else if (it->first.find("proofer") != std::string::npos) {
            this->mProoferIP = parsed_map[it->first];
        }
    }

}

void KDC::GenKeyAndDistribute() {
    EC_KEY *key;
    key = ecies_key_create();
    if (key == NULL) {
        cout << "Key generation failed!" << endl;
        return;
    }
    else {
        mPublicKey = ecies_key_public_get_hex(key);
        mPrivateKey = ecies_key_private_get_hex(key);
        string public_key(mPublicKey);
        string private_key(mPrivateKey);

        string publickey_msg = "{\"Public_Key\":\"" + public_key + "\"}";
        string privatekey_msg = "{\"Private_Key\":\"" + private_key + "\"}";

        // send public key to all verifiers
        HttpClient* client_verifier[mVerifierIPList.size()];
        for (int i = 0; i<mVerifierIPList.size(); i++) {
            client_verifier[i] = new HttpClient(mVerifierIPList[i]+":"+to_string(mVerifierOpenPort));
	    client_verifier[i]->request("POST", "/publickey", publickey_msg, [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
                if(!ec) {

                }
              });
            client_verifier[i]->io_service->run();
        }

        // send private key to proofer
        HttpClient client_proof(mProoferIP+":"+to_string(mProoferOpenPort));
        client_proof.request("POST", "/privatekey", privatekey_msg, [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
            if(!ec) {

            }
          });
        client_proof.io_service->run();

    }
}
