#include "graph.h"

using namespace std;

Graph::Graph() {

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

/* 
 * This algorithm generate a random graph of two-layer chain structure
 * The upper chain is a consortium chain in which nodes reach a concensus based on PBFT
 * The lower chain is a public chain
 * int num_consortium must be <= number of verifiers
 * */
void Graph::genRandGraph_TwoLayerChain(int num_consortium) {

    remove("../config/consortium_graph.txt");

	srand(time(NULL));
	if (num_consortium > mVerifierIPList.size()) {
		cout << "ERROR: The number of nodes in the consortium chain is greater than the number of verifiers" << endl;
		return;
	}

	//generate n unique randoms numbers for consortium chain, n = # of verifiers
	genUniqNums(mVerifierIPList.size(), num_consortium);
	for (int i = 0; i < mGeneratedRandNums.size(); i++) {
		mConsortiumChain.push_back(mVerifierIPList[mGeneratedRandNums[i]]);
	}

	//write the graph file for PBFT to config
    ofstream consortiumchain_file;
	consortiumchain_file.open("../config/consortium_graph.txt", ios::app);
	for(int i = 0; i < mConsortiumChain.size(); i++) {
		consortiumchain_file << mConsortiumChain[i] << endl;
	}

    cout << "Send consortium chain info to verifiers" << endl;
    sendGraphFile("../config/consortium_graph.txt");

	consortiumchain_file.close();
	mGeneratedRandNums.clear();
	mConsortiumChain.clear();
	mPublicChain.clear();
}

// broadcast the graph file to all verifiers (IP list of nodes in consortium chain)
void Graph::sendGraphFile(string filepath) {
    std::ifstream t(filepath);
    std::string consortium_chain_content((std::istreambuf_iterator<char>(t)),
                     std::istreambuf_iterator<char>());

    HttpClient* client_verifier[mVerifierIPList.size()];
    for (int i = 0; i<mVerifierIPList.size(); i++) {
        client_verifier[i] = new HttpClient(mVerifierIPList[i]+":"+to_string(mVerifierOpenPort));
        client_verifier[i]->request("POST", "/accconsortiumchain", consortium_chain_content, [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
            if(!ec) {
            }
          });
        client_verifier[i]->io_service->run();
    }
}

void Graph::genUniqNums(int max_num, int num_nums) {
	int rand_num = rand() % max_num;
	while (true) {
		if(!isNumGenerated(rand_num)) {
			mGeneratedRandNums.push_back(rand_num);
		}
		else {
			rand_num = rand() % max_num;
		}
		
		if (mGeneratedRandNums.size() >= num_nums) {
			break;
		}
	}
}

bool Graph::isNumGenerated(int num) {
	bool result = false;
	for (int i = 0; i<mGeneratedRandNums.size(); i++) {
		if (mGeneratedRandNums[i] == num) {
			result = true;
		}
	}
	return result;
}
