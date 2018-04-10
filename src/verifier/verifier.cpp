#include "verifier.h"

using namespace std;
using namespace boost::property_tree;

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;

std::string Verifier::mPublicKey = "";
std::string Verifier::mCorrectAns = "";
bool Verifier::mSelfDecision = false;
vector<bool> Verifier::mAllConsortNodesDecisions;

/* Read the config file from ../config/verifer.config
 * The attribute is OPEN_PORT:xxxx
 * Try not to change the path and filename of the config file
 * Try not to change the attribute names in the config file
*/
Verifier::Verifier() {
    this->mConfigParser = ConfigParser();

    // try best not to change the config filename and path
    mConfigParser.OpenFile("../config/verifer.config");
    map<string, string> parsed_map = this->mConfigParser.Parse();

    if(parsed_map.size() >= 1) {
        // try best not to change the key name
        stringstream geek(parsed_map["OPEN_PORT"]);
        geek >> mOpenPort;
        cout << "Setting HTTP open port at " << mOpenPort << endl;
        mInterface = parsed_map["INTERFACE"];
        cout << "Setting interface " << mInterface << endl;
        getLocalIPv4();
        cout << "The IPv4 address of this node is " << mLocalIPv4 << endl;
    }
    else {
        cout << "Config file parse fails !!" << endl;
    }

    getLocalIPv4();

}

/* Open a port and accept the public key from key-distribution center and to verify proofer
 *
 * The key distribution acceptance rules:
 * (1). The key is passed in a JSON formate: {"Public_Key":"xxxx"} at http://localhost:port/publickey
 * (2). The key has to be sent in POST method
 *
 *The proofer rules:
 *(1). A proofer has to send a request to a verifer upon the link http://localhost:port/verifyme
 *(2). Then the verifier will respond a random number encrypted with ECIES public key in the format of
 * cryptex4transmit object type
 *(3). Then the verifier uses the private key to decrypt the ciphtertext and passes the plaintext number back to verifier
 * upon the linke http://localhost:port/answer with the format of {"plaintext":"xxxx"}
 *
 * Open a port and accept the consortium chain file
 * The link is http://localhost:port/accconsortiumchain
 * The content is raw file content with one ip one line
 *
 * Open a port and accept other verifiers from consortium chain of their decisions
 * The linke is http://localhost:port/otherconsortdecision
 * The format should be {"IP_Addr":"xxx", "Decision":"xxx"}
*/

void Verifier::getLocalIPv4() {
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);

            // locate the specific interface
            string iterator_interf(ifa->ifa_name);
            if (mInterface.find(iterator_interf) != std::string::npos) {
                mLocalIPv4 = addressBuffer;
                break;
            }
        }
    }
    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);
}

void Verifier::Serve() {
    HttpServer server;
    server.config.port = mOpenPort;
    srand(time(NULL));

    // Accepting public key from key distribution center
    cout << "Waiting for public key......" << endl;
    server.resource["^/publickey$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
                ptree pt;
                read_json(request->content, pt);
                Verifier::mPublicKey = pt.get<string>("Public_Key");

                if (Verifier::mPublicKey != "") {
                    string response_str = "Public Key Accepted Successfully !!";
                    *response << "HTTP/1.1 200 OK\r\n"
                              << "Content-Length: " << response_str.length() << "\r\n\r\n"
                              << response_str;
                }
                else {
                    string response_str = "Public Key Accepted Failed !!";
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

    // Accepts "verifyme" request
    server.resource["^/verifyme$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
                //generate a random number between 0 to 99,999
                int random_int = rand() % 100000;
                string random_int_str = to_string(random_int);
                Verifier::mCorrectAns = random_int_str;

                cout << "The random number is " << random_int << endl;

                //encrypt the random number with the received public key
                string response_str;
                char* ciphered = NULL;
                if (!(ciphered = ecies_encrypt((char*) Verifier::mPublicKey.c_str(),
                                        (unsigned char*) random_int_str.c_str(), sizeof(random_int_str)*sizeof(char)))) {
                    response_str = "The encryption process failed!";
                    cout << response_str << endl;

                    *response << "HTTP/1.1 200 OK\r\n"
                              << "Content-Length: " << response_str.length() << "\r\n\r\n"
                              << response_str;
                }
                else {


                    cryptex4transmit cryptex2transmit = cryptex4transmit();
                    cryptex2transmit.convert_cryptex2transmit(ciphered);

                    stringstream archive_stream;
                    boost::archive::text_oarchive archive(archive_stream);
                    archive << cryptex2transmit;

                    *response << "HTTP/1.1 200 OK\r\n"
                              << "Content-Length: " << archive_stream.str().length()
                              << "\r\n\r\n" << archive_stream.str().c_str();

                }

            }
        catch(const exception &e) {
                *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
            }
    };

    // Verify answer part
    //TODO: Our PBFT algorithm and reach a concensus and reply back to proofer
    server.resource["^/answer$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
                ptree pt;
                read_json(request->content, pt);
                string answer = pt.get<string>("plaintext");

                if (answer != "" && answer == Verifier::mCorrectAns) {
                    Verifier::mSelfDecision = true;
                    Verifier::mAllConsortNodesDecisions.push_back(Verifier::mSelfDecision);
                    cout << "The answer is correct !" << endl;
//                    string response_str = "Public Key Accepted Successfully !!";
//                    *response << "HTTP/1.1 200 OK\r\n"
//                              << "Content-Length: " << response_str.length() << "\r\n\r\n"
//                              << response_str;
                }
                else {
                    Verifier::mSelfDecision = false;
                    cout << "The answer is wrong !" << endl;
//                    string response_str = "Answer Accepted Failed !!";
//                    *response << "HTTP/1.1 200 OK\r\n"
//                              << "Content-Length: " << response_str.length() << "\r\n\r\n"
//                              << response_str;
                }

                // TODO: PBFT here and reply the concensus to the proofer
            }
        catch(const exception &e) {
                *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
            }
    };

    // Accept the consortium chain file
    server.resource["^/accconsortiumchain$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
                remove("../config/consortium_graph.txt");
                string consortiumchain_str = request->content.string();
                if (consortiumchain_str != "") {
                    string response_str = "Consortium chain confirmed !!";
                                        *response << "HTTP/1.1 200 OK\r\n"
                                                  << "Content-Length: " << response_str.length() << "\r\n\r\n"
                                                  << response_str;

                    ofstream consortiumchain_file;
                    consortiumchain_file.open("../config/consortium_graph.txt", ios::app);
                    consortiumchain_file << consortiumchain_str;

                }
            }
        catch(const exception &e) {
                *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
            }
    };

    // Accept the consortium chain file
    server.resource["^/otherconsortdecision$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
        try {
                ptree pt;
                read_json(request->content, pt);
                string other_consortchain_ip;
                string other_consrtchain_des;
                other_consortchain_ip = pt.get<string>("IP_Addr");
                other_consrtchain_des = pt.get<string>("Decision");

                if (other_consortchain_ip != "" && other_consrtchain_des != "") {
                    string response_str = "Consortium chain confirmed !!";
                                        *response << "HTTP/1.1 200 OK\r\n"
                                                  << "Content-Length: " << response_str.length() << "\r\n\r\n"
                                                  << response_str;

                    if(other_consrtchain_des.find("true") != std::string::npos
                            || other_consrtchain_des.find("True") != std::string::npos) {
                        Verifier::mAllConsortNodesDecisions.push_back(true);
                    }
                    else {
                        Verifier::mAllConsortNodesDecisions.push_back(false);
                    }
                }

            }
        catch(const exception &e) {
                *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
                    << e.what();
            }
    };


    // start the server
    server.start();
}

// TODO: open the consortium chain file
// send the self decision to all nodes in the consortium chain
void Verifier::sendDecision2OtherConsortiumVerifiers() {

}
