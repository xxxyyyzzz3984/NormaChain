#include "verifier.h"

using namespace std;
using namespace boost::property_tree;

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;

std::string Verifier::mPublicKey = "";
std::string Verifier::mCorrectAns = "";
bool Verifier::mSelfDecision = false;

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
    }
    else {
        cout << "Config file parse fails !!" << endl;
    }

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
*/


void Verifier::Serve() {
    HttpServer server;
    server.config.port = mOpenPort;

    // Accepting public key from key distribution center
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

    // start the server
    server.start();
}
