#include "configparser.h"

using namespace std;

ConfigParser::ConfigParser(){
    this->FileConent = "";
}

void ConfigParser::OpenFile(string filename) {
    ifstream t(filename);
    if (!t.is_open()) {
        cout << "File " << filename << " Not Found!!" << endl;
        return;
    }
    string str((istreambuf_iterator<char>(t)), istreambuf_iterator<char>());
    this->FileConent = str;
}

map<string, string> ConfigParser::Parse() {
    map<string, string> config_map;
    config_map.empty();
    if(this->FileConent != "") {
        istringstream is_file(this->FileConent);
        string line;
        while( std::getline(is_file, line) ) {
            istringstream is_line(line);
            string key;
            if(getline(is_line, key, '=') ) {
                string value;
                if(getline(is_line, value)) {
                    config_map.insert(pair<string, string>(key, value));
                }
            }
        }
    }

    return config_map;
}
