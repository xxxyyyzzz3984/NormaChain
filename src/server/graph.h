#ifndef GRAPH_H
#define GRAPH_H

#include <map>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <string>
#include <time.h>
#include <fstream>
#include <cstdio>

#include "httpimpl/client_http.hpp"
#include "configparser/configparser.h"

using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;

// Graph generation algorithms
class Graph{
public:
	Graph();
	void genRandGraph_TwoLayerChain(int num_consortium);
private:
	std::vector <std::string> mConsortiumChain;
	std::vector <std::string> mPublicChain;
 	int mVerifierOpenPort;
    	int mProoferOpenPort;
    	ConfigParser mConfigParser;
    	std::vector<std::string> mVerifierIPList;
    	std::string mProoferIP;
	std::vector<int> mGeneratedRandNums;

	void genUniqNums(int max_num, int num_nums);
	bool isNumGenerated(int num);
	void sendGraphFile(std::string filepath);
};

#endif
