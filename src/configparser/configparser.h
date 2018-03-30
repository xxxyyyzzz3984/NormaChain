#ifndef CONFIGPARSER_H
#define CONFIGPARSER_H

#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <sstream>
#include <map>
#include <iterator>
#include <algorithm>

class ConfigParser
{

public:
    ConfigParser();
    void OpenFile(std::string filename);
    std::map<std::string, std::string> Parse();

private:
    std::string FileConent;
};

#endif
