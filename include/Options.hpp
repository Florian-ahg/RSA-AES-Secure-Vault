#ifndef OPTIONS_HPP
#define OPTIONS_HPP

#include <iostream>
#include <string>
#include <vector>
#include <iomanip> 
#include <sstream> 

struct Options {
    std::string crypto_system;
    char mode = '\0';        
    bool is_block_mode = false;
    std::string key_str;
    std::string p_value;       
    std::string q_value;    
    std::string sym_key;
    std::string rsa_key;
};

#endif 


