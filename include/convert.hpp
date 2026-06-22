#ifndef CONVERT_HPP
#define CONVERT_HPP

#include <iostream>
#include <string>
#include <vector>
#include <iomanip> 
#include <sstream>
#include <iterator>
#include <algorithm>
#include "Options.hpp"

namespace Convert
{
    std::vector<unsigned char> hex_string_to_bytes(const std::string &hex);
    std::string bytes_to_hex_string(const std::vector<unsigned char> &bytes);
    std::vector<unsigned char> read_input();
    std::string read_line_input();
    void reverse_endian_blocks(std::vector<unsigned char> &bytes);

    std::vector<unsigned char> handle_xor(const std::vector<unsigned char> &input_data, 
                                         const std::vector<unsigned char> &key_bytes, 
                                         const Options &options);
    std::vector<unsigned char> handle_aes(std::vector<unsigned char> input_data, 
                                            std::vector<unsigned char> key_bytes, 
                                            Options options);
    std::vector<unsigned char> handle_pgp_aes(const std::vector<unsigned char>& input_data,
                                                const Options& options);
    std::vector<unsigned char> handle_pgp_xor(const std::vector<unsigned char>& input_data,
                                                const Options& options);
    
    std::vector<unsigned char> aes_operation(
        const std::vector<unsigned char>& input,
        const std::vector<unsigned char>& key,
        char mode);
};

#endif 