#include "Options.hpp"
#include <vector>
#include <string>
#include <iostream>
#include "gmp.h"
#include "convert.hpp"

namespace Convert {
    void hexToMpz_LE(mpz_t result, const std::string& hex);
    std::string mpzToHex_LE(const mpz_t n);
    void bytesToMpz_LE(mpz_t result, const std::vector<unsigned char>& bytes);
    std::vector<unsigned char> mpzToBytes_LE(const mpz_t n);

    std::vector<unsigned char> handle_rsa(
        const std::vector<unsigned char>& input_data,
        const std::string& key_str,
        const Options& options);

    
}