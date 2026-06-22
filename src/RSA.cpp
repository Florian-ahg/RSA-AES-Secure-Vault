#include <gmp.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>
#include "../include/RSA.hpp"
#include "../include/Options.hpp"
#include "../include/convert.hpp"

namespace Convert {

    void hexToMpz_LE(mpz_t result, const std::string& hex) {
        std::string padded_hex = (hex.length() % 2 != 0) ? ("0" + hex) : hex;
        std::string reversed_hex;
        for (int i = padded_hex.length() - 2; i >= 0; i -= 2) {
            reversed_hex += padded_hex.substr(i, 2);
        }
        mpz_set_str(result, reversed_hex.c_str(), 16);
    }

    std::string mpzToHex_LE(const mpz_t n) {
        char* big_endian_hex_c_str = mpz_get_str(NULL, 16, n);
        std::string big_endian_hex(big_endian_hex_c_str);
        free(big_endian_hex_c_str);

        if (big_endian_hex.length() % 2 != 0) {
            big_endian_hex = "0" + big_endian_hex;
        }

        std::string little_endian_hex;
        for (int i = big_endian_hex.length() - 2; i >= 0; i -= 2) {
            little_endian_hex += big_endian_hex.substr(i, 2);
        }
        return little_endian_hex;
    }

    void bytesToMpz_LE(mpz_t result, const std::vector<unsigned char>& bytes) {
        mpz_import(result, bytes.size(), -1, sizeof(unsigned char), 0, 0, bytes.data());
    }

    std::vector<unsigned char> mpzToBytes_LE(const mpz_t n) {
        size_t count;
        unsigned char* bytes_be = (unsigned char*)mpz_export(NULL, &count, 1, sizeof(unsigned char), 0, 0, n);
        
        std::vector<unsigned char> bytes_le;
        for (size_t i = 0; i < count; ++i) {
            bytes_le.push_back(bytes_be[i]);
        }
        std::reverse(bytes_le.begin(), bytes_le.end()); // pour le Little Endian
        
        free(bytes_be);
        if (bytes_le.empty()) return {0};
        return bytes_le;
    }

    std::vector<unsigned char> handle_rsa(const std::vector<unsigned char>& input_data,
        const std::string& key_str,
        const Options& options)
    {
        mpz_t p, q, n, p_minus_1, q_minus_1, gcd_val, lambda_n, e, d;
        mpz_inits(p, q, n, p_minus_1, q_minus_1, gcd_val, lambda_n, e, d, NULL);

        if (options.mode == 'g') {
            if (options.p_value.empty() || options.q_value.empty()) exit(84);
            
            hexToMpz_LE(p, options.p_value); 
            hexToMpz_LE(q, options.q_value);

            if (mpz_cmp_ui(p, 1) <= 0 || mpz_cmp_ui(q, 1) <= 0) exit(84);
            if (mpz_cmp(p, q) == 0) exit(84);

            mpz_mul(n, p, q);
            mpz_sub_ui(p_minus_1, p, 1);
            mpz_sub_ui(q_minus_1, q, 1);
            mpz_gcd(gcd_val, p_minus_1, q_minus_1);
            mpz_mul(lambda_n, p_minus_1, q_minus_1);
            mpz_divexact(lambda_n, lambda_n, gcd_val);

            const unsigned long fermat_primes[] = {65537, 257, 17, 5, 3};
            bool e_found = false;
            for (unsigned long fermat : fermat_primes) {
                mpz_set_ui(e, fermat);
                if (mpz_cmp(e, lambda_n) < 0) {
                    mpz_gcd(gcd_val, e, lambda_n);
                    if (mpz_cmp_ui(gcd_val, 1) == 0) {
                        e_found = true;
                        break;
                    }
                }
            }
            if (!e_found) exit(84);
            
            if (mpz_invert(d, e, lambda_n) == 0) exit(84);

            std::cout << "public key: " << mpzToHex_LE(e) << "-" << mpzToHex_LE(n) << std::endl;
            std::cout << "private key: " << mpzToHex_LE(d) << "-" << mpzToHex_LE(n) << std::endl;
            
            mpz_clears(p, q, n, p_minus_1, q_minus_1, gcd_val, lambda_n, e, d, NULL);
            return {};
        }

        size_t dash_pos = key_str.find('-');
        if (dash_pos == std::string::npos) exit(84);
        std::string exp_str = key_str.substr(0, dash_pos);
        std::string mod_str = key_str.substr(dash_pos + 1);
        if (exp_str.empty() || mod_str.empty()) exit(84);
        
        mpz_t key_part1, modulus;
        mpz_inits(key_part1, modulus, NULL);
        hexToMpz_LE(key_part1, exp_str);
        hexToMpz_LE(modulus, mod_str);

        if (mpz_cmp_ui(modulus, 0) <= 0) exit(84);
        
        std::vector<unsigned char> output_data;

        if (options.mode == 'c') {
            if (input_data.empty()) exit(84);

            mpz_t message_num;
            mpz_init(message_num);
            bytesToMpz_LE(message_num, input_data);
            
            if (mpz_cmp(message_num, modulus) >= 0) exit(84);
            
            mpz_t encrypted_num;
            mpz_init(encrypted_num);
            mpz_powm(encrypted_num, message_num, key_part1, modulus);
            output_data = mpzToBytes_LE(encrypted_num);
            
            mpz_clears(message_num, encrypted_num, NULL);

        } else if (options.mode == 'd') {
            mpz_t encrypted_num;
            mpz_init(encrypted_num);

            if (!input_data.empty()) {
                bytesToMpz_LE(encrypted_num, input_data);
            } else {
                std::string hex_input = Convert::read_line_input();
                if (hex_input.empty()) exit(84);
                hexToMpz_LE(encrypted_num, hex_input);
            }
            
            if (mpz_cmp(encrypted_num, modulus) >= 0) exit(84);
            
            mpz_t decrypted_num;
            mpz_init(decrypted_num);
            mpz_powm(decrypted_num, encrypted_num, key_part1, modulus);
            output_data = mpzToBytes_LE(decrypted_num);

            mpz_clears(encrypted_num, decrypted_num, NULL);
        }

        mpz_clears(p, q, n, p_minus_1, q_minus_1, gcd_val, lambda_n, e, d, key_part1, modulus, NULL);
        return output_data;
    }
}