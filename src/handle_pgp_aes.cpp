#include "../include/AES.hpp"
#include "../include/convert.hpp"
#include "../include/RSA.hpp"

namespace Convert {
    std::vector<unsigned char> handle_pgp_aes(const std::vector<unsigned char>& input_data,
                                                const Options& options) 
    {
        if (options.mode == 'c') {
            std::vector<unsigned char> sym_key_bytes = hex_string_to_bytes(options.sym_key);
            
            std::vector<unsigned char> encrypted_data = aes_operation(input_data, sym_key_bytes, 'c');

            Options rsa_options = {"rsa", 'c', false, options.rsa_key, "", "", "", "" };
            std::vector<unsigned char> rsa_encrypted_key = handle_rsa(sym_key_bytes, options.rsa_key, rsa_options);

            std::cout << bytes_to_hex_string(rsa_encrypted_key);
            return encrypted_data;
            
        } else if (options.mode == 'd') {
            Options rsa_options = {"rsa", 'd', false, options.rsa_key, "", "", "", "" };
            std::vector<unsigned char> rsa_encrypted_key = hex_string_to_bytes(options.sym_key);
            std::vector<unsigned char> sym_key_bytes = handle_rsa(rsa_encrypted_key, options.rsa_key, rsa_options);

            std::vector<unsigned char> decrypted_data = aes_operation(input_data, sym_key_bytes, 'd');
            return decrypted_data;
            
        } else {
            std::cerr << "Error: Invalid mode for PGP-AES." << std::endl;
            exit(84);
        }
    }
}