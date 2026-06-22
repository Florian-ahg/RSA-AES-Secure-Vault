#include "../include/convert.hpp"
#include "../include/RSA.hpp"
#include <algorithm>

namespace Convert {
    std::vector<unsigned char> handle_pgp_xor(const std::vector<unsigned char>& input_data,
                                                const Options& options) 
    {
        if (options.mode == 'c') {
            // CHIFFREMENT PGP-XOR
            std::vector<unsigned char> sym_key_bytes = hex_string_to_bytes(options.sym_key);
            
            // Inverser la clé pour XOR (comme dans main.cpp)
            std::reverse(sym_key_bytes.begin(), sym_key_bytes.end());
            
            // Chiffrer les données avec XOR
            std::vector<unsigned char> encrypted_data = handle_xor(input_data, sym_key_bytes, options);

            // Remettre la clé dans l'ordre normal pour RSA
            std::reverse(sym_key_bytes.begin(), sym_key_bytes.end());
            
            // Chiffrer la clé symétrique avec RSA
            Options rsa_options = {"rsa", 'c', false, options.rsa_key, "", "", "", "" };
            std::vector<unsigned char> rsa_encrypted_key = handle_rsa(sym_key_bytes, options.rsa_key, rsa_options);

            // Afficher la clé RSA chiffrée sur la première ligne
            std::cout << bytes_to_hex_string(rsa_encrypted_key);
            return encrypted_data;
            
        } else if (options.mode == 'd') {
            // DÉCHIFFREMENT PGP-XOR
            Options rsa_options = {"rsa", 'd', false, options.rsa_key, "", "", "", "" };
            std::vector<unsigned char> rsa_encrypted_key = hex_string_to_bytes(options.sym_key);
            std::vector<unsigned char> sym_key_bytes = handle_rsa(rsa_encrypted_key, options.rsa_key, rsa_options);

            // Inverser la clé pour XOR (comme dans main.cpp)
            std::reverse(sym_key_bytes.begin(), sym_key_bytes.end());
            
            // Déchiffrer les données avec XOR
            std::vector<unsigned char> decrypted_data = handle_xor(input_data, sym_key_bytes, options);
            return decrypted_data;
            
        } else {
            std::cerr << "Error: Invalid mode for PGP-XOR." << std::endl;
            exit(84);
        }
    }
}
