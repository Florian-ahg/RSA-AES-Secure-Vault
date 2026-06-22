#include "../include/convert.hpp"
#include "../include/AES.hpp"

namespace Convert
{
    std::vector<unsigned char> hex_string_to_bytes(const std::string &hex)
    {
        std::vector<unsigned char> bytes;
        if (hex.length() % 2 != 0)
        {
            std::cerr << "Error: Invalid key format. Hexadecimal string must have an even number of characters." << std::endl;
            exit(84);
        }

        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::string byte_string = hex.substr(i, 2);
            if (!std::isxdigit(byte_string[0]) || !std::isxdigit(byte_string[1]))
            {
                std::cerr << "Error: Invalid key format. Contains non-hexadecimal characters." << std::endl;
                exit(84);
            }
            unsigned char byte = static_cast<unsigned char>(std::stoul(byte_string, nullptr, 16)); // Convertit un paire de caractères hex en un octet
            bytes.push_back(byte);
        }
        return bytes;
    }

    std::string bytes_to_hex_string(const std::vector<unsigned char> &bytes)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (unsigned char byte : bytes)
        {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        ss << '\n';
        return ss.str();
    }

    void reverse_endian_blocks(std::vector<unsigned char> &bytes)
    {
        if (bytes.size() % 4 != 0)
            return;
        for (size_t i = 0; i < bytes.size(); i += 4)
            std::reverse(bytes.begin() + i, bytes.begin() + i + 4);
    }

    std::vector<unsigned char> read_input()
    {
        std::vector<unsigned char> data;
        char c;
        
        while (std::cin.get(c))
        {
            data.push_back(static_cast<unsigned char>(c));
        }

        // Supprimer le retour à la ligne final s'il y en a un
        if (!data.empty() && data.back() == '\n')
        {
            data.pop_back();
        }

        return data;
    }

    std::string read_line_input()
    {
        std::string line;
        if (std::getline(std::cin, line)) {
            return line;
        }
        
        // Si getline échoue, essayer de lire avec get()
        char c;
        line.clear();
        while (std::cin.get(c) && c != '\n') {
            line += c;
        }
        
        // Note: getline() supprime déjà le \n, donc pas besoin de le filtrer ici
        return line;
    }

    std::vector<unsigned char> handle_aes(std::vector<unsigned char> input_data,
                                          std::vector<unsigned char> key_bytes,
                                          Options options)
    {
        try
        {
            AES aes_cipher(key_bytes);

            if (options.mode == 'c')
            {
                if (options.is_block_mode)
                {
                    std::vector<unsigned char> block(input_data.begin(), input_data.begin() + 16);
                    return aes_cipher.encrypt(block);
                }
                else
                {
                    return aes_cipher.encrypt(input_data);
                }
            }
            else
            {
                return aes_cipher.decrypt(input_data);
            }
        }
        catch (const std::invalid_argument &e)
        {
            std::cerr << "Error (AES): " << e.what() << std::endl;
            std::exit(84);
        }
    }

    std::vector<unsigned char> aes_operation(const std::vector<unsigned char>& input,
                                            const std::vector<unsigned char>& key,
                                            char mode)
    {
        std::vector<unsigned char> processed_key = key;
        reverse_endian_blocks(processed_key);
        
        std::vector<unsigned char> processed_input = input;
        if (mode == 'd') {
            reverse_endian_blocks(processed_input);
        }

        AES aes_cipher(processed_key);
        std::vector<unsigned char> output;
        
        if (mode == 'c') {
            output = aes_cipher.encrypt(processed_input);
            reverse_endian_blocks(output);
        } else {
            output = aes_cipher.decrypt(processed_input);
        }
        return output;
    }

}
