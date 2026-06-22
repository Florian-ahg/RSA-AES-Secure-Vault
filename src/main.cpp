#include <iostream>
#include <string>
#include <vector>
#include <iomanip>  
#include <sstream> 
#include <iterator> 
#include <algorithm>
#include "../include/Options.hpp"
#include "../include/convert.hpp"
#include "../include/AES.hpp"
#include "../include/RSA.hpp"

void usage()
{
    std::cout << "USAGE\n";
    std::cout << "    ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]\n\n";
    std::cout << "DESCRIPTION\n";
    std::cout << "    Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. The MESSAGE is read from the\n";
    std::cout << "    standard input.\n\n";
    std::cout << "CRYPTO_SYSTEM\n";
    std::cout << "    \"xor\"     computation using XOR algorithm\n";
    std::cout << "    \"aes\"     computation using 128-bit AES algorithm\n";
    std::cout << "    \"rsa\"     computation using RSA algorithm\n";
    std::cout << "    \"pgp-xor\" computation using both RSA and XOR algorithm\n";
    std::cout << "    \"pgp-aes\" computation using both RSA and 128-bit AES algorithm\n\n";
    std::cout << "MODE\n";
    std::cout << "    -c         MESSAGE is clear and we want to cipher it\n";
    std::cout << "    -d         MESSAGE is ciphered and we want to decipher it\n";
    std::cout << "    -g P Q     for RSA only: Don't read a MESSAGE, but instead generate a public and\n";
    std::cout << "               private key pair from the prime number P and Q\n\n";
    std::cout << "OPTIONS\n";
    std::cout << "    -b         for XOR, AES and PGP, only works on one block. The MESSAGE and the\n";
    std::cout << "               symmetric key must be the same size\n\n";
    std::cout << "key\n";
    std::cout << "    Key used to cipher/decipher MESSAGE (incompatible with -g MODE)\n";
}

void checking_options(Options &options)
{
    if (options.crypto_system == "" || options.mode == '\0')
    {
        std::cerr << "Error: CRYPTO_SYSTEM and mode are required." << std::endl;
        usage();
        std::exit(84);
    }

    if (options.mode == 'g' && options.crypto_system != "rsa")
    {
        std::cerr << "Error: -g option is only compatible with RSA crypto system, and key must be empty." << std::endl;
        usage();
        std::exit(84);
    }
    else if (options.mode == 'g' && !options.key_str.empty())
    {
        options.key_str = "";
    }

    if ((options.mode == 'c' || options.mode == 'd') && options.key_str.empty())
    {
        std::cerr << "Error: Key is required for cipher (-c) and decipher (-d) modes." << std::endl;
        usage();
        std::exit(84);
    }

    if (options.crypto_system == "pgp-xor" || options.crypto_system == "pgp-aes")
    {
        auto sep = options.key_str.find(':');
        if (sep == std::string::npos)
        {
            std::cerr << "Error: For PGP modes, key must be in the format 'rsa_key:symmetric_key'." << std::endl;
            usage();
            std::exit(84);
        }

        std::string sym_key = options.key_str.substr(0, sep);
        std::string rsa_key = options.key_str.substr(sep + 1);
        if (sym_key.empty() || rsa_key.empty())
        {
            std::cerr << "Error: For PGP modes, both RSA key and symmetric key must be provided." << std::endl;
            usage();
            std::exit(84);
        }
        
        if (rsa_key.find('-') == std::string::npos)
        {
            std::cerr << "Error: Invalid RSA key format in PGP modes. Expected e-N or d-N." << std::endl;
            usage();
            std::exit(84);
        }

        options.rsa_key = rsa_key;
        options.sym_key = sym_key;
    }
}

Options parse_arguments(int ac, char **av)
{
    Options options;

    int c_mode = 0;
    int d_mode = 0;
    int g_mode = 0;
    if (ac < 3 || ac > 5)
    {
        std::cerr << "Error: Not enough or more arguments." << std::endl;
        usage();
        std::exit(84);
    }
    for (int i = 1; av[i] != nullptr; ++i)
    {
        if (std::string(av[i]) == "xor" || std::string(av[i]) == "aes" || std::string(av[i]) == "rsa" || std::string(av[i]) == "pgp-xor" || std::string(av[i]) == "pgp-aes")
        {
            if (!options.crypto_system.empty())
            {
                std::cerr << "Error: Multiple CRYPTO_SYSTEM provided." << std::endl;
                std::exit(84);
            }
            options.crypto_system = std::string(av[i]);
        }
        if (av[i][0] == '-')
        {
            if (std::string(av[i]) == "-c")
            {
                options.mode = 'c';
                c_mode++;
            }
            else if (std::string(av[i]) == "-d")
            {
                options.mode = 'd';
                d_mode++;
            }
            else if (std::string(av[i]) == "-g")
            {

                options.mode = 'g';
                g_mode++;
                if (av[i + 1] == nullptr || av[i + 2] == nullptr)
                {
                    std::cerr << "Error: -g option requires two arguments P and Q." << std::endl;
                    usage();
                    std::exit(84);
                }
                options.p_value = std::string(av[i + 1]);
                options.q_value = std::string(av[i + 2]);
                i += 2;
            }
            else if (std::string(av[i]) == "-b")
            {
                options.is_block_mode = true;
            }
            else
            {
                std::cerr << "Error: Unknown option " << av[i] << std::endl;
                usage();
                std::exit(84);
            }
        }
        if (options.crypto_system != "" && av[i][0] != '-' && std::string(av[i]) != options.crypto_system && options.key_str == "")
        {
            options.key_str = av[i];
        } else if (options.key_str != "" && av[i][0] != '-' && std::string(av[i]) != options.crypto_system)
        {
            std::cerr << "Error: Multiple keys provided." << std::endl;
            usage();
            std::exit(84);
        }
    }
    checking_options(options);
    return options;
}

int main(int ac, char **av)
{
    if (ac == 2 && std::string(av[1]) == "-h") {
        usage();
        return 0;
    }
    Options options = parse_arguments(ac, av);
    if (options.mode == 'g' && options.crypto_system == "rsa") {
        Convert::handle_rsa({}, options.key_str, options);
        return 0;
    }
    std::vector<unsigned char> input_data;

    if (options.crypto_system == "rsa") {
        if (options.mode == 'c') {
            input_data = Convert::read_input();
        }
    } else {
        if (options.mode == 'c') {
            input_data = Convert::read_input();
        } else if (options.mode == 'd') {
            std::string hex_input = Convert::read_line_input();
            input_data = Convert::hex_string_to_bytes(hex_input);
        }
    }

    if (input_data.empty() && options.mode == 'c') {
        std::cerr << "Error: No input data provided." << std::endl;
        return 84;
    }

    std::vector<unsigned char> output_data;

    if (options.crypto_system == "rsa") {
        output_data = Convert::handle_rsa(input_data, options.key_str, options);
    } else if (options.crypto_system == "pgp-aes") {
        output_data = Convert::handle_pgp_aes(input_data, options);
    } else if (options.crypto_system == "pgp-xor") {
        output_data = Convert::handle_pgp_xor(input_data, options);
    }
    else {
        std::vector<unsigned char> key_bytes = Convert::hex_string_to_bytes(options.key_str);

        if (options.is_block_mode) {
            if (input_data.size() != key_bytes.size()) {
                std::cerr << "Error: In block mode, the message and key must be the same size." << std::endl;
                return 84;
            }
        }

        if (options.crypto_system == "aes") {
            output_data = Convert::aes_operation(input_data, key_bytes, options.mode);
        } else if (options.crypto_system == "xor") {
            std::reverse(key_bytes.begin(), key_bytes.end());

            output_data = Convert::handle_xor(input_data, key_bytes, options);
        }
    }


    if (options.mode == 'c') {
        std::cout << Convert::bytes_to_hex_string(output_data);
    } else if (options.mode == 'd') {
        for (unsigned char c : output_data) {
            std::cout << c;
        }
        std::cout << '\n';
    }

    return 0;
}