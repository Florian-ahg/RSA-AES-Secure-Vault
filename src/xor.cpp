#include "../include/convert.hpp"
#include "../include/Options.hpp"
#include <algorithm>

namespace Convert
{
    std::vector<unsigned char> handle_xor(const std::vector<unsigned char> &input_data, 
                                         const std::vector<unsigned char> &key_bytes, 
                                         const Options &options)
    {
        std::vector<unsigned char> output_data;
        
        if (options.mode == 'c') 
        {   
            if (options.is_block_mode)
            {
                for (size_t i = 0; i < input_data.size(); ++i)
                {
                    output_data.push_back(input_data[i] ^ key_bytes[i]);
                }
            }
            else
            {
                size_t key_size = key_bytes.size();
                size_t input_size = input_data.size();                
                for (size_t i = 0; i < input_size; i += key_size)
                {
                    size_t block_end = std::min(i + key_size, input_size);
                    
                    for (size_t j = i; j < block_end; ++j)
                    {
                        output_data.push_back(input_data[j] ^ key_bytes[j - i]);
                    }
                }
            }            
            std::reverse(output_data.begin(), output_data.end());
        }
        else if (options.mode == 'd')
        {
            std::vector<unsigned char> reversed_input = input_data;
            std::reverse(reversed_input.begin(), reversed_input.end());
            
            if (options.is_block_mode)
            {
                for (size_t i = 0; i < reversed_input.size(); ++i)
                {
                    output_data.push_back(reversed_input[i] ^ key_bytes[i]);
                }
            }
            else
            {
                size_t key_size = key_bytes.size();
                size_t input_size = reversed_input.size();
            
                for (size_t i = 0; i < input_size; i += key_size)
                {
                    size_t block_end = std::min(i + key_size, input_size);
                    
                    for (size_t j = i; j < block_end; ++j)
                    {
                        output_data.push_back(reversed_input[j] ^ key_bytes[j - i]);
                    }
                }
            }
          
        }
        
        return output_data;
    }
}
