

#ifndef AES_HPP
#define AES_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include "Options.hpp"

class AES
{
public:
    explicit AES(const std::vector<unsigned char> &key);
    ~AES();

    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& message);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext);

private:
    unsigned char expandedKeys[176];

    void keyExpansion(const unsigned char* key);

    void encryptBlock(unsigned char* block);
    void decryptBlock(unsigned char* block);

    void addRoundKey(unsigned char* state, int round);
    void subBytes(unsigned char* state);
    void invSubBytes(unsigned char* state);
    void shiftRows(unsigned char* state);
    void invShiftRows(unsigned char* state);
    void mixColumns(unsigned char* state);
    void invMixColumns(unsigned char* state);

    void rotWord(unsigned char* word);
    void subWord(unsigned char* word);
    unsigned char gmul(unsigned char a, unsigned char b);

    static const unsigned char s_box[256];
    static const unsigned char inv_s_box[256];
    static const unsigned char Rcon[10][4];
};

#endif
