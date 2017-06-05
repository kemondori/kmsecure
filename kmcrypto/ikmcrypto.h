#ifndef IKMCRYPTO_H
#define IKMCRYPTO_H

#include <stdint.h>
#include <cstddef>
#include <vector>
#include <string>
#include <exception>
#include <stdexcept>

class ikmcrypto {

public:
    virtual void set_key(const char *key, size_t byte_length);
    virtual void set_key_with_iv(const char *key, size_t byte_length, const char* iv, size_t iv_length);
    virtual uint16_t get_minimum_block_size() = 0;
    virtual std::vector<char> encrypt(const std::vector<char> &src) = 0;
    virtual std::vector<char> decrypt(const std::vector<char> &src) = 0;
};

class kmcrypto_exception: public std::runtime_error
{
public:
    kmcrypto_exception(std::string what_message);
};

#endif
