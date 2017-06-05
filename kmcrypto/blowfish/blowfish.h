//
// Blowfish C++ implementation
//
// CC0 - PUBLIC DOMAIN
// This work is free of known copyright restrictions.
// http://creativecommons.org/publicdomain/zero/1.0/
//

#pragma once

#ifndef __blowfish__
#define __blowfish__

#include <stdint.h>
#include <cstddef>
#include <vector>
#include "ikmcrypto.h"

class Blowfish: public ikmcrypto {
public:
  Blowfish();
  std::vector<char> encrypt(const std::vector<char> &src);
  std::vector<char> decrypt(const std::vector<char> &src);
  void set_key(const char *key, size_t byte_length);
  uint16_t get_minimum_block_size();

private:
  void EncryptBlock(uint32_t *left, uint32_t *right) const;
  void DecryptBlock(uint32_t *left, uint32_t *right) const;
  uint32_t Feistel(uint32_t value) const;

private:
  uint32_t pary_[18];
  uint32_t sbox_[4][256];
};

#endif /* defined(__blowfish__) */
