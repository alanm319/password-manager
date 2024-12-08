#ifndef CRYPTO_CONSTANTS_H
#define CRYPTO_CONSTANTS_H
#include <cstddef>

constexpr size_t SALTBYTES = 16;         // crypto_pwhash_SALTBYTES
constexpr size_t NONCEBYTES = 24;       // crypto_secretbox_NONCEBYTES
constexpr size_t DEKBYTES = 32;         // crypto_secretbox_KEYBYTES
constexpr size_t MACBYTES = 16;         // crypto_secretbox_MACBYTES

#endif
