#include "Crypto.h"
#include <sodium.h>

namespace Crypto {
    std::vector<unsigned char> generate_random_bytes(size_t length) {
        std::vector<unsigned char> random_bytes(length);
        randombytes_buf(random_bytes.data(), random_bytes.size());
        return random_bytes;
    }
    
    std::vector<unsigned char> derive_kek(const std::string &password, const std::vector<unsigned char> &salt) {
        std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);

        if (crypto_pwhash(key.data(), key.size(),
                            password.c_str(), password.length(), salt.data(),
                            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                            crypto_pwhash_ALG_DEFAULT) != 0)
        {

            throw std::runtime_error("Key derivation failed");
        }
        return key;
    }

    std::vector<unsigned char> encrypt_dek(const std::vector<unsigned char> &dek, const std::vector<unsigned char> &key, std::vector<unsigned char> &nonce) {
        std::vector<unsigned char> ciphertext(crypto_secretbox_MACBYTES + crypto_secretbox_KEYBYTES);
        crypto_secretbox_easy(ciphertext.data(), dek.data(), dek.size(), nonce.data(), key.data());
        return ciphertext;
    }

    std::tuple<std::vector<unsigned char>, std::vector<unsigned char>, std::vector<unsigned char>> init_masterkey_data(const std::string &password) {
        std::vector<unsigned char> salt = generate_random_bytes(crypto_pwhash_SALTBYTES);

        std::vector<unsigned char> kek = derive_kek(password, salt);
        sodium_memzero(const_cast<char *>(password.data()), password.length());

        std::vector<unsigned char> nonce = generate_random_bytes(crypto_secretbox_NONCEBYTES);
        std::vector<unsigned char> dek = generate_random_bytes(crypto_secretbox_KEYBYTES);

        std::vector<unsigned char> encrypted_dek = encrypt_dek(dek, kek, nonce);
        sodium_memzero(dek.data(), dek.size());
        
        return std::make_tuple(salt, nonce, encrypted_dek);
    }
}

