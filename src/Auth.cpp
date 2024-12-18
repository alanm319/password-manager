#include "Auth.hpp"
#include "Util.hpp"
#include "FileManager.hpp"
#include <sodium.h>
#include <iostream>

const unsigned int DEK_LEN = 32U;
const unsigned int CIPHERTEXT_LEN = crypto_secretbox_MACBYTES + DEK_LEN;

void Auth::login_usr() {
    // prompt the user for a login password
    const std::string password = Util::get_password("Enter master password: ");

    // retrieve the stored salt, nonce, and encrypted
    std::vector<unsigned char> stored_salt, stored_nonce, stored_cipher;
    FileManager::read_key_file(stored_salt, stored_nonce, stored_cipher);

    // derive the key and hash it
    std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(key.data(), key.size(),
                        password.c_str(), password.length(), stored_salt.data(),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Key derivation failed");
    }

    // decrypt dek
    std::vector<unsigned char> decrypted(DEK_LEN);
    if (crypto_secretbox_open_easy(decrypted.data(), stored_cipher.data(), CIPHERTEXT_LEN, stored_nonce.data(), key.data()) != 0) {
    /* message forged! */
        throw std::runtime_error("Authintication failed");
    } else {
        std::cout << "Authentication successful!" << std::endl;
    }
}

void Auth::first_time_setup() {

    std::cout << "Welcome to password manager!!!" << std::endl;

    // ask for password
    std::string password = Util::get_password("Set a password: ");

    // generate a salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    // generate key
    std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(key.data(), key.size(),
                        password.c_str(), password.length(), salt.data(),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_DEFAULT) != 0)
    {

        throw std::runtime_error("Key derivation failed");
    }

    sodium_memzero(&password[0], password.size());

    // generate a noce for dek encryption
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // generate dek
    std::vector<unsigned char> dek(DEK_LEN);
    randombytes_buf(dek.data(), dek.size());

    // ecnrypt dek
    std::vector<unsigned char> ciphertext(CIPHERTEXT_LEN);
    crypto_secretbox_easy(ciphertext.data(), dek.data(), dek.size(), nonce.data(), key.data());
    sodium_memzero(&dek[0], dek.size());

    // write the encrypted file into a file (for now)
    FileManager::create_key_file(salt, nonce, ciphertext);
    sodium_memzero(&salt[0], salt.size());
    sodium_memzero(&nonce[0], nonce.size());
    sodium_memzero(&ciphertext[0], ciphertext.size());

}