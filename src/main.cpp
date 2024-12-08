#include <sodium.h>
#include <iostream>
#include <filesystem>


#include "Auth.h"
#include "Crypto.h"
#include "FileManager.h"

const unsigned int DEK_LEN = 32U;
const unsigned int CIPHERTEXT_LEN = crypto_secretbox_MACBYTES + DEK_LEN;

void to_hex(const unsigned char *const data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
}

void first_time_setup() {

    std::cout << "Welcome to password manager!!!" << std::endl;

    // ask for password
    std::string password = Auth::get_password("Set a password: ");

    std::vector<unsigned char> salt, nonce, encrypted_dek;
    try {
        std::tie(salt, nonce, encrypted_dek) = Crypto::init_masterkey_data(password);
    } catch (const std::exception &e) {
        std::cerr << "Error during setup: "<< e.what() << std::endl;
        return;
    }
    
    // write the encrypted file into a file (for now)
    FileManager::write_key_file("key.bin", salt, nonce, encrypted_dek);
}

int main()
{
    try
    {
        // init libsodium
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium couldn't be initialized");
        }

        if (!std::filesystem::exists("key.bin")) {
            first_time_setup();
        }



    }
    catch (const std::exception &e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}