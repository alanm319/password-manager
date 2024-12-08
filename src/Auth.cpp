#include "Auth.h"
#include "Crypto.h"
#include "FileManager.h"
#include "CryptoConstants.h"

#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>
#include <stdexcept>

class Auth {

    static std::string get_password(const std::string &prompt) {
        std::cout << prompt;
        struct termios oldt, newt;
        char c;
        std::string password;

        // Get current terminal attributes
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;

        // Disable echo
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        // Read password from stdin
        while (std::cin.get(c) && c != '\n') {
            password += c;
        }

        // Restore terminal settings
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << std::endl;

        return password;
    }


    static bool authenticate_user() {
        try {
            // Prompt the user for a login password
            std::string password = get_password("Enter master password: ");

            // Retrieve the stored salt, nonce, and encrypted DEK
            std::vector<unsigned char> stored_salt, stored_nonce, stored_cipher;
            FileManager::read_key_file("key.bin", stored_salt, stored_nonce, stored_cipher);

            // Derive the key
            std::vector<unsigned char> key = Crypto::derive_kek(password, stored_salt);

            // Clear sensitive password memory
            sodium_memzero(const_cast<char *>(password.data()), password.size());

            // Decrypt the DEK
            std::vector<unsigned char> decrypted(DEKBYTES);
            if (crypto_secretbox_open_easy(decrypted.data(), stored_cipher.data(),
                                        MACBYTES + DEKBYTES, stored_nonce.data(), key.data()) != 0) {
                throw std::runtime_error("Authentication failed: invalid credentials");
            }

            std::cout << "Authentication successful!" << std::endl;
            return true;

        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }

    void clear_sensitive_data(std::vector<unsigned char> &data) {
        // Clear sensitive data using libsodium's secure memory handling
        sodium_memzero(data.data(), data.size());
    }

};
