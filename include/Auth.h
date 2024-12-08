#ifndef AUTH_H
#define AUTH_H

#include <string>
#include <vector>

class Auth {
public:
    // Authenticate the user
    static bool authenticate_user();

    // Retrieve the user's password securely
    static std::string get_password(const std::string &prompt);

private:
    

    // Constants for encryption (could alternatively use CryptoConstants.h)
    static constexpr size_t DEKBYTES = 32;  // DEK length in bytes
    static constexpr size_t CIPHERTEXT_LEN = DEKBYTES + 16; // Ciphertext length

    // Securely handle sensitive memory (to be implemented)
    void clear_sensitive_data(std::vector<unsigned char> &data);
};

#endif // AUTH_H
