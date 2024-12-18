#include "FileManager.hpp"
#include <fstream>
#include <sys/stat.h>
#include <sodium.h>

void FileManager::create_key_file(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &nonce, const std::vector<unsigned char> &cipher) {
    std::ofstream out("data/keys/key.bin", std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open file for writing.");
    }

    out.write(reinterpret_cast<const char *>(salt.data()), salt.size());
    out.write(reinterpret_cast<const char *>(nonce.data()), nonce.size());
    out.write(reinterpret_cast<const char *>(cipher.data()), cipher.size());

    out.close();
    chmod("data/keys/key.bin", S_IRUSR | S_IWUSR);
}
void FileManager::read_key_file(std::vector<unsigned char> &salt, std::vector<unsigned char> &nonce, std::vector<unsigned char> &cipher) {
    std::ifstream in("data/keys/key.bin", std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file for writing.");
    }

    salt.resize(crypto_pwhash_SALTBYTES);
    nonce.resize(crypto_secretbox_NONCEBYTES);
    cipher.resize(crypto_secretbox_MACBYTES + 32U);

    in.read(reinterpret_cast<char *>(salt.data()), salt.size());
    in.read(reinterpret_cast<char *>(nonce.data()), nonce.size());
    in.read(reinterpret_cast<char *>(cipher.data()), cipher.size());

    in.close();
}