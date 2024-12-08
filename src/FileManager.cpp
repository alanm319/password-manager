#include "FileManager.h"
#include "CryptoConstants.h"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>

namespace FileManager {

    void write_key_file(const std::string &filePath,
                      const std::vector<unsigned char> &salt,
                      const std::vector<unsigned char> &nonce,
                      const std::vector<unsigned char> &cipher) {
        // Open the file for binary output
        std::ofstream out(filePath, std::ios::binary);
        if (!out) {
            throw std::runtime_error("Failed to open file '" + filePath + "' for writing.");
        }

        // Write salt, nonce, and encrypted DEK to the file
        out.write(reinterpret_cast<const char *>(salt.data()), salt.size());
        out.write(reinterpret_cast<const char *>(nonce.data()), nonce.size());
        out.write(reinterpret_cast<const char *>(cipher.data()), cipher.size());

        out.close();

        // Set file permissions (read/write for owner only)
        if (chmod(filePath.c_str(), S_IRUSR | S_IWUSR) != 0) {
            throw std::runtime_error("Failed to set permissions on file '" + filePath + "'.");
        }
    }

    void read_key_file(const std::string &filePath,
                     std::vector<unsigned char> &salt,
                     std::vector<unsigned char> &nonce,
                     std::vector<unsigned char> &cipher) {
        // Check if the file exists and is readable
        struct stat fileStat;
        if (stat(filePath.c_str(), &fileStat) != 0) {
            throw std::runtime_error("File '" + filePath + "' does not exist or is not readable.");
        }

        // Open the file for binary input
        std::ifstream in(filePath, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open file '" + filePath + "' for reading.");
        }

        // Resize buffers to expected sizes
        salt.resize(SALTBYTES);
        nonce.resize(NONCEBYTES);
        cipher.resize(MACBYTES + DEKBYTES);

        // Read salt, nonce, and encrypted DEK
        in.read(reinterpret_cast<char *>(salt.data()), salt.size());
        in.read(reinterpret_cast<char *>(nonce.data()), nonce.size());
        in.read(reinterpret_cast<char *>(cipher.data()), cipher.size());

        // Validate that all data was read successfully
        if (in.gcount() < static_cast<std::streamsize>(salt.size() + nonce.size() + cipher.size())) {
            throw std::runtime_error("File '" + filePath + "' is incomplete or corrupted.");
        }

        in.close();
    }

}
