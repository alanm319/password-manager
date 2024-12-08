#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <vector>
#include <string>

namespace FileManager {

    // Writes the salt, nonce, and encrypted DEK to a binary file
    void write_key_file(const std::string &filePath,
                      const std::vector<unsigned char> &salt,
                      const std::vector<unsigned char> &nonce,
                      const std::vector<unsigned char> &cipher);

    // Reads the salt, nonce, and encrypted DEK from a binary file
    void read_key_file(const std::string &filePath,
                     std::vector<unsigned char> &salt,
                     std::vector<unsigned char> &nonce,
                     std::vector<unsigned char> &cipher);

}

#endif // FILE_MANAGER_H
