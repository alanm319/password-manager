#ifndef FILEMANAGER_HPP
#define FILEMANAGER_HPP

#include <vector>

namespace FileManager {

    void create_key_file(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &nonce, const std::vector<unsigned char> &cipher);
    void read_key_file(std::vector<unsigned char> &salt, std::vector<unsigned char> &nonce, std::vector<unsigned char> &cipher);
}
#endif