#ifndef UTIL_HPP
#define UTIL_HPP
#include <string>

namespace Util {
    std::string get_password(const std::string &prompt);

    void to_hex(const unsigned char *const data, size_t size);
}
#endif