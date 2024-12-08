#include <string>
#include <vector>
#include <tuple>

namespace Crypto {
        
        std::tuple<std::vector<unsigned char>, std::vector<unsigned char>, std::vector<unsigned char>> init_masterkey_data(const std::string &password);

        std::vector<unsigned char> derive_kek(const std::string &password, const std::vector<unsigned char> &salt);

        std::vector<unsigned char> generate_random_bytes(size_t length);

        std::vector<unsigned char> encrypt_dek(const std::vector<unsigned char> &dek, const std::vector<unsigned char> &key, std::vector<unsigned char> &nonce);
}