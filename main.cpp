#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <termios.h>
#include <unistd.h>
#include <fstream>
#include <sys/stat.h>

void to_hex(const unsigned char *const data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
}

/**
 * Get a password from the user without echoing it to the terminal
 */
std::string get_password(const std::string &prompt)
{
    std::cout << prompt;
    struct termios oldt, newt;
    char c;
    std::string password;

    // get current terminal attributes
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    // disable echo
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // read password from stdin
    while (std::cin.get(c) && c != '\n')
    {
        password += c;
    }

    // restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;

    return password;
}

/**
 * Save the salt and key hash to a file
 */
void save_salt_and_hash(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &key_hash)
{
    std::ofstream out("key.bin", std::ios::binary);
    if (!out)
    {
        throw std::runtime_error("Failed to open file for writing.");
    }

    out.write(reinterpret_cast<const char *>(salt.data()), salt.size());
    out.write(reinterpret_cast<const char *>(key_hash.data()), key_hash.size());
    out.close();

    chmod("key.bin", S_IRUSR | S_IWUSR);
}

/**
 * @brief Read salt and key hash from key.bin
 * @param salt vector to store salt
 * @param key_hash vector to store key hash
 */
void read_salt_and_hash(std::vector<unsigned char> &salt, std::vector<unsigned char> &key_hash)
{
    std::ifstream in("key.bin", std::ios::binary);
    if (!in)
    {
        throw std::runtime_error("Failed to open file for writing.");
    }

    salt.resize(crypto_pwhash_SALTBYTES);
    key_hash.resize(crypto_generichash_BYTES);

    in.read(reinterpret_cast<char *>(salt.data()), salt.size());
    in.read(reinterpret_cast<char *>(key_hash.data()), key_hash.size());

    in.close();
}

int main()
{
    try
    {

        // init libsodium
        if (sodium_init() < 0)
        {
            throw std::runtime_error("libsodium couldn't be initialized");
        }

        // ask for password
        const std::string password = get_password("Enter a password: ");

        // generate a salt
        std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
        randombytes_buf(salt.data(), sizeof(salt));

        // generate key
        std::vector<unsigned char> key(crypto_pwhash_BYTES_MIN);

        if (crypto_pwhash(key.data(), key.size(),
                          password.c_str(), password.length(), salt.data(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                          crypto_pwhash_ALG_DEFAULT) != 0)
        {

            throw std::runtime_error("Key derivation failed");
        }

        // hash the key
        std::vector<unsigned char> key_hash(crypto_generichash_BYTES);
        crypto_generichash(key_hash.data(), key_hash.size(), key.data(), key.size(), nullptr, 0);

        // store the salt and key hash
        save_salt_and_hash(salt, key_hash);

        std::vector<unsigned char> stored_salt, stored_hash;
        read_salt_and_hash(stored_salt, stored_hash);

        if (salt == stored_salt && key_hash == stored_hash)
        {
            std::cout << "Salt and key hash stored successfully" << std::endl;
        }
        else
        {
            throw std::runtime_error("Salt and key verification failed");
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}