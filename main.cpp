#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <termios.h>
#include <unistd.h>
#include <fstream>
#include <sys/stat.h>
#include <filesystem>

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


// TODO deprecate
void save_salt_and_hash(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &key_hash)
{
    std::ofstream out("key.bin", std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open file for writing.");
    }

    out.write(reinterpret_cast<const char *>(salt.data()), salt.size());
    out.write(reinterpret_cast<const char *>(key_hash.data()), key_hash.size());
    out.close();

    chmod("key.bin", S_IRUSR | S_IWUSR);
}

// TODO deprecate
void read_salt_and_hash(std::vector<unsigned char> &salt, std::vector<unsigned char> &key_hash)
{
    std::ifstream in("key.bin", std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file for writing.");
    }

    salt.resize(crypto_pwhash_SALTBYTES);
    key_hash.resize(crypto_generichash_BYTES);

    in.read(reinterpret_cast<char *>(salt.data()), salt.size());
    in.read(reinterpret_cast<char *>(key_hash.data()), key_hash.size());

    in.close();
}

// TODO store sensitive data in secure memory
void first_time_setup() {

    std::cout << "Welcome to password manager!!!" << std::endl;

    // ask for password
    const std::string password = get_password("Enter a password: ");

    // generate a salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    // generate key
    // TODO change key len to 256
    std::vector<unsigned char> key(crypto_pwhash_BYTES_MIN);

    // TODO use argon2id and a higher opslimit
    if (crypto_pwhash(key.data(), key.size(),
                        password.c_str(), password.length(), salt.data(),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_DEFAULT) != 0)
    {

        throw std::runtime_error("Key derivation failed");
    }



    // TODO instead of saving a hash of key, derive a DEK and encrypt it the key (KEK)
    // hash the key
    std::vector<unsigned char> key_hash(crypto_generichash_BYTES);
    crypto_generichash(key_hash.data(), key_hash.size(), key.data(), key.size(), nullptr, 0);

    // store the salt and key hash
    save_salt_and_hash(salt, key_hash);

    // verify salt and key hash
    std::vector<unsigned char> stored_salt, stored_hash;
    read_salt_and_hash(stored_salt, stored_hash);

    if (salt != stored_salt || key_hash != stored_hash) {
        throw std::runtime_error("Verification Failed: Stored data does not match");
    }
    std::cout << "First-time setup complete" << std::endl;
}

// TODO store sensitive data in secure memory
void login_usr() {
    // TODO store in secure memory
    // prompt the user for a login password
    const std::string password = get_password("Enter master password: ");

    // retrieve the stored salt and key hash
    std::vector<unsigned char> stored_salt, stored_key_hash;
    read_salt_and_hash(stored_salt, stored_key_hash);

    // derive the key and hash it
    std::vector<unsigned char> key(crypto_pwhash_BYTES_MIN);

    // TODO use same parameters for kdf as first_time_setup()
    if (crypto_pwhash(key.data(), key.size(),
                        password.c_str(), password.length(), stored_salt.data(),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Key derivation failed");
    }

    // TODO update to new architecutre
    std::vector<unsigned char> derived_key_hash(crypto_generichash_BYTES);
    crypto_generichash(derived_key_hash.data(), derived_key_hash.size(), key.data(), key.size(), nullptr, 0);

    // check if the stored key hash matches the derived hash and act accordingly
    if (stored_key_hash == derived_key_hash) {
        std::cout << "Login successful" << std::endl;
    } else {
        std::cout << "Login failed" << std::endl;
    }
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

        login_usr();
        

    }
    catch (const std::exception &e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}