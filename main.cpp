#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <termios.h>
#include <unistd.h>
#include <fstream>
#include <sys/stat.h>
#include <filesystem>

const unsigned int DEK_LEN = 32U;
const unsigned int CIPHERTEXT_LEN = crypto_secretbox_MACBYTES + DEK_LEN;

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


// stores salt plaintext, nonce plaintext, and dek (ciphertext)
void create_key_file(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &nonce, const std::vector<unsigned char> &cipher)
{
    std::ofstream out("key.bin", std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open file for writing.");
    }

    out.write(reinterpret_cast<const char *>(salt.data()), salt.size());
    out.write(reinterpret_cast<const char *>(nonce.data()), nonce.size());
    out.write(reinterpret_cast<const char *>(cipher.data()), cipher.size());

    out.close();
    chmod("key.bin", S_IRUSR | S_IWUSR);
}

// reads the plaintext salt and nonce and encrypted dek for decryption
void read_key_file(std::vector<unsigned char> &salt, std::vector<unsigned char> &nonce, std::vector<unsigned char> &cipher)
{
    std::ifstream in("key.bin", std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file for writing.");
    }

    salt.resize(crypto_pwhash_SALTBYTES);
    nonce.resize(crypto_secretbox_NONCEBYTES);
    cipher.resize(CIPHERTEXT_LEN);

    in.read(reinterpret_cast<char *>(salt.data()), salt.size());
    in.read(reinterpret_cast<char *>(nonce.data()), nonce.size());
    in.read(reinterpret_cast<char *>(cipher.data()), cipher.size());

    in.close();
}

// TODO store sensitive data in secure memory
void login_usr() {
    // TODO store in secure memory
    // prompt the user for a login password
    const std::string password = get_password("Enter master password: ");

    // retrieve the stored salt, nonce, and encrypted
    std::vector<unsigned char> stored_salt, stored_nonce, stored_cipher;
    read_key_file(stored_salt, stored_nonce, stored_cipher);

    // derive the key and hash it
    std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(key.data(), key.size(),
                        password.c_str(), password.length(), stored_salt.data(),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Key derivation failed");
    }



    // decrypt dek
    std::vector<unsigned char> decrypted(DEK_LEN);
    if (crypto_secretbox_open_easy(decrypted.data(), stored_cipher.data(), CIPHERTEXT_LEN, stored_nonce.data(), key.data()) != 0) {
    /* message forged! */
        throw std::runtime_error("Authintication failed");
    } else {
        std::cout << "Authentication successful!" << std::endl;
    }

}

// TODO store sensitive data in secure memory
void first_time_setup() {

    std::cout << "Welcome to password manager!!!" << std::endl;

    // ask for password
    std::string password = get_password("Set a password: ");

    // generate a salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    // generate key
    std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(key.data(), key.size(),
                        password.c_str(), password.length(), salt.data(),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_DEFAULT) != 0)
    {

        throw std::runtime_error("Key derivation failed");
    }

    sodium_memzero(&password[0], password.size());

    // generate a noce for dek encryption
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // generate dek
    std::vector<unsigned char> dek(DEK_LEN);
    randombytes_buf(dek.data(), dek.size());

    // ecnrypt dek
    std::vector<unsigned char> ciphertext(CIPHERTEXT_LEN);
    crypto_secretbox_easy(ciphertext.data(), dek.data(), dek.size(), nonce.data(), key.data());

    // write the encrypted file into a file (for now)
    create_key_file(salt, nonce, ciphertext);
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