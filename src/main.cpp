#include <sodium.h>
#include <iostream>
#include <filesystem>

#include "Util.hpp"
#include "FileManager.hpp"
#include "Auth.hpp"


int main()
{
    try
    {
        // init libsodium
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium couldn't be initialized");
        }

        if (!std::filesystem::exists("data/keys/key.bin")) {
            Auth::first_time_setup();
        }

        Auth::login_usr();

    }
    catch (const std::exception &e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}