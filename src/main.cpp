#include <sodium.h>
#include <iostream>
#include <filesystem>
#include <sqlite3.h>

#include "Util.hpp"
#include "FileManager.hpp"
#include "Auth.hpp"
#include "DatabaseManager.hpp"


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

        DatabaseManager dbManager("test.db");

        dbManager.init_db();
        
        std::cout << "\nRetrieving all credentials:" << std::endl;
        auto all_creds = dbManager.get_all_entries();;
        for (const auto& cred : all_creds) {
             std::cout << "Service: " << cred.website 
                       << ", Username: " << cred.username 
                       << ", Password: " << cred.password << std::endl;
        }
    }
    catch (const std::exception &e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}