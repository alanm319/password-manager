#include <sodium.h>
#include <iostream>
#include <filesystem>
#include <sqlite3.h>

#include "Util.hpp"
#include "DatabaseManager.hpp"
#include "CLI11.hpp"


int main(int argc, char** argv)
{
    try
    {
        DatabaseManager db("data/test.db");

        CLI::App app{"Password manager"};
        argv = app.ensure_utf8(argv);   
        
        auto sub_init = app.add_subcommand("db_init", "Initialize database");
        sub_init->callback([&]() {
            std::cout << "Initializing Database" << std::endl;
            db.init_db(Util::get_password("Enter a master password to encrypt database: "));
        });

        auto sub_add  = app.add_subcommand("add", "Add a new entry to database");
        std::string add_service;
        std::string add_username;
        sub_add->add_option("-s, --service", add_service, "Entry's associated service")->required();
        sub_add->add_option("-u, --username", add_username, "Entry's username")->required();
        sub_add->callback([&]() {
            if (!db.authenticate(Util::get_password("Enter password to unlock database: "))) {
                throw std::runtime_error("Invalid credentials");
            }
            std::string pw = Util::get_password("Enter password for new entry:");
            db.add_entry(add_service, add_username, pw);
        });

        auto sub_show = app.add_subcommand("show", "Show an entry's information");
        std::string show_service;
        sub_show->add_option("-s, --service", show_service, "Entry's associated service")->required();
        sub_show->callback([&]() {
            if (!db.authenticate(Util::get_password("Enter password to unlock database: "))) {
                throw std::runtime_error("Invalid credentials");
            }
            std::vector<Entry> creds = db.get_entry(show_service);
            for (const auto& cred : creds) {
             std::cout << "Service: " << cred.website 
                       << ", Username: " << cred.username 
                       << ", Password: " << cred.password << std::endl;
            }
        });
        
        auto sub_del  = app.add_subcommand("rm", "Remove an entry from the database");
        std::string del_service;
        sub_del->add_option("-s, --service", del_service, "Entry's associated service")->required();
        sub_del->callback([&]() {
            db.delete_entry(del_service);
            std::cout << "deleted entry " << del_service << std::endl;
        });

        app.require_subcommand(1);
        CLI11_PARSE(app, argc, argv);
    }
    catch (const std::exception &e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}