#ifndef DB_HPP
#define DB_HPP

#include <string>
#include <sqlite3.h>

struct Entry {
    std::string website;
    std::string username;
    std::string password;
};

class DatabaseManager {
public:
    DatabaseManager(const std::string db_name);
    ~DatabaseManager();

    bool init_db();
    void add_entry(const std::string& website, const std::string& username, const std::string& password);
    std::vector<Entry> get_entry(const std::string& website);
    std::vector<Entry> get_all_entries();
    void delete_entry(const std::string& website);
private: 
    sqlite3* db;
    void close_db();
};

#endif