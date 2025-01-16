#ifndef DB_HPP
#define DB_HPP

#include <string>

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
private: 
    std::string db_name_;
    void close_db();
};

#endif