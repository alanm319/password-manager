#include "DatabaseManager.hpp"
#include <iostream>
#include <sqlite3.h>

DatabaseManager::DatabaseManager(const std::string db_name) : db_name_(db_name) {}

DatabaseManager::~DatabaseManager() {
    close_db();
}

bool DatabaseManager::init_db() {
    sqlite3* db = nullptr;
    char* err_msg = nullptr;

    // Open the database
    int rc = sqlite3_open(db_name_.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::string error_message = "Can't open database: " + std::string(sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        throw std::runtime_error(error_message);
    }

    // SQL to create the table
    const char* create_table_sql = R"(
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            password TEXT NOT NULL
        );
    )";

    // Execute the SQL statement
    rc = sqlite3_exec(db, create_table_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string error_message = "Can't create table: " + std::string(err_msg ? err_msg : "Unknown error");
        if (err_msg) sqlite3_free(err_msg);  // Free error message memory
        sqlite3_close(db);                   // Ensure the database handle is closed
        throw std::runtime_error(error_message);
    }

    std::cout << "Successfully initialized database." << std::endl;

    // Close the database
    sqlite3_close(db);
    return true;
}

 void DatabaseManager::add_entry(const std::string& website, const std::string& username,const std::string& password) {
    sqlite3* db;
    sqlite3_stmt* stmt;

    int rc = sqlite3_open(db_name_.c_str(), &db);
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Cannot open db: " + std::string(sqlite3_errmsg(db)));
    }
    std::cout << "1"<<std::endl;
    const char* insert_sql = "INSERT INTO entries (website, username, password) VALUES (?, ?, ?);";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
    std::cout << "Preparing SQL statement: " << insert_sql << std::endl;
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
    }
    
    sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 1, password.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        throw std::runtime_error("Failed to prepapre statement: "+ std::string(sqlite3_errmsg(db)));
    }

    std::cout << "Saved entry to db" << std::endl;

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

std::vector<Entry> DatabaseManager::get_entry(const std::string& website) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    std::vector<Entry> entries;

    int rc = sqlite3_open(db_name_.c_str(), &db);
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Cannot open db:" + std::string(sqlite3_errmsg(db)));
    }

    const char* query_sql = "SELECT service, username, password FROM entries WHERE service = ?;";
    rc = sqlite3_prepare_v2(db, query_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Entry ent;
        ent.website = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ent.website = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        ent.website = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entries.push_back(ent);
    }

    if (entries.empty()) {
        throw std::runtime_error("No credentials found for website: " + website);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return entries;
}

void DatabaseManager::close_db() {

}