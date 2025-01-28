#include "DatabaseManager.hpp"
#include <sqlite3.h>
#include <stdexcept>
#include <iostream>
#include <vector>

DatabaseManager::DatabaseManager(const std::string db_name) : db(nullptr) {
    if (sqlite3_open(db_name.c_str(), &db) != SQLITE_OK) {
        throw std::runtime_error("Failed to open database: " + std::string(sqlite3_errmsg(db)));
    }
}

DatabaseManager::~DatabaseManager() {
    close_db();
}

bool DatabaseManager::init_db() {
    const std::string createTableQuery = R"(
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
    )";

    char* errMsg = nullptr;
    if (sqlite3_exec(db, createTableQuery.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL Error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

void DatabaseManager::add_entry(const std::string& website, const std::string& username, const std::string& password) {
    const std::string insertQuery = R"(
        INSERT INTO entries (website, username, password) VALUES (?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insertQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
    }

    if (sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, password.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to bind values to statement: " + std::string(sqlite3_errmsg(db)));
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to execute statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_finalize(stmt);
}

std::vector<Entry> DatabaseManager::get_entry(const std::string& website) {
    const std::string selectQuery = R"(
        SELECT website, username, password FROM entries WHERE website = ?;
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, selectQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
    }

    if (sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to bind values to statement: " + std::string(sqlite3_errmsg(db)));
    }

    std::vector<Entry> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Entry entry;
        entry.website = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        results.push_back(entry);
    }

    sqlite3_finalize(stmt);
    return results;
}

std::vector<Entry> DatabaseManager::get_all_entries() {
    const std::string selectAllQuery = R"(
        SELECT website, username, password FROM entries;
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, selectAllQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
    }

    std::vector<Entry> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Entry entry;
        entry.website = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        results.push_back(entry);
    }

    sqlite3_finalize(stmt);
    return results;
}

void DatabaseManager::delete_entry(const std::string& website) {
    const std::string deleteQuery = R"(
        DELETE FROM credentials WHERE website = ?;
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, deleteQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare delete statement: " + std::string(sqlite3_errmsg(db)));
    }

    if (sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to bind values to delete statement: " + std::string(sqlite3_errmsg(db)));
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to execute delete statement: " + std::string(sqlite3_errmsg(db)));
    }

    sqlite3_finalize(stmt);
}

void DatabaseManager::close_db() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}
