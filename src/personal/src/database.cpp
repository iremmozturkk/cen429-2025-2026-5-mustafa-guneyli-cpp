#pragma execution_character_set("utf-8")

#include "../header/database.h"
#include "../header/data_security.hpp"  // 🛡️ Veri Güvenliği modülü
#include "../../sqlite3/sqlite3.h"
#include <iostream>

using namespace Coruh::personal;

DatabaseManager::DatabaseManager() : db(nullptr) {}

DatabaseManager::~DatabaseManager() {
    close();
}

// 🛡️ VERİ GÜVENLİĞİ: Dosya izinlerini sıkılaştır (data_security modülü)
bool DatabaseManager::setSecureFilePermissions(const std::string& dbPath) {
    // DataSecurity modülündeki fonksiyonu kullan
    return Coruh::DataSecurity::setSecureFilePermissions(dbPath);
}

bool DatabaseManager::open(const std::string& dbPath) {
    if (db != nullptr) {
        close();
    }

    // 🛡️ VERİ GÜVENLİĞİ: Güvenli dosya oluşturma
#ifndef _WIN32
    // Unix: umask ile başlangıç izinlerini ayarla
    mode_t old_umask = umask(0077); // rwx------
#endif

    int rc = sqlite3_open(dbPath.c_str(), &db);

#ifndef _WIN32
    umask(old_umask); // Restore
#endif

    if (rc != SQLITE_OK) {
        lastError = sqlite3_errmsg(db);
        sqlite3_close(db);
        db = nullptr;
        return false;
    }

    // 🛡️ VERİ GÜVENLİĞİ: Dosya izinlerini sıkılaştır
    setSecureFilePermissions(dbPath);

    // 🛡️ VERİ GÜVENLİĞİ: SQLite güvenlik pragma'ları
    execute("PRAGMA journal_mode = WAL;");           // Write-Ahead Logging (concurrent access)
    execute("PRAGMA foreign_keys = ON;");            // Foreign key integrity
    execute("PRAGMA secure_delete = ON;");           // Silinen verileri disk'ten temizle
    execute("PRAGMA auto_vacuum = INCREMENTAL;");    // Disk footprint minimize
    execute("PRAGMA temp_store = MEMORY;");          // Geçici dosyalar RAM'de
    execute("PRAGMA synchronous = FULL;");           // Veri bütünlüğü garantisi
    
    // 🛡️ VERİ GÜVENLİĞİ: Busy handler (race condition önleme)
    sqlite3_busy_timeout(db, 5000); // 5 saniye timeout

    return true;
}

void DatabaseManager::close() {
    if (db != nullptr) {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool DatabaseManager::isOpen() const {
    return db != nullptr;
}

bool DatabaseManager::execute(const std::string& sql) {
    if (!isOpen()) {
        lastError = "Database is not open";
        return false;
    }

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
    
    if (rc != SQLITE_OK) {
        lastError = errMsg ? errMsg : "Unknown error";
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

bool DatabaseManager::createTables() {
    if (!isOpen()) {
        return false;
    }

    // Users tablosu (en önce oluşturulmalı - diğer tablolar buna bağımlı)
    std::string sqlUsers = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    )";

    // Budget tablosu (kullanıcıya özel)
    std::string sqlBudget = R"(
        CREATE TABLE IF NOT EXISTS budget (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total_income REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    )";

    // Budget Categories tablosu
    std::string sqlCategories = R"(
        CREATE TABLE IF NOT EXISTS budget_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            limit_amount REAL DEFAULT 0.0,
            spent_amount REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, name)
        );
    )";

    // Investments tablosu
    std::string sqlInvestments = R"(
        CREATE TABLE IF NOT EXISTS investments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            symbol TEXT NOT NULL,
            units REAL DEFAULT 0.0,
            current_price REAL DEFAULT 0.0,
            cost_basis_per_unit REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    )";

    // Goals tablosu
    std::string sqlGoals = R"(
        CREATE TABLE IF NOT EXISTS goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            target_amount REAL DEFAULT 0.0,
            saved_amount REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, name)
        );
    )";

    // Debts tablosu
    std::string sqlDebts = R"(
        CREATE TABLE IF NOT EXISTS debts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            principal REAL DEFAULT 0.0,
            annual_rate_percent REAL DEFAULT 0.0,
            min_monthly_payment REAL DEFAULT 0.0,
            paid_so_far REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    )";

    // Tüm tabloları oluştur
    if (!execute(sqlUsers)) return false;
    if (!execute(sqlBudget)) return false;
    if (!execute(sqlCategories)) return false;
    if (!execute(sqlInvestments)) return false;
    if (!execute(sqlGoals)) return false;
    if (!execute(sqlDebts)) return false;

    return true;
}

bool DatabaseManager::beginTransaction() {
    return execute("BEGIN TRANSACTION;");
}

bool DatabaseManager::commitTransaction() {
    return execute("COMMIT;");
}

bool DatabaseManager::rollbackTransaction() {
    return execute("ROLLBACK;");
}

std::string DatabaseManager::getLastError() const {
    return lastError;
}

