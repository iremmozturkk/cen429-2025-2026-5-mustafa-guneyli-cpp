#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <memory>

// Forward declaration
struct sqlite3;

namespace Coruh {
    namespace personal {

        /**
         * @brief SQLite3 veritabanı yönetimi için wrapper sınıfı
         */
        class DatabaseManager {
        public:
            DatabaseManager();
            ~DatabaseManager();

            // Veritabanını aç/kapat
            bool open(const std::string& dbPath);
            void close();
            bool isOpen() const;

            // Tabloları oluştur (ilk çalıştırmada)
            bool createTables();

            // Transaction yönetimi
            bool beginTransaction();
            bool commitTransaction();
            bool rollbackTransaction();

            // SQL çalıştırma yardımcıları
            bool execute(const std::string& sql);
            sqlite3* getHandle() const { return db; }

            // Hata yönetimi
            std::string getLastError() const;

        private:
            sqlite3* db;
            std::string lastError;

            // Kopyalama ve atamayı engelle
            DatabaseManager(const DatabaseManager&) = delete;
            DatabaseManager& operator=(const DatabaseManager&) = delete;
        };

    } // namespace personal
} // namespace Coruh

#endif // DATABASE_H

