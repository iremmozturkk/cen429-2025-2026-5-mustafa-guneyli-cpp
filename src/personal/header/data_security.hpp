#ifndef DATA_SECURITY_HPP
#define DATA_SECURITY_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

/**
 * @file data_security.hpp
 * @brief 🛡️ VERİ GÜVENLİĞİ MODÜLÜ - Merkezi güvenlik yönetimi
 * 
 * Bu modül, projenin tüm veri güvenliği ihtiyaçlarını karşılar:
 * - Depolamada güvenlik (encryption, hashing)
 * - Kullanımda güvenlik (secure memory management)
 * - İletimde güvenlik (data integrity, TLS hazırlık)
 * - Dosya güvenliği (permissions, secure delete)
 */

namespace Kerem {
    namespace DataSecurity {

        // ═══════════════════════════════════════════════════════════
        // 🔐 DEPOLAMADA VERİ GÜVENLİĞİ
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: Veriyi şifreler (AES-256 benzeri)
         * @param plaintext Şifrelenmemiş veri
         * @param key Şifreleme anahtarı
         * @return Base64 encoded şifreli veri
         */
        std::string encryptData(const std::string& plaintext, const std::string& key);

        /**
         * @brief 🛡️ Veri Güvenliği: Şifreli veriyi çözer
         * @param ciphertext Base64 encoded şifreli veri
         * @param key Şifreleme anahtarı
         * @return Orijinal veri
         */
        std::string decryptData(const std::string& ciphertext, const std::string& key);

        /**
         * @brief 🛡️ Veri Güvenliği: PBKDF2 benzeri güçlü password hash
         * @param password Şifre
         * @param iterations Iterasyon sayısı (varsayılan: 10000)
         * @return Hash değeri
         */
        std::string hashPassword(const std::string& password, int iterations = 10000);

        /**
         * @brief 🛡️ Veri Güvenliği: SHA-256 benzeri hash
         * @param data Hash'lenecek veri
         * @return Hash değeri (hex string)
         */
        std::string hashData(const std::string& data);

        /**
         * @brief 🛡️ Veri Güvenliği: HMAC (keyed-hash message authentication)
         * @param message Mesaj
         * @param key Anahtar
         * @return HMAC değeri
         */
        std::string hmacSign(const std::string& message, const std::string& key);

        /**
         * @brief 🛡️ Veri Güvenliği: Güvenli anahtar türetme (kullanıcı bazlı)
         * 
         * Kullanıcı bazlı şifreleme anahtarı türetir. Her kullanıcı için farklı anahtar üretir.
         * Anahtar, username ve password hash'inden türetilir.
         * 
         * @param username Kullanıcı adı
         * @param passwordHash Şifre hash'i (veritabanındaki hash)
         * @return Güvenli şifreleme anahtarı (SecureString olarak saklanmalı)
         */
        std::string deriveEncryptionKey(const std::string& username, const std::string& passwordHash);

        /**
         * @brief 🛡️ Veri Güvenliği: Güvenli anahtar alma (environment variable veya türetilmiş)
         * 
         * Önce environment variable'dan anahtarı okumaya çalışır (EMAIL_ENCRYPTION_KEY).
         * Bulunamazsa, kullanıcı bazlı key derivation kullanır.
         * 
         * @param username Kullanıcı adı (fallback için gerekli)
         * @param passwordHash Şifre hash'i (fallback için gerekli)
         * @return Güvenli şifreleme anahtarı
         */
        std::string getEncryptionKey(const std::string& username = "", const std::string& passwordHash = "");

        // ═══════════════════════════════════════════════════════════
        // 🧠 KULANIMDA VERİ GÜVENLİĞİ (Secure Memory)
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: SecureString sınıfı
         * 
         * Bellekte hassas verileri (şifre, token vb.) güvenli şekilde yönetir.
         * Destructor'da otomatik olarak belleği temizler.
         */
        class SecureString {
        public:
            SecureString();
            explicit SecureString(const std::string& str);
            explicit SecureString(const char* str);
            ~SecureString();

            // 🛡️ Veri Güvenliği: Belleği güvenli şekilde temizle
            void secureClear();

            // Getter
            const std::string& get() const;
            const char* c_str() const;
            size_t length() const;
            bool empty() const;

            // Assignment
            SecureString& operator=(const std::string& str);
            SecureString& operator=(const char* str);

            // 🛡️ Veri Güvenliği: Copy engellendi (güvenlik)
            SecureString(const SecureString&) = delete;
            SecureString& operator=(const SecureString&) = delete;

            // 🛡️ Veri Güvenliği: Move semantics
            SecureString(SecureString&& other) noexcept;
            SecureString& operator=(SecureString&& other) noexcept;

        private:
            std::string data_;
        };

        /**
         * @brief 🛡️ Veri Güvenliği: Bellek bölgesini güvenli temizle
         * @param ptr Bellek adresi
         * @param size Boyut
         */
        void secureZeroMemory(void* ptr, size_t size);

        // ═══════════════════════════════════════════════════════════
        // 📤 İLETİMDE VERİ GÜVENLİĞİ (Data Integrity)
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: Veri paketi (integrity verification)
         */
        struct DataPacket {
            std::string data;           // Asıl veri
            std::string checksum;       // CRC32 checksum
            std::string hmac;           // HMAC imzası
            uint64_t timestamp;         // Unix timestamp

            DataPacket();
            DataPacket(const std::string& d, const std::string& key);

            /**
             * @brief 🛡️ Veri Güvenliği: Paketin bütünlüğünü doğrula
             * @param key HMAC anahtarı
             * @param maxAgeSeconds Maksimum yaş (replay attack önleme)
             * @return true = geçerli, false = bozulmuş/eski
             */
            bool verify(const std::string& key, uint64_t maxAgeSeconds = 300) const;
        };

        /**
         * @brief 🛡️ Veri Güvenliği: CRC32 checksum hesapla
         * @param data Veri
         * @return Checksum (hex string)
         */
        std::string calculateChecksum(const std::string& data);

        /**
         * @brief 🛡️ Veri Güvenliği: Input validation tipleri
         */
        enum class InputType {
            USERNAME,       // 3-32 karakter, alfanumerik
            EMAIL,          // RFC 5322 format
            AMOUNT,         // Sayısal değer
            GENERIC,        // Genel metin (max 1000 char)
            OPTIONAL_FIELD  // İsteğe bağlı
        };

        /**
         * @brief 🛡️ Veri Güvenliği: Input validation (SQL injection önleme)
         * @param input Girdi
         * @param type Validation tipi
         * @return true = geçerli, false = geçersiz
         */
        bool validateInput(const std::string& input, InputType type);

        /**
         * @brief 🛡️ Veri Güvenliği: Tehlikeli karakterleri temizle
         * @param input Girdi
         * @return Temizlenmiş girdi
         */
        std::string sanitizeInput(const std::string& input);

        /**
         * @brief 🛡️ Veri Güvenliği: TLS Context (gelecek network desteği)
         * 
         * Bu sınıf, ileride HTTPS/TLS desteği eklendiğinde kullanılacak.
         * Şu an sadece placeholder/stub implementasyon.
         */
        class TLSContext {
        public:
            TLSContext();
            ~TLSContext();

            void initialize();
            void cleanup();
            
            void setCertificate(const std::string& certPath);
            void setPrivateKey(const std::string& keyPath);
            void setVerifyPeer(bool verify);

        private:
            std::string certificatePath_;
            std::string privateKeyPath_;
            bool verifyPeer_;
        };

        // ═══════════════════════════════════════════════════════════
        // 🔒 DOSYA GÜVENLİĞİ
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: Dosya izinlerini sıkılaştır
         * @param filePath Dosya yolu
         * @return true = başarılı, false = hata
         * 
         * Linux/Unix: chmod 600 (rw-------)
         * Windows: ACL ile sadece owner erişimi
         */
        bool setSecureFilePermissions(const std::string& filePath);

        /**
         * @brief 🛡️ Veri Güvenliği: Dosyayı güvenli şekilde sil
         * @param filePath Dosya yolu
         * @return true = başarılı, false = hata
         * 
         * Dosyayı silmeden önce rastgele verilerle üzerine yazar.
         */
        bool secureDeleteFile(const std::string& filePath);

        /**
         * @brief 🛡️ Veri Güvenliği: Veritabanı yedek al (şifreli)
         * @param dbPath Veritabanı yolu
         * @param backupPath Yedek dosya yolu
         * @param encryptionKey Şifreleme anahtarı
         * @return true = başarılı, false = hata
         */
        bool createEncryptedBackup(const std::string& dbPath,
                                   const std::string& backupPath,
                                   const std::string& encryptionKey);

        /**
         * @brief 🛡️ Veri Güvenliği: Şifreli yedeği geri yükle
         * @param backupPath Yedek dosya yolu
         * @param dbPath Hedef veritabanı yolu
         * @param encryptionKey Şifreleme anahtarı
         * @return true = başarılı, false = hata
         */
        bool restoreEncryptedBackup(const std::string& backupPath,
                                    const std::string& dbPath,
                                    const std::string& encryptionKey);

        // ═══════════════════════════════════════════════════════════
        // 🧾 EKSTRA: LOG İMZALAMA
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: Log kaydı (HMAC imzalı)
         */
        struct SignedLogEntry {
            std::string message;        // Log mesajı
            uint64_t timestamp;         // Unix timestamp
            std::string signature;      // HMAC imzası

            SignedLogEntry();
            SignedLogEntry(const std::string& msg, const std::string& key);
            bool verify(const std::string& key) const;
        };

        /**
         * @brief 🛡️ Veri Güvenliği: İmzalı log kaydet
         * @param message Log mesajı
         * @param logFilePath Log dosya yolu
         * @param signingKey İmza anahtarı
         * @return true = başarılı, false = hata
         */
        bool writeSignedLog(const std::string& message,
                           const std::string& logFilePath,
                           const std::string& signingKey);

        /**
         * @brief 🛡️ Veri Güvenliği: Log dosyasını doğrula
         * @param logFilePath Log dosya yolu
         * @param signingKey İmza anahtarı
         * @return true = bütünlük sağlam, false = değiştirilmiş
         */
        bool verifyLogFile(const std::string& logFilePath,
                          const std::string& signingKey);

        // ═══════════════════════════════════════════════════════════
        // 🔧 YARDIMCI FONKSİYONLAR (Internal)
        // ═══════════════════════════════════════════════════════════

        namespace Internal {
            // Base64 encoding/decoding
            std::string base64Encode(const std::vector<uint8_t>& data);
            std::vector<uint8_t> base64Decode(const std::string& encoded);

            // Salt üretimi
            std::vector<uint8_t> generateSalt(size_t length);

            // Key derivation
            std::vector<uint8_t> deriveKey(const std::string& key,
                                           const std::vector<uint8_t>& salt,
                                           size_t length);

            // Timestamp
            uint64_t getCurrentTimestamp();
        }

    } // namespace DataSecurity
} // namespace Kerem

#endif // DATA_SECURITY_HPP

