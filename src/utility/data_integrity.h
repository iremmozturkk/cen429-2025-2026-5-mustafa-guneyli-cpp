#ifndef DATA_INTEGRITY_H
#define DATA_INTEGRITY_H

#include <string>
#include <map>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cctype>
#include "encryption.h"

namespace Coruh {
    namespace security {

        // 🛡️ VERİ GÜVENLİĞİ: Veri bütünlüğü doğrulama sistemi
        /**
         * @brief DataIntegrityValidator - İletim sırasında veri bütünlüğünü korur
         * 
         * Özellikler:
         * - Checksum hesaplama (veri değişikliği tespiti)
         * - HMAC doğrulama (integrity + authenticity)
         * - Timestamp kontrolü (replay attack önleme)
         * - TLS placeholder (gelecek network desteği için)
         */
        class DataIntegrityValidator {
        public:
            // 🛡️ VERİ GÜVENLİĞİ: Veri paketi oluştur (checksum ile)
            struct DataPacket {
                std::string data;
                std::string checksum;
                std::string hmac;
                uint64_t timestamp;
                
                DataPacket() : timestamp(0) {}
                
                DataPacket(const std::string& d, const std::string& key)
                    : data(d), timestamp(getCurrentTimestamp()) {
                    
                    // Checksum hesapla
                    checksum = calculateChecksum(d);
                    
                    // HMAC ile bütünlük garantisi
                    std::string payload = d + std::to_string(timestamp);
                    hmac = EncryptionHelper::hmac(payload, key);
                }
                
                // Doğrulama
                bool verify(const std::string& key, uint64_t maxAgeSeconds = 300) const {
                    // Timestamp kontrolü (replay attack önleme)
                    uint64_t now = getCurrentTimestamp();
                    if (now - timestamp > maxAgeSeconds) {
                        return false; // Çok eski paket
                    }
                    
                    // Checksum kontrolü
                    if (calculateChecksum(data) != checksum) {
                        return false; // Veri değiştirilmiş
                    }
                    
                    // HMAC kontrolü
                    std::string payload = data + std::to_string(timestamp);
                    std::string expectedHmac = EncryptionHelper::hmac(payload, key);
                    if (hmac != expectedHmac) {
                        return false; // Bütünlük ihlali
                    }
                    
                    return true;
                }
                
            private:
                static uint64_t getCurrentTimestamp() {
                    return static_cast<uint64_t>(
                        std::chrono::system_clock::now().time_since_epoch().count());
                }
                
                static std::string calculateChecksum(const std::string& data) {
                    // CRC32 benzeri basit checksum
                    uint32_t checksum = 0xFFFFFFFF;
                    for (char c : data) {
                        checksum ^= static_cast<uint8_t>(c);
                        for (int i = 0; i < 8; ++i) {
                            checksum = (checksum >> 1) ^ (0xEDB88320 & -(checksum & 1));
                        }
                    }
                    
                    std::ostringstream oss;
                    oss << std::hex << std::setw(8) << std::setfill('0') << ~checksum;
                    return oss.str();
                }
            };
            
            // 🛡️ VERİ GÜVENLİĞİ: Input validation (SQL injection, XSS önleme)
            static bool validateInput(const std::string& input, InputType type) {
                if (input.empty()) return type == InputType::OPTIONAL;
                
                switch (type) {
                    case InputType::USERNAME:
                        return validateUsername(input);
                    case InputType::EMAIL:
                        return validateEmail(input);
                    case InputType::AMOUNT:
                        return validateAmount(input);
                    case InputType::GENERIC:
                        return validateGeneric(input);
                    case InputType::OPTIONAL:
                        return true;
                    default:
                        return false;
                }
            }
            
            // 🛡️ VERİ GÜVENLİĞİ: SQL injection karakterlerini temizle
            static std::string sanitizeInput(const std::string& input) {
                std::string sanitized;
                sanitized.reserve(input.length());
                
                for (char c : input) {
                    // Tehlikeli karakterleri filtrele
                    if (c == '\'' || c == '\"' || c == ';' || c == '-' || c == '/' || c == '\\') {
                        continue; // Atla
                    }
                    // Kontrol karakterlerini atla
                    if (c < 32 && c != '\t' && c != '\n') {
                        continue;
                    }
                    sanitized += c;
                }
                
                return sanitized;
            }
            
            // 🛡️ VERİ GÜVENLİĞİ: TLS Placeholder (gelecekte ağ bağlantısı için)
            struct TLSContext {
                std::string certificatePath;
                std::string privateKeyPath;
                bool verifyPeer;
                
                TLSContext() : verifyPeer(true) {}
                
                // Gelecekte OpenSSL/SChannel ile implementasyon
                void initialize() {
                    // TODO: TLS initialization
                    // SSL_library_init();
                    // SSL_load_error_strings();
                }
                
                void cleanup() {
                    // TODO: TLS cleanup
                    // EVP_cleanup();
                }
            };
            
            enum class InputType {
                USERNAME,
                EMAIL,
                AMOUNT,
                GENERIC,
                OPTIONAL
            };
            
        private:
            static bool validateUsername(const std::string& username) {
                // 3-32 karakter, alfanumerik ve alt çizgi
                if (username.length() < 3 || username.length() > 32) return false;
                
                for (char c : username) {
                    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
                        return false;
                    }
                }
                return true;
            }
            
            static bool validateEmail(const std::string& email) {
                // Basit email validasyonu
                if (email.length() < 5 || email.length() > 254) return false;
                
                size_t atPos = email.find('@');
                size_t dotPos = email.find_last_of('.');
                
                return (atPos != std::string::npos && 
                        dotPos != std::string::npos &&
                        atPos < dotPos &&
                        dotPos < email.length() - 1);
            }
            
            static bool validateAmount(const std::string& amount) {
                if (amount.empty()) return false;
                
                bool hasDecimal = false;
                for (size_t i = 0; i < amount.length(); ++i) {
                    char c = amount[i];
                    
                    if (c == '.' || c == ',') {
                        if (hasDecimal) return false; // İkinci ondalık işareti
                        hasDecimal = true;
                    } else if (!std::isdigit(static_cast<unsigned char>(c))) {
                        return false;
                    }
                }
                
                return true;
            }
            
            static bool validateGeneric(const std::string& input) {
                // Genel metin girişi (max 1000 karakter)
                if (input.length() > 1000) return false;
                
                // Tehlikeli karakter kontrolü
                const std::string dangerous = "'\";<>{}[]|\\`$";
                for (char c : input) {
                    if (dangerous.find(c) != std::string::npos) {
                        return false;
                    }
                }
                
                return true;
            }
        };

    } // namespace security
} // namespace Coruh

#endif // DATA_INTEGRITY_H

