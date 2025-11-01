#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <chrono>

namespace Kerem {
    namespace security {

        // 🛡️ VERİ GÜVENLİĞİ: AES-256 benzeri basit XOR şifreleme
        /**
         * @brief EncryptionHelper - Veritabanında hassas verileri şifreler
         * 
         * NOT: Production ortamı için OpenSSL/CryptoAPI ile AES-256 kullanılmalı
         * Bu implementasyon eğitim amaçlıdır ve temel şifreleme prensiplerini gösterir
         * 
         * Özellikler:
         * - Symmetric encryption (aynı anahtar ile şifreleme/çözme)
         * - Salt kullanımı (her şifreleme farklı salt)
         * - Base64 encoding (veritabanı uyumluluğu)
         */
        class EncryptionHelper {
        public:
            // 🛡️ VERİ GÜVENLİĞİ: Veriyi şifrele
            static std::string encrypt(const std::string& plaintext, const std::string& key) {
                if (plaintext.empty()) return "";
                
                // Salt oluştur (rastgele 8 byte)
                std::vector<uint8_t> salt = generateSalt(8);
                
                // Anahtarı genişlet (key derivation)
                std::vector<uint8_t> derivedKey = deriveKey(key, salt, plaintext.length());
                
                // XOR şifreleme uygula
                std::vector<uint8_t> encrypted;
                encrypted.reserve(salt.size() + plaintext.length());
                
                // Salt'ı başa ekle (decryption için gerekli)
                encrypted.insert(encrypted.end(), salt.begin(), salt.end());
                
                // Şifreleme
                for (size_t i = 0; i < plaintext.length(); ++i) {
                    encrypted.push_back(plaintext[i] ^ derivedKey[i]);
                }
                
                // Base64 encode (veritabanı için güvenli)
                return base64Encode(encrypted);
            }
            
            // 🛡️ VERİ GÜVENLİĞİ: Şifreli veriyi çöz
            static std::string decrypt(const std::string& ciphertext, const std::string& key) {
                if (ciphertext.empty()) return "";
                
                try {
                    // Base64 decode
                    std::vector<uint8_t> encrypted = base64Decode(ciphertext);
                    
                    if (encrypted.size() < 8) {
                        throw std::runtime_error("Invalid ciphertext");
                    }
                    
                    // Salt'ı ayır
                    std::vector<uint8_t> salt(encrypted.begin(), encrypted.begin() + 8);
                    std::vector<uint8_t> data(encrypted.begin() + 8, encrypted.end());
                    
                    // Anahtarı genişlet
                    std::vector<uint8_t> derivedKey = deriveKey(key, salt, data.size());
                    
                    // XOR ile çözme
                    std::string plaintext;
                    plaintext.reserve(data.size());
                    for (size_t i = 0; i < data.size(); ++i) {
                        plaintext += static_cast<char>(data[i] ^ derivedKey[i]);
                    }
                    
                    return plaintext;
                } catch (...) {
                    return ""; // Hatalı şifre veya bozuk veri
                }
            }
            
            // 🛡️ VERİ GÜVENLİĞİ: SHA-256 benzeri hash (veri bütünlüğü için)
            static std::string hash(const std::string& data) {
                // Basit hash algoritması (production için SHA-256 kullanın)
                uint64_t hash1 = 0xcbf29ce484222325ULL; // FNV offset basis
                uint64_t hash2 = 0x100000001b3ULL;      // FNV prime
                
                for (char c : data) {
                    hash1 ^= static_cast<uint8_t>(c);
                    hash1 *= hash2;
                }
                
                std::ostringstream oss;
                oss << std::hex << std::setw(16) << std::setfill('0') << hash1;
                return oss.str();
            }
            
            // 🛡️ VERİ GÜVENLİĞİ: HMAC benzeri (integrity verification)
            static std::string hmac(const std::string& message, const std::string& key) {
                // Basit HMAC implementasyonu
                std::string combined = key + message + key;
                return hash(combined);
            }
            
        private:
            // Salt üretimi
            static std::vector<uint8_t> generateSalt(size_t length) {
                std::vector<uint8_t> salt;
                salt.reserve(length);
                
                // Pseudo-random (production için cryptographic RNG kullanın)
                uint32_t seed = static_cast<uint32_t>(
                    std::chrono::system_clock::now().time_since_epoch().count());
                
                for (size_t i = 0; i < length; ++i) {
                    seed = seed * 1103515245 + 12345; // LCG
                    salt.push_back(static_cast<uint8_t>(seed >> 16));
                }
                
                return salt;
            }
            
            // Key derivation (PBKDF2 benzeri)
            static std::vector<uint8_t> deriveKey(const std::string& key, 
                                                  const std::vector<uint8_t>& salt,
                                                  size_t length) {
                std::vector<uint8_t> derived;
                derived.reserve(length);
                
                std::string material = key;
                for (uint8_t b : salt) {
                    material += static_cast<char>(b);
                }
                
                // Hash iterasyonları
                for (size_t i = 0; i < length; ++i) {
                    uint32_t h = 0;
                    for (size_t j = 0; j < material.length(); ++j) {
                        h = h * 31 + material[j] + i;
                    }
                    derived.push_back(static_cast<uint8_t>(h & 0xFF));
                }
                
                return derived;
            }
            
            // Base64 encoding
            static std::string base64Encode(const std::vector<uint8_t>& data) {
                static const char* base64_chars = 
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                
                std::string encoded;
                encoded.reserve(((data.size() + 2) / 3) * 4);
                
                int val = 0, valb = -6;
                for (uint8_t c : data) {
                    val = (val << 8) + c;
                    valb += 8;
                    while (valb >= 0) {
                        encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
                        valb -= 6;
                    }
                }
                
                if (valb > -6) {
                    encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
                }
                
                while (encoded.size() % 4) {
                    encoded.push_back('=');
                }
                
                return encoded;
            }
            
            // Base64 decoding
            static std::vector<uint8_t> base64Decode(const std::string& encoded) {
                static const int base64_table[256] = {
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
                    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
                    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
                    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
                    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
                    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
                };
                
                std::vector<uint8_t> decoded;
                int val = 0, valb = -8;
                
                for (char c : encoded) {
                    if (c == '=') break;
                    int index = base64_table[static_cast<uint8_t>(c)];
                    if (index == -1) continue;
                    
                    val = (val << 6) + index;
                    valb += 6;
                    if (valb >= 0) {
                        decoded.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
                        valb -= 8;
                    }
                }
                
                return decoded;
            }
        };

    } // namespace security
} // namespace Kerem

#endif // ENCRYPTION_H

