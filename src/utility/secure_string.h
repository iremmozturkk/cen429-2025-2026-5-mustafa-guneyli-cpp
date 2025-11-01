#ifndef SECURE_STRING_H
#define SECURE_STRING_H

#include <string>
#include <cstring>
#include <cstdlib>
#include <algorithm>

namespace Kerem {
    namespace security {

        // 🛡️ VERİ GÜVENLİĞİ: RAM'de hassas verileri güvenli tutan sınıf
        /**
         * @brief SecureString - Bellekte hassas verileri güvenli şekilde yöneten sınıf
         * 
         * Özellikler:
         * - Destructor'da belleği güvenli şekilde temizler (volatile ile)
         * - Copy constructor devre dışı (veri kopyalanmaz)
         * - Move semantics destekli (verimli kaynak transferi)
         * - Swap operasyonu güvenli
         */
        class SecureString {
        public:
            SecureString() = default;
            
            explicit SecureString(const std::string& str) : data_(str) {}
            
            explicit SecureString(const char* str) : data_(str ? str : "") {}
            
            // Destructor: Belleği güvenli şekilde temizle
            ~SecureString() {
                secureClear();
            }
            
            // 🛡️ VERİ GÜVENLİĞİ: Belleği volatile pointer ile temizleme
            void secureClear() {
                if (!data_.empty()) {
                    // Compiler optimization'ı önlemek için volatile kullan
                    volatile char* ptr = const_cast<char*>(data_.data());
                    std::memset(const_cast<char*>(data_.data()), 0, data_.size());
                    
                    // Ekstra güvenlik: Rastgele değerlerle üzerine yaz
                    for (size_t i = 0; i < data_.size(); ++i) {
                        ptr[i] = static_cast<char>(rand() % 256);
                    }
                    std::memset(const_cast<char*>(data_.data()), 0, data_.size());
                    
                    data_.clear();
                    data_.shrink_to_fit(); // Belleği serbest bırak
                }
            }
            
            // Getter - sadece const reference
            const std::string& get() const { return data_; }
            const char* c_str() const { return data_.c_str(); }
            size_t length() const { return data_.length(); }
            bool empty() const { return data_.empty(); }
            
            // Assignment operators
            SecureString& operator=(const std::string& str) {
                secureClear();
                data_ = str;
                return *this;
            }
            
            SecureString& operator=(const char* str) {
                secureClear();
                data_ = str ? str : "";
                return *this;
            }
            
            // 🛡️ VERİ GÜVENLİĞİ: Copy constructor devre dışı (güvenlik)
            SecureString(const SecureString&) = delete;
            SecureString& operator=(const SecureString&) = delete;
            
            // 🛡️ VERİ GÜVENLİĞİ: Move semantics (verimli kaynak transferi)
            SecureString(SecureString&& other) noexcept : data_(std::move(other.data_)) {
                other.secureClear();
            }
            
            SecureString& operator=(SecureString&& other) noexcept {
                if (this != &other) {
                    secureClear();
                    data_ = std::move(other.data_);
                    other.secureClear();
                }
                return *this;
            }
            
            // Güvenli swap
            void swap(SecureString& other) noexcept {
                data_.swap(other.data_);
            }
            
        private:
            std::string data_;
        };

        // 🛡️ VERİ GÜVENLİĞİ: Herhangi bir bellek bölgesini güvenli şekilde temizle
        inline void secureZeroMemory(void* ptr, size_t size) {
            if (ptr && size > 0) {
                volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
                while (size--) {
                    *p++ = 0;
                }
            }
        }

    } // namespace security
} // namespace Kerem

#endif // SECURE_STRING_H

