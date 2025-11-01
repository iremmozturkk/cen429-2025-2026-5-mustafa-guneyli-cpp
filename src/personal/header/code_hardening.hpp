#ifndef CODE_HARDENING_HPP
#define CODE_HARDENING_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <cstring>
#include <array>
#include <utility>

/**
 * @file code_hardening.hpp
 * @brief 🔒 KOD SERTLEŞTİRME MODÜLÜ - ÖÇ.3 Implementation
 * 
 * Bu modül, kod sertleştirme özelliklerini içerir:
 * - Kontrol akışı gizleme (control-flow flattening + opaque predicates)
 * - String/fonksiyon gizleme (obfuscation, indirect calls)
 * - Bellek koruması (sensitive buffer wipe)
 * 
 * Derleme önerileri:
 * - -fvisibility=hidden
 * - -fstack-protector-strong
 * - -s (strip symbols)
 */

namespace Kerem {
    namespace CodeHardening {

        // ═══════════════════════════════════════════════════════════
        // 🔐 STRING GİZLEME (Obfuscation)
        // ═══════════════════════════════════════════════════════════

        namespace detail {
            /**
             * @brief Compile-time string obfuscation helper
             * Derleme zamanında XOR + rotasyon ile string'i gizle
             */
            // Constexpr obfuscation helper
            inline constexpr char obfuscate_char(uint8_t c) {
                constexpr uint8_t XOR_KEY = 0xAA;
                constexpr int ROTATE_BY = 7;
                c ^= XOR_KEY;
                c = ((c >> ROTATE_BY) | (c << (8 - ROTATE_BY))) & 0xFF;
                return static_cast<char>(c);
            }

            // Runtime obfuscation (MSVC constexpr sorunlarını önlemek için)
            template<size_t N>
            inline std::array<char, N> obfuscate_string(const char(&str)[N]) {
                std::array<char, N> result{};
                for (size_t i = 0; i < N - 1; ++i) {
                    result[i] = obfuscate_char(static_cast<uint8_t>(str[i]));
                }
                result[N - 1] = '\0';
                return result;
            }

            /**
             * @brief String deobfuscation helper (runtime)
             */
            inline std::string unhide_string(const char* obfuscated, size_t len) {
                if (!obfuscated || len == 0) return "";
                
                // XOR key (compile-time constant)
                constexpr uint8_t XOR_KEY = 0xAA;
                
                // Rotate key (compile-time constant)
                constexpr int ROTATE_BY = 7;
                
                std::string result;
                result.reserve(len);
                
                for (size_t i = 0; i < len; ++i) {
                    uint8_t c = static_cast<uint8_t>(obfuscated[i]);
                    // Reverse rotation
                    c = ((c << (8 - ROTATE_BY)) | (c >> ROTATE_BY)) & 0xFF;
                    // Reverse XOR
                    c ^= XOR_KEY;
                    result += static_cast<char>(c);
                }
                
                return result;
            }

            /**
             * @brief Runtime deobfuscation wrapper
             */
            template<size_t N>
            inline std::string unhide_string(const std::array<char, N>& arr) {
                return unhide_string(arr.data(), N - 1);
            }
            
            /**
             * @brief Obfuscated string data structure (runtime initialization)
             */
            template<size_t N>
            struct obfuscated_string_storage {
                std::array<char, N> data;
                
                obfuscated_string_storage(const char(&str)[N]) 
                    : data(obfuscate_string(str)) {}
            };
        } // namespace detail

        /**
         * @brief String gizleme makrosu: XOR/rotasyon ile string'i sakla (runtime obfuscation)
         * @param str String literal
         * @return Deobfuscated string
         */
        #define HIDE_STR(str) []() { \
            static Kerem::CodeHardening::detail::obfuscated_string_storage<sizeof(str)> _obf_storage(str); \
            return Kerem::CodeHardening::detail::unhide_string(_obf_storage.data); \
        }()

        // ═══════════════════════════════════════════════════════════
        // 🛡️ BELLEK KORUMASI (Secure Erase)
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief Güvenli bellek temizleme: string için
         * @param data Temizlenecek string (referans)
         * 
         * Volatile üzerinden byte bazlı sıfırlama yapar,
         * sonrasında shrink_to_fit() çağırır.
         */
        void secure_erase(std::string& data);

        /**
         * @brief Güvenli bellek temizleme: vector için
         * @param data Temizlenecek vector (referans)
         */
        void secure_erase(std::vector<uint8_t>& data);

        // ═══════════════════════════════════════════════════════════
        // 🔀 KONTROL AKIŞI GİZLEME (Control-Flow Flattening)
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief Flatten edilmiş kontrol akışı ile fonksiyon çalıştırma
         * @param taskId Task identifier (switch case için)
         * @param fn Çalıştırılacak fonksiyon (lambda veya function pointer)
         * 
         * Tek while + switch ile flatten edilmiş yürütme.
         * Opaque predicate kullanır.
         */
        void flatten_guarded_execute(int taskId, const std::function<void()>& fn);

        // ═══════════════════════════════════════════════════════════
        // 🔄 FONKSİYON GİZLEME (Indirect Calls)
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief Obfuscated string birleştirme (indirect call örneği)
         * @param a İlk string
         * @param b İkinci string
         * @return Birleştirilmiş string
         */
        std::string obfuscated_join(const std::string& a, const std::string& b);

        /**
         * @brief Hardened string karşılaştırma (flattened akış + opaque predicate)
         * @param a İlk string
         * @param b İkinci string
         * @return true = eşit, false = farklı
         */
        bool hardened_compare(const std::string& a, const std::string& b);

        /**
         * @brief Örnek sertleştirilmiş fonksiyon (test/demo için)
         */
        void harden_sample();

    } // namespace CodeHardening
} // namespace Kerem

// ═══════════════════════════════════════════════════════════
// 📝 LOG MAKROSU (Debug için)
// ═══════════════════════════════════════════════════════════

#ifndef NDEBUG
    #include <iostream>
    #define LOG(...) do { \
        std::cerr << "[HARDEN] "; \
        std::cerr << __VA_ARGS__; \
        std::cerr << std::endl; \
    } while(0)
#else
    #define LOG(...) ((void)0)
#endif

#endif // CODE_HARDENING_HPP

