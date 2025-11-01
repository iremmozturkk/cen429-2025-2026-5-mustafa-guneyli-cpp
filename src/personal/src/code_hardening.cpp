#pragma execution_character_set("utf-8")

/**
 * @file code_hardening.cpp
 * @brief 🔒 KOD SERTLEŞTİRME MODÜLÜ - ÖÇ.3 Implementation
 * 
 * Bu dosya, kod sertleştirme özelliklerini implement eder:
 * - Kontrol akışı gizleme (control-flow flattening + opaque predicates)
 * - String/fonksiyon gizleme (obfuscation, indirect calls)
 * - Bellek koruması (sensitive buffer wipe)
 * 
 * Derleme önerileri:
 *   -fvisibility=hidden
 *   -fstack-protector-strong
 *   -s (strip symbols)
 */

#include "../header/code_hardening.hpp"
#include <algorithm>
#include <cstring>
#include <random>
#include <array>

namespace Kerem {
    namespace CodeHardening {

        // ═══════════════════════════════════════════════════════════
        // 🛡️ BELLEK KORUMASI (Secure Erase) - IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════

        void secure_erase(std::string& data) {
            if (data.empty()) return;

            // Volatile pointer ile compiler optimization'ı önle
            volatile char* ptr = const_cast<char*>(data.data());
            size_t len = data.length();

            // Byte bazlı sıfırlama (volatile üzerinden)
            for (size_t i = 0; i < len; ++i) {
                ptr[i] = 0;
            }

            // Rastgele değerlerle üzerine yaz (ekstra güvenlik)
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<unsigned int> dis(0, 255);
            
            for (size_t i = 0; i < len; ++i) {
                ptr[i] = static_cast<char>(dis(gen) & 0xFF);
            }

            // Tekrar sıfırla
            for (size_t i = 0; i < len; ++i) {
                ptr[i] = 0;
            }

            // Belleği serbest bırak
            data.clear();
            data.shrink_to_fit();
        }

        void secure_erase(std::vector<uint8_t>& data) {
            if (data.empty()) return;

            // Volatile pointer ile compiler optimization'ı önle
            volatile uint8_t* ptr = data.data();
            size_t len = data.size();

            // Byte bazlı sıfırlama (volatile üzerinden)
            for (size_t i = 0; i < len; ++i) {
                ptr[i] = 0;
            }

            // Rastgele değerlerle üzerine yaz (ekstra güvenlik)
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<unsigned int> dis(0, 255);
            
            for (size_t i = 0; i < len; ++i) {
                ptr[i] = static_cast<uint8_t>(dis(gen) & 0xFF);
            }

            // Tekrar sıfırla
            for (size_t i = 0; i < len; ++i) {
                ptr[i] = 0;
            }

            // Belleği serbest bırak
            data.clear();
            data.shrink_to_fit();
        }

        // ═══════════════════════════════════════════════════════════
        // 🔀 KONTROL AKIŞI GİZLEME - IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════

        void flatten_guarded_execute(int taskId, const std::function<void()>& fn) {
            if (!fn) return;

            // Flatten edilmiş kontrol akışı
            // Tek while + switch ile düzleştirilmiş yürütme
            
            // State variable (opaque predicate için)
            int state = taskId;
            int nextState = 0;
            bool done = false;

            // OPAQUE PREDICATE 1: (x*x + 1) % 1 == 0 (her zaman true)
            // Statik analizde anlaşılması zor
            constexpr int opaque_constant = 42;
            bool predicate1 = ((opaque_constant * opaque_constant + 1) % 1 == 0); // Always true
            bool predicate2 = false;

            // OPAQUE PREDICATE 2: x != 0 && x == x (her zaman true if x != 0)
            if (state != 0) {
                predicate2 = (state != 0 && state == state); // Always true if state != 0
            }

            // While loop ile flatten edilmiş akış
            while (!done) {
                // Opaque predicate kontrolü
                if (!predicate1 || (state == 0 && !predicate2)) {
                    // Bu dal asla çalışmaz (opaque predicate her zaman true)
                    state = -1;
                    break;
                }

                // Switch ile task dispatch
                switch (state) {
                    case 0:
                        // Initial state - direkt başlat
                        nextState = taskId;
                        state = nextState;
                        continue;

                    case 1:
                        // Task 1: Execute function
                        fn();
                        nextState = 99; // Done state
                        break;

                    case 2:
                        // Task 2: Alternative path (aynı işi yapar ama farklı yol)
                        fn();
                        nextState = 99;
                        break;

                    case 99:
                        // Done state
                        done = true;
                        break;

                    default:
                        // Fallback: Execute and done
                        fn();
                        nextState = 99;
                        break;
                }

                // OPAQUE PREDICATE 3: Loop control
                // (x & 1) != (x % 2) is always false (bit manipulation vs modulo)
                int check = state;
                bool predicate3 = ((check & 1) != (check % 2)); // Always false
                
                if (predicate3) {
                    // Bu dal asla çalışmaz
                    state = -1;
                    break;
                }

                state = nextState;
            }

            // Cleanup (RAII garantisi)
            state = 0;
            nextState = 0;
        }

        // ═══════════════════════════════════════════════════════════
        // 🔄 FONKSİYON GİZLEME (Indirect Calls) - IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════

        // Indirect function call helpers (sembol görünürlüğünü azaltır)
        namespace detail {
            // String birleştirme fonksiyon pointer'ları
            using StringJoinFunc = std::string(*)(const std::string&, const std::string&);

            // Obfuscated function dispatch
            StringJoinFunc get_join_func(int selector) {
                // Opaque predicate ile selector değiştir
                int masked = selector ^ 0x5A; // XOR mask
                masked = masked + (masked * 2); // Arithmetic obfuscation

                // Function table (indirect dispatch)
                static const StringJoinFunc funcs[] = {
                    [](const std::string& a, const std::string& b) -> std::string {
                        return a + b;
                    },
                    [](const std::string& a, const std::string& b) -> std::string {
                        std::string result;
                        result.reserve(a.length() + b.length());
                        result = a;
                        result += b;
                        return result;
                    },
                    [](const std::string& a, const std::string& b) -> std::string {
                        std::string result(a);
                        result.append(b);
                        return result;
                    }
                };

                // Opaque predicate: (selector % 3) != ((selector * 2) % 3) if selector % 3 == 0
                int idx = selector % 3;
                if ((idx == 0) && ((selector * 2) % 3) != 0) {
                    // Always true when idx == 0
                    idx = 0;
                }

                return funcs[idx % 3];
            }
        } // namespace detail

        std::string obfuscated_join(const std::string& a, const std::string& b) {
            // Indirect call (function pointer)
            int selector = static_cast<int>(a.length() + b.length());
            detail::StringJoinFunc func = detail::get_join_func(selector);
            
            return func(a, b);
        }

        bool hardened_compare(const std::string& a, const std::string& b) {
            // Flatten edilmiş karşılaştırma + opaque predicate
            if (a.length() != b.length()) {
                return false;
            }

            // Indirect comparison function
            using CompareFunc = bool(*)(const std::string&, const std::string&);
            
            CompareFunc compare_func = [](const std::string& x, const std::string& y) -> bool {
                // Flatten edilmiş karşılaştırma
                int state = 0;
                bool result = false;
                bool done = false;
                size_t idx = 0;

                // OPAQUE PREDICATE: (x*x) % x == 0 if x != 0 (her zaman true)
                int len = static_cast<int>(x.length());
                bool predicate = (len != 0) && ((len * len) % len == 0); // Always true if len != 0

                while (!done && predicate) {
                    switch (state) {
                        case 0:
                            // Init
                            idx = 0;
                            result = true;
                            state = 1;
                            break;

                        case 1:
                            // Compare loop
                            if (idx < x.length()) {
                                if (x[idx] != y[idx]) {
                                    result = false;
                                    state = 99;
                                } else {
                                    ++idx;
                                    state = 1; // Continue
                                }
                            } else {
                                state = 99;
                            }
                            break;

                        case 99:
                            done = true;
                            break;
                    }
                }

                return result;
            };

            // Flatten edilmiş execute ile karşılaştırma
            bool comparison_result = false;
            flatten_guarded_execute(1, [&]() {
                comparison_result = compare_func(a, b);
            });

            return comparison_result;
        }

        void harden_sample() {
            // Örnek kullanım: String obfuscation + indirect call + secure erase
            
            // Obfuscated string kullan (HIDE_STR makrosu kullanılmalı ama burada manuel örnek)
            // Not: HIDE_STR compile-time obfuscation için, runtime'da örnek gösterimi:
            
            // Geçici buffer (RAII ile otomatik temizlenecek)
            std::string sensitive_data = "sensitive_information_here";
            std::vector<uint8_t> sensitive_buffer(sensitive_data.begin(), sensitive_data.end());

            // HIDE_STR kullanımı (runtime obfuscated)
            static Kerem::CodeHardening::detail::obfuscated_string_storage<sizeof("Starting hardened operation")> msg1_storage("Starting hardened operation");
            LOG(Kerem::CodeHardening::detail::unhide_string(msg1_storage.data).c_str());

            // Flatten edilmiş execute ile işlem
            flatten_guarded_execute(1, [&]() {
                // Hardened compare kullan
                std::string test1 = "test";
                std::string test2 = "test";
                bool matches = hardened_compare(test1, test2);
                (void)matches; // Unused warning suppression

                // Obfuscated join kullan (string obfuscation ile)
                static Kerem::CodeHardening::detail::obfuscated_string_storage<sizeof("prefix")> prefix_storage("prefix");
                static Kerem::CodeHardening::detail::obfuscated_string_storage<sizeof("_suffix")> suffix_storage("_suffix");
                std::string prefix = Kerem::CodeHardening::detail::unhide_string(prefix_storage.data);
                std::string suffix = Kerem::CodeHardening::detail::unhide_string(suffix_storage.data);
                std::string joined = obfuscated_join(prefix, suffix);
                secure_erase(prefix);
                secure_erase(suffix);
                secure_erase(joined);
            });

            // Hassas verileri temizle
            secure_erase(sensitive_data);
            secure_erase(sensitive_buffer);

            static Kerem::CodeHardening::detail::obfuscated_string_storage<sizeof("Hardened operation completed")> msg2_storage("Hardened operation completed");
            LOG(Kerem::CodeHardening::detail::unhide_string(msg2_storage.data).c_str());
        }

    } // namespace CodeHardening
} // namespace Kerem

