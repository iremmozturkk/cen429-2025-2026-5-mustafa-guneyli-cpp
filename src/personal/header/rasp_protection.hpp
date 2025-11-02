#ifndef RASP_PROTECTION_HPP
#define RASP_PROTECTION_HPP

#include <string>
#include <cstdint>

/**
 * @file rasp_protection.hpp
 * @brief 🛡️ RUNTIME APPLICATION SELF-PROTECTION (RASP) MODÜLÜ
 * 
 * Bu modül, uygulamanın çalışma zamanında kendini korumasını sağlar:
 * - Anti-debug mekanizmaları (debugger tespiti)
 * - Checksum doğrulama (kod bütünlüğü kontrolü)
 * - Tamper tespiti (kod değişiklik tespiti)
 * 
 * Cross-platform: Windows ve Linux desteklenir.
 * 
 * KULLANIM:
 * --------
 * 1. Uygulama başında init() çağrılmalı:
 *    Kerem::personal::rasp::init();
 * 
 * 2. Periyodik kontroller için verify_periodic() kullanılabilir:
 *    auto result = Kerem::personal::rasp::verify_periodic();
 *    if (result != Kerem::personal::rasp::RaspResult::OK) {
 *        // Güvenlik ihlali tespit edildi
 *    }
 * 
 * TEST TALİMATLARI:
 * -----------------
 * 1. Normal çalıştırma: Uygulamayı derleyip çalıştırın -> init() başarılı olmalı
 * 2. Checksum testi: rasp_protection.cpp dosyasını değiştirip tekrar çalıştırın -> 
 *    ERROR_CHECKSUM_MISMATCH ile terminate olmalı
 * 3. Debugger testi: IDE ile debugger attach edin -> ERROR_DEBUGGER_DETECTED ile 
 *    terminate olmalı
 * 
 * NOT: rasp_expected_checksum.h dosyası CMake ile generate edilmelidir.
 */

namespace Kerem {
    namespace personal {
        namespace rasp {

            // ═══════════════════════════════════════════════════════════
            // 🔴 RASPRESULT ENUM - Kontrol Sonuçları
            // ═══════════════════════════════════════════════════════════

            enum class RaspResult : uint8_t {
                OK = 0,                          // ✅ Tüm kontroller başarılı
                ERROR_DEBUGGER_DETECTED = 1,      // 🚨 Debugger tespit edildi
                ERROR_CHECKSUM_MISMATCH = 2,      // 🚨 Dosya checksum'ı eşleşmedi
                ERROR_TAMPER_DETECTED = 3         // 🚨 Kod değişikliği tespit edildi
            };

            // ═══════════════════════════════════════════════════════════
            // 🛡️ RASP FONKSİYONLARI
            // ═══════════════════════════════════════════════════════════

            /**
             * @brief RASP sistemini başlatır ve startup kontrollerini yapar
             * 
             * Uygulama başında bir kez çağrılmalıdır. Şu kontrolleri yapar:
             * 1. Anti-debug kontrolü (is_debugger_present)
             * 2. Checksum doğrulama (executable dosyası)
             * 
             * Herhangi bir kontrol başarısız olursa fail_safe_action() çağrılır
             * ve uygulama terminate edilir.
             */
            void init();

            /**
             * @brief Startup kontrollerini yapar (anti-debug + checksum)
             * @return RaspResult - Kontrol sonucu
             * 
             * Bu fonksiyon init() tarafından çağrılır. Manuel olarak da 
             * çağrılabilir.
             */
            RaspResult verify_startup();

            /**
             * @brief Hafif periyodik kontroller yapar (sadece anti-debug)
             * @return RaspResult - Kontrol sonucu
             * 
             * Checksum kontrolü yapmaz (performans için). Sadece debugger
             * tespiti yapar.
             * 
             * NOT: Timer mekanizması bu modülde yoktur. Ana uygulama 
             * (personal.cpp) sorumludur.
             */
            RaspResult verify_periodic();

            /**
             * @brief Debugger varlığını tespit eder
             * @return true = debugger tespit edildi, false = güvenli
             * 
             * Platform bazlı implementasyon:
             * - Windows: IsDebuggerPresent() + CheckRemoteDebuggerPresent()
             * - Linux: ptrace() veya /proc/self/status kontrolü
             */
            bool is_debugger_present();

            /**
             * @brief Dosyanın SHA256 hash'ini hesaplar
             * @param path Dosya yolu
             * @return SHA256 hash değeri (hex string) veya boş string (hata)
             * 
             * Öncelik sırası:
             * 1. OpenSSL SHA256 kullanır (varsa)
             * 2. Fallback SHA256 implementasyonu (header-only)
             */
            std::string compute_file_sha256(const std::string& path);

            /**
             * @brief Güvenlik ihlali durumunda fail-safe aksiyon alır
             * @param r Hata tipi (RaspResult)
             * 
             * Yapılan işlemler:
             * 1. Güvenlik logu (std::cerr)
             * 2. Hassas bellek temizleme (varsa secure_bzero)
             * 3. std::terminate() çağrısı
             * 
             * NOT: Production'da safe-mode sunulabilir (şu an terminate ediyor).
             */
            void fail_safe_action(RaspResult r);

        } // namespace rasp
    } // namespace personal
} // namespace Kerem

#endif // RASP_PROTECTION_HPP

