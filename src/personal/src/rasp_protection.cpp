#pragma execution_character_set("utf-8")

/**
 * @file rasp_protection.cpp
 * @brief 🛡️ RUNTIME APPLICATION SELF-PROTECTION (RASP) MODÜLÜ - Implementation
 * 
 * Bu dosya, RASP tekniklerinin implementasyonunu içerir:
 * - Anti-debug mekanizmaları (Windows/Linux)
 * - Checksum doğrulama (SHA256)
 * - Tamper tespiti
 * 
 * Cross-platform: Windows ve Linux desteklenir.
 * 
 * KULLANIM:
 * --------
 * Uygulama başında init() çağrılmalı:
 *   Kerem::personal::rasp::init();
 * 
 * TEST TALİMATLARI:
 * -----------------
 * 1. Normal çalıştırma:
 *    - Derleyip uygulamayı çalıştırın
 *    - init() başarılı olmalı (console'da hata olmamalı)
 * 
 * 2. Checksum testi:
 *    - rasp_protection.cpp içeriğini değiştirin (ör: yorum ekleyin)
 *    - Uygulamayı yeniden derleyip çalıştırın
 *    - ERROR_CHECKSUM_MISMATCH ile terminate olmalı
 * 
 * 3. Debugger testi:
 *    - Visual Studio/CLion ile debugger attach edin
 *    - Uygulamayı debug modda çalıştırın
 *    - ERROR_DEBUGGER_DETECTED ile terminate olmalı
 * 
 * NOT: rasp_expected_checksum.h dosyası CMake ile generate edilmelidir.
 *      İlk build'de placeholder olabilir.
 */

#include "../header/rasp_protection.hpp"
#include "../header/fallback_sha256.hpp"
#include "../header/rasp_expected_checksum.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <cctype>

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
    #include <psapi.h>
    #pragma comment(lib, "psapi.lib")
#else
    #include <unistd.h>
    #include <sys/ptrace.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <cstdio>
    #include <cstring>
#endif

// OpenSSL kontrolü (optional)
#ifdef USE_OPENSSL
    #include <openssl/sha.h>
    #define HAS_OPENSSL 1
#else
    #define HAS_OPENSSL 0
    // OpenSSL yoksa fallback kullanılacak
#endif

namespace Kerem {
    namespace personal {
        namespace rasp {

            // ═══════════════════════════════════════════════════════════
            // 🔧 YARDIMCI FONKSİYONLAR
            // ═══════════════════════════════════════════════════════════

            namespace detail {

                /**
                 * @brief Executable dosya yolunu alır (platform-specific)
                 * @return Executable dosya yolu veya boş string (hata)
                 */
                std::string get_executable_path() {
#ifdef _WIN32
                    char path[MAX_PATH];
                    DWORD length = GetModuleFileNameA(NULL, path, MAX_PATH);
                    if (length == 0 || length >= MAX_PATH) {
                        std::cerr << "[RASP] Error: Cannot get executable path (Windows)" << std::endl;
                        return "";
                    }
                    return std::string(path);
#else
                    // Linux: /proc/self/exe symlink'ini oku
                    char path[1024] = {0};
                    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
                    if (length == -1) {
                        std::cerr << "[RASP] Error: Cannot get executable path (Linux)" << std::endl;
                        // Fallback: __FILE__ kullan (rasp_protection.cpp'nin yolu)
                        return __FILE__;
                    }
                    path[length] = '\0';
                    return std::string(path);
#endif
                }

                /**
                 * @brief Dosyayı byte array olarak okur
                 * @param path Dosya yolu
                 * @return Dosya içeriği (byte vector) veya boş vector (hata)
                 */
                std::vector<uint8_t> read_file_bytes(const std::string& path) {
                    std::vector<uint8_t> data;
                    std::ifstream file(path, std::ios::binary | std::ios::ate);
                    
                    if (!file.is_open()) {
                        std::cerr << "[RASP] Error: Cannot open file: " << path << std::endl;
                        return data;
                    }
                    
                    std::streamsize size = file.tellg();
                    file.seekg(0, std::ios::beg);
                    
                    data.resize(static_cast<size_t>(size));
                    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
                        std::cerr << "[RASP] Error: Cannot read file: " << path << std::endl;
                        data.clear();
                        return data;
                    }
                    
                    return data;
                }

            } // namespace detail

            // ═══════════════════════════════════════════════════════════
            // 🛡️ OPENSSL SHA256 veya FALLBACK
            // ═══════════════════════════════════════════════════════════

            std::string compute_file_sha256(const std::string& path) {
                // Dosyayı oku
                std::vector<uint8_t> file_data = detail::read_file_bytes(path);
                if (file_data.empty()) {
                    return "";
                }

#if HAS_OPENSSL
                // OpenSSL SHA256 kullan
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256_CTX sha256;
                
                if (SHA256_Init(&sha256) != 1) {
                    std::cerr << "[RASP] Error: SHA256_Init failed" << std::endl;
                    return "";
                }
                
                if (SHA256_Update(&sha256, file_data.data(), file_data.size()) != 1) {
                    std::cerr << "[RASP] Error: SHA256_Update failed" << std::endl;
                    return "";
                }
                
                if (SHA256_Final(hash, &sha256) != 1) {
                    std::cerr << "[RASP] Error: SHA256_Final failed" << std::endl;
                    return "";
                }
                
                // Hex string'e çevir
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
                }
                
                return oss.str();
#else
                // Fallback SHA256 kullan
                return detail::fallback_sha256(file_data);
#endif
            }

            // ═══════════════════════════════════════════════════════════
            // 🔍 ANTI-DEBUG MEKANİZMALARI (Platform-specific)
            // ═══════════════════════════════════════════════════════════

            bool is_debugger_present() {
#ifdef _WIN32
                // Windows: IsDebuggerPresent() API
                if (IsDebuggerPresent() != FALSE) {
                    std::cout << "[RASP] Debugger detected: IsDebuggerPresent()" << std::endl;
                    std::cout.flush();
                    return true;
                }
                
                // Windows: CheckRemoteDebuggerPresent()
                BOOL remote_debugger = FALSE;
                if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger) != 0) {
                    if (remote_debugger != FALSE) {
                        std::cout << "[RASP] Debugger detected: CheckRemoteDebuggerPresent()" << std::endl;
                        std::cout.flush();
                        return true;
                    }
                }
                
                return false;
#else
                // Linux: ptrace() kontrolü
                // PTRACE_TRACEME, parent process'e attach edilirse başarısız olur
                if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
                    // ptrace başarısız oldu -> muhtemelen debugger var
                    std::cout << "[RASP] Debugger detected: ptrace() failed" << std::endl;
                    std::cout.flush();
                    return true;
                }
                
                // ptrace başarılı oldu, şimdi kendimizi detach edelim
                ptrace(PTRACE_DETACH, 0, 1, 0);
                
                // Alternatif: /proc/self/status içinde TracerPid kontrolü
                std::ifstream status_file("/proc/self/status");
                if (status_file.is_open()) {
                    std::string line;
                    while (std::getline(status_file, line)) {
                        if (line.find("TracerPid:") == 0) {
                            // TracerPid: 0 = no tracer, >0 = debugger attached
                            size_t pos = line.find_first_of("0123456789");
                            if (pos != std::string::npos) {
                                int tracer_pid = std::stoi(line.substr(pos));
                                if (tracer_pid != 0) {
                                    std::cout << "[RASP] Debugger detected: TracerPid = " << tracer_pid << std::endl;
                                    std::cout.flush();
                                    status_file.close();
                                    return true;
                                }
                            }
                            break;
                        }
                    }
                    status_file.close();
                }
                
                return false;
#endif
            }

            // ═══════════════════════════════════════════════════════════
            // ✅ STARTUP DOĞRULAMA
            // ═══════════════════════════════════════════════════════════

            RaspResult verify_startup() {
                // 1. Anti-debug kontrolü
                if (is_debugger_present()) {
#ifdef NDEBUG
                    // Release build: Tam koruma - terminate et
                    return RaspResult::ERROR_DEBUGGER_DETECTED;
#else
                    // Debug build: Sadece uyarı ver, devam et (development için)
                    std::cout << "[RASP] Warning: Debugger detected, but continuing in debug mode" << std::endl;
                    std::cout << "[RASP] Note: In release builds, this would terminate the application" << std::endl;
                    std::cout.flush();
                    return RaspResult::OK;
#endif
                }
                
                // 2. Checksum doğrulama
                std::string executable_path = detail::get_executable_path();
                if (executable_path.empty()) {
                    // Executable path alınamadı, checksum kontrolü yapamıyoruz
                    std::cout << "[RASP] Error: Cannot get executable path!" << std::endl;
                    std::cout.flush();
#ifdef NDEBUG
                    // Release build: Sıkı güvenlik - terminate et
                    return RaspResult::ERROR_TAMPER_DETECTED;
#else
                    // Debug build: Uyarı ver, devam et (development için)
                    std::cout << "[RASP] Warning: Continuing in debug mode, but this would fail in release builds" << std::endl;
                    std::cout.flush();
                    return RaspResult::OK;
#endif
                }
                
                // SHA256 hesapla
                std::string computed_hash = compute_file_sha256(executable_path);
                if (computed_hash.empty()) {
                    std::cout << "[RASP] Error: Cannot compute file SHA256!" << std::endl;
                    std::cout.flush();
#ifdef NDEBUG
                    // Release build: Sıkı güvenlik - terminate et
                    return RaspResult::ERROR_TAMPER_DETECTED;
#else
                    // Debug build: Uyarı ver, devam et (development için)
                    std::cout << "[RASP] Warning: Continuing in debug mode, but this would fail in release builds" << std::endl;
                    std::cout.flush();
                    return RaspResult::OK;
#endif
                }
                
                // Beklenen hash ile karşılaştır
                std::string expected_hash = RASP_EXPECTED_SHA256;
                
                // Eğer expected_hash boş veya placeholder ise
                if (expected_hash.empty() || expected_hash == "PLACEHOLDER_CHANGE_ME") {
                    std::cout << "[RASP] Warning: Expected SHA256 is empty or placeholder" << std::endl;
                    std::cout << "[RASP] Computed SHA256: " << computed_hash << std::endl;
                    std::cout << "[RASP] Note: This is expected on first build. Update RASP_EXPECTED_SHA256 for production." << std::endl;
                    std::cout.flush();
#ifdef NDEBUG
                    // Release build: Placeholder olmamalı - production'da hash mutlaka olmalı
                    std::cout << "[RASP] Error: Expected SHA256 is not configured! Production builds require valid checksum." << std::endl;
                    std::cout.flush();
                    return RaspResult::ERROR_TAMPER_DETECTED;
#else
                    // Debug build: İlk build için placeholder normal, sadece uyarı ver
                    return RaspResult::OK;
#endif
                }
                
                // Hash karşılaştırma (case-insensitive)
                std::string computed_lower = computed_hash;
                std::string expected_lower = expected_hash;
                std::transform(computed_lower.begin(), computed_lower.end(), computed_lower.begin(), ::tolower);
                std::transform(expected_lower.begin(), expected_lower.end(), expected_lower.begin(), ::tolower);
                
                if (computed_lower != expected_lower) {
                    std::cout << "[RASP] Checksum mismatch!" << std::endl;
                    std::cout << "[RASP] Expected: " << expected_hash << std::endl;
                    std::cout << "[RASP] Computed:  " << computed_hash << std::endl;
                    std::cout.flush();
                    return RaspResult::ERROR_CHECKSUM_MISMATCH;
                }
                
                std::cout << "[RASP] Startup verification OK" << std::endl;
                std::cout.flush();
                return RaspResult::OK;
            }

            // ═══════════════════════════════════════════════════════════
            // ⏰ PERİYODİK KONTROL (Hafif)
            // ═══════════════════════════════════════════════════════════

            RaspResult verify_periodic() {
                // Sadece anti-debug kontrolü (checksum çok yavaş olabilir)
                if (is_debugger_present()) {
#ifdef NDEBUG
                    // Release build: Tam koruma - terminate et
                    return RaspResult::ERROR_DEBUGGER_DETECTED;
#else
                    // Debug build: Sadece uyarı ver, devam et
                    std::cout << "[RASP] Warning: Debugger detected in periodic check (debug mode)" << std::endl;
                    std::cout.flush();
                    return RaspResult::OK;
#endif
                }
                
                return RaspResult::OK;
            }

            // ═══════════════════════════════════════════════════════════
            // 🚨 FAIL-SAFE ACTION
            // ═══════════════════════════════════════════════════════════

            void fail_safe_action(RaspResult r) {
                // Güvenlik logu
                std::cerr << std::endl;
                std::cerr << "═══════════════════════════════════════════════════════" << std::endl;
                std::cerr << "🚨 RASP SECURITY VIOLATION DETECTED" << std::endl;
                std::cerr << "═══════════════════════════════════════════════════════" << std::endl;
                
                switch (r) {
                    case RaspResult::ERROR_DEBUGGER_DETECTED:
                        std::cerr << "Reason: Debugger detected (anti-debug violation)" << std::endl;
                        break;
                    case RaspResult::ERROR_CHECKSUM_MISMATCH:
                        std::cerr << "Reason: Checksum mismatch (code tampering detected)" << std::endl;
                        break;
                    case RaspResult::ERROR_TAMPER_DETECTED:
                        std::cerr << "Reason: Tamper detected (code modification)" << std::endl;
                        break;
                    default:
                        std::cerr << "Reason: Unknown security violation" << std::endl;
                        break;
                }
                
                std::cerr << "Action: Terminating application..." << std::endl;
                std::cerr << "═══════════════════════════════════════════════════════" << std::endl;
                std::cerr << std::endl;
                
                // NOT: Production'da secure_bzero() ile hassas bellek temizlenebilir
                // Şu an için sadece terminate ediyoruz
                
                // std::terminate() çağır (sadece release build'de buraya gelir)
                // Debug build'de zaten verify_startup() OK döndürüyor
                std::terminate();
            }

            // ═══════════════════════════════════════════════════════════
            // 🚀 INIT - RASP BAŞLATMA
            // ═══════════════════════════════════════════════════════════

            void init() {
                // std::cout kullan (std::cerr yerine) - daha görünür ve buffer flush ile
                std::cout << "[RASP] Initializing Runtime Application Self-Protection..." << std::endl;
                std::cout.flush();  // Buffer'ı hemen boşalt, mesajların görünmesini garanti et
                
                RaspResult result = verify_startup();
                
                if (result != RaspResult::OK) {
                    fail_safe_action(result);
                    // fail_safe_action std::terminate() çağırır, buraya gelmez
                    return;
                }
                
                std::cout << "[RASP] RASP initialized successfully" << std::endl;
                std::cout.flush();  // Buffer'ı hemen boşalt
            }

        } // namespace rasp
    } // namespace personal
} // namespace Kerem

