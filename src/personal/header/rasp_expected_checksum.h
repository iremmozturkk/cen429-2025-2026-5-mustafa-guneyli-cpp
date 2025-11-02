#ifndef RASP_EXPECTED_CHECKSUM_H
#define RASP_EXPECTED_CHECKSUM_H

/**
 * @file rasp_expected_checksum.h
 * @brief RASP Checksum Beklenen Değerleri
 * 
 * BU DOSYA CMake VEYA BUILD SİSTEMİ TARAFINDAN OTOMATİK OLUŞTURULMALIDIR.
 * 
 * Bu dosya, uygulama executable'ının SHA256 hash'ini içerir.
 * RASP sistemi, çalışma zamanında executable'ın checksum'ını hesaplayıp
 * bu değerle karşılaştırır.
 * 
 * NOT: Manuel olarak oluşturulabilir, ancak build sistemi tarafından
 * otomatik generate edilmesi önerilir.
 * 
 * Örnek CMake komutu:
 * ```
 * # Executable'ın SHA256'sını hesapla
 * execute_process(
 *     COMMAND ${CMAKE_COMMAND} -E sha256sum ${CMAKE_CURRENT_BINARY_DIR}/personalapp.exe
 *     OUTPUT_VARIABLE SHA256_OUTPUT
 * )
 * # SHA256_OUTPUT'tan hash'i çıkar ve bu dosyayı generate et
 * ```
 */

// ═══════════════════════════════════════════════════════════════════
// 🔐 BEKLENEN CHECKSUM DEĞERİ
// ═══════════════════════════════════════════════════════════════════

/**
 * @brief Beklenen executable SHA256 hash değeri
 * 
 * Bu değer, build zamanında executable'ın SHA256 hash'i ile doldurulmalıdır.
 * 
 * NOT: İlk build'de bu değer boş bırakılabilir veya placeholder olarak
 * "PLACEHOLDER_CHANGE_ME" kullanılabilir. Production build'lerde mutlaka
 * gerçek hash değeri olmalıdır.
 */
#define RASP_EXPECTED_SHA256 ""

// ═══════════════════════════════════════════════════════════════════
// 📝 KULLANIM NOTU
// ═══════════════════════════════════════════════════════════════════

/**
 * Manuel olarak hash hesaplama (test için):
 * 
 * Windows:
 *   certutil -hashfile personalapp.exe SHA256
 * 
 * Linux:
 *   sha256sum personalapp
 * 
 * Veya OpenSSL:
 *   openssl dgst -sha256 personalapp.exe
 */

#endif // RASP_EXPECTED_CHECKSUM_H

