#ifndef ASSET_PROTECTION_HPP
#define ASSET_PROTECTION_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <map>
#include <chrono>
#include <functional>

/**
 * @file asset_protection.hpp
 * @brief 🛡️ VARLIK YÖNETİMİ MODÜLÜ - Asset Protection System
 * 
 * Bu modül projedeki tüm varlıkların güvenliğini sağlar:
 * - Statik varlıkların korunması (compile-time sabitler, embedded anahtarlar)
 * - Dinamik varlıkların korunması (runtime bellek, heap varlıkları)
 * - Varlık dokümantasyonu (envanter, audit logları)
 */

namespace Kerem {
    namespace AssetProtection {

        // ═══════════════════════════════════════════════════════════
        // 📊 VARLIK TİPLERİ VE ENUM'LAR
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief Varlık tipi enumeration
         */
        enum class AssetType {
            STATIC_STRING,      ///< Statik string varlık (API key, secret)
            STATIC_KEY,         ///< Kriptografik anahtar
            STATIC_CONFIG,      ///< Konfigürasyon sabiti
            DYNAMIC_MEMORY,     ///< Dinamik bellek varlığı
            DYNAMIC_BUFFER,     ///< Geçici buffer
            DYNAMIC_CREDENTIAL, ///< Runtime credential (şifre, token)
            SENSITIVE_DATA      ///< Hassas veri
        };

        /**
         * @brief Varlık güvenlik seviyesi
         */
        enum class SecurityLevel {
            LOW,        ///< Düşük güvenlik
            MEDIUM,     ///< Orta güvenlik
            HIGH,       ///< Yüksek güvenlik
            CRITICAL    ///< Kritik güvenlik
        };

        /**
         * @brief Varlık durumu
         */
        enum class AssetStatus {
            ACTIVE,     ///< Aktif kullanımda
            PROTECTED,  ///< Korumalı durumda
            DESTROYED,  ///< Yok edildi
            COMPROMISED ///< Tehlikeye girmiş
        };

        // ═══════════════════════════════════════════════════════════
        // 🔒 STATİK VARLIK KORUYUCU
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Statik Varlık Koruyucu Sınıfı
         * 
         * Compile-time sabitlerini ve embedded değerleri korur.
         * XOR obfuscation ve hash doğrulama kullanır.
         */
        class StaticAssetProtector {
        public:
            /**
             * @brief Constructor
             * @param obfuscationKey XOR obfuscation için anahtar
             */
            explicit StaticAssetProtector(uint8_t obfuscationKey = 0x5A);

            /**
             * @brief Destructor
             */
            ~StaticAssetProtector();

            /**
             * @brief String'i XOR ile obfuscate et
             * @param plaintext Orijinal string
             * @return Obfuscated string
             */
            std::string obfuscateString(const std::string& plaintext) const;

            /**
             * @brief Obfuscated string'i deobfuscate et
             * @param obfuscated Obfuscated string
             * @return Orijinal string
             */
            std::string deobfuscateString(const std::string& obfuscated) const;

            /**
             * @brief Compile-time hash hesapla (runtime versiyonu)
             * @param data Hash'lenecek veri
             * @return 32-bit hash değeri
             */
            uint32_t computeHash(const std::string& data) const;

            /**
             * @brief Kritik anahtar koruma (multi-layer obfuscation)
             * @param key Korunacak anahtar
             * @return Korunmuş anahtar
             */
            std::vector<uint8_t> protectKey(const std::vector<uint8_t>& key) const;

            /**
             * @brief Korunmuş anahtarı çöz
             * @param protectedKey Korunmuş anahtar
             * @return Orijinal anahtar
             */
            std::vector<uint8_t> unprotectKey(const std::vector<uint8_t>& protectedKey) const;

            /**
             * @brief Hash doğrulama
             * @param data Doğrulanacak veri
             * @param expectedHash Beklenen hash
             * @return true = eşleşiyor, false = eşleşmiyor
             */
            bool verifyHash(const std::string& data, uint32_t expectedHash) const;

            /**
             * @brief Obfuscation anahtarını değiştir
             * @param newKey Yeni anahtar
             */
            void setObfuscationKey(uint8_t newKey);

        private:
            uint8_t obfuscationKey_;
            
            // Internal helper
            void xorTransform(std::string& data) const;
        };

        // ═══════════════════════════════════════════════════════════
        // 🧠 DİNAMİK VARLIK KORUYUCU
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Dinamik Varlık Koruyucu Sınıfı
         * 
         * Runtime'da oluşturulan hassas verileri korur.
         * Güvenli bellek yönetimi ve canary değerleri kullanır.
         */
        class DynamicAssetProtector {
        public:
            /**
             * @brief Constructor
             */
            DynamicAssetProtector();

            /**
             * @brief Destructor - tüm korumalı belleği temizler
             */
            ~DynamicAssetProtector();

            /**
             * @brief Güvenli bellek ayır
             * @param size Ayırılacak boyut (byte)
             * @return Güvenli bellek pointer, nullptr = hata
             */
            void* secureAllocate(size_t size);

            /**
             * @brief Güvenli bellek serbest bırak (içerik sıfırlanır)
             * @param ptr Bellek pointer
             * @param size Boyut
             */
            void secureFree(void* ptr, size_t size);

            /**
             * @brief Bellek bütünlük kontrolü (canary check)
             * @param ptr Kontrol edilecek bellek
             * @param size Boyut
             * @return true = bütünlük sağlam, false = bozulmuş
             */
            bool checkIntegrity(void* ptr, size_t size) const;

            /**
             * @brief Belleği salt-okunur yap (mümkünse)
             * @param ptr Bellek pointer
             * @param size Boyut
             * @return true = başarılı
             */
            bool protectMemory(void* ptr, size_t size);

            /**
             * @brief Bellek korumasını kaldır (yazılabilir yap)
             * @param ptr Bellek pointer
             * @param size Boyut
             * @return true = başarılı
             */
            bool unprotectMemory(void* ptr, size_t size);

            /**
             * @brief Güvenli string oluştur
             * @param plaintext Orijinal string
             * @return Korumalı string (SecureString benzeri)
             */
            std::string createSecureString(const std::string& plaintext);

            /**
             * @brief Güvenli string'i temizle
             * @param secureStr Temizlenecek string referansı
             */
            void destroySecureString(std::string& secureStr);

            /**
             * @brief Toplam korunan bellek miktarı
             * @return Byte cinsinden boyut
             */
            size_t getProtectedMemorySize() const;

        private:
            struct ProtectedBlock {
                void* ptr;
                size_t size;
                uint32_t canaryStart;
                uint32_t canaryEnd;
                bool isProtected;
            };

            std::vector<ProtectedBlock> protectedBlocks_;
            size_t totalProtectedSize_;

            static const uint32_t CANARY_VALUE = 0xDEADBEEF;
            
            void secureZero(void* ptr, size_t size);
        };

        // ═══════════════════════════════════════════════════════════
        // 📋 VARLIK KAYIT SİSTEMİ (Registry & Documentation)
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief Varlık bilgisi yapısı
         */
        struct AssetInfo {
            std::string id;                 ///< Benzersiz varlık ID
            std::string name;               ///< Varlık adı
            std::string description;        ///< Açıklama
            AssetType type;                 ///< Varlık tipi
            SecurityLevel securityLevel;    ///< Güvenlik seviyesi
            AssetStatus status;             ///< Mevcut durum
            std::string location;           ///< Dosya/bellek konumu
            uint64_t createdAt;             ///< Oluşturulma zamanı (Unix timestamp)
            uint64_t lastAccessedAt;        ///< Son erişim zamanı
            std::string owner;              ///< Sahip/sorumlu

            AssetInfo();
        };

        /**
         * @brief Audit log girişi
         */
        struct AuditLogEntry {
            uint64_t timestamp;             ///< Zaman damgası
            std::string assetId;            ///< Varlık ID
            std::string action;             ///< Gerçekleştirilen eylem
            std::string actor;              ///< Eylemi gerçekleştiren
            std::string details;            ///< Detaylar
            bool success;                   ///< Başarılı mı?

            AuditLogEntry();
        };

        /**
         * @brief 🛡️ Varlık Kayıt Sistemi
         * 
         * Tüm güvenlik varlıklarının envanterini tutar ve
         * erişim loglarını yönetir.
         */
        class AssetRegistry {
        public:
            /**
             * @brief Constructor
             */
            AssetRegistry();

            /**
             * @brief Destructor
             */
            ~AssetRegistry();

            /**
             * @brief Yeni varlık kaydet
             * @param asset Varlık bilgisi
             * @return true = başarılı, false = zaten var veya hata
             */
            bool registerAsset(const AssetInfo& asset);

            /**
             * @brief Varlık kaydını sil
             * @param assetId Varlık ID
             * @return true = başarılı
             */
            bool unregisterAsset(const std::string& assetId);

            /**
             * @brief Varlık bilgisi getir
             * @param assetId Varlık ID
             * @return Varlık bilgisi (bulunamazsa boş AssetInfo)
             */
            AssetInfo getAsset(const std::string& assetId) const;

            /**
             * @brief Varlık var mı kontrol et
             * @param assetId Varlık ID
             * @return true = var
             */
            bool hasAsset(const std::string& assetId) const;

            /**
             * @brief Tüm varlıkları listele
             * @return Varlık listesi
             */
            std::vector<AssetInfo> listAllAssets() const;

            /**
             * @brief Tipe göre varlık listele
             * @param type Varlık tipi
             * @return Filtrelenmiş varlık listesi
             */
            std::vector<AssetInfo> listAssetsByType(AssetType type) const;

            /**
             * @brief Güvenlik seviyesine göre varlık listele
             * @param level Güvenlik seviyesi
             * @return Filtrelenmiş varlık listesi
             */
            std::vector<AssetInfo> listAssetsBySecurityLevel(SecurityLevel level) const;

            /**
             * @brief Varlık durumunu güncelle
             * @param assetId Varlık ID
             * @param newStatus Yeni durum
             * @return true = başarılı
             */
            bool updateAssetStatus(const std::string& assetId, AssetStatus newStatus);

            /**
             * @brief Varlık erişimini logla
             * @param assetId Varlık ID
             * @param action Eylem (READ, WRITE, DELETE vb.)
             * @param actor Eylemi gerçekleştiren
             * @param success Başarılı mı?
             * @param details Ek detaylar
             */
            void logAccess(const std::string& assetId,
                          const std::string& action,
                          const std::string& actor,
                          bool success,
                          const std::string& details = "");

            /**
             * @brief Audit log'ları getir
             * @param limit Maksimum kayıt sayısı (0 = sınırsız)
             * @return Audit log listesi
             */
            std::vector<AuditLogEntry> getAuditLogs(size_t limit = 0) const;

            /**
             * @brief Belirli varlık için audit log'ları getir
             * @param assetId Varlık ID
             * @return Varlığa ait audit log'ları
             */
            std::vector<AuditLogEntry> getAssetAuditLogs(const std::string& assetId) const;

            /**
             * @brief Güvenlik raporu oluştur
             * @return Markdown formatında güvenlik raporu
             */
            std::string generateSecurityReport() const;

            /**
             * @brief Kayıtlı varlık sayısı
             * @return Toplam varlık sayısı
             */
            size_t getAssetCount() const;

            /**
             * @brief Audit log sayısı
             * @return Toplam log sayısı
             */
            size_t getAuditLogCount() const;

            /**
             * @brief Tüm kayıtları temizle
             */
            void clear();

            /**
             * @brief Benzersiz varlık ID'si oluştur
             * @return Benzersiz ID string
             */
            std::string generateAssetId() const;

        private:
            std::map<std::string, AssetInfo> assets_;
            std::vector<AuditLogEntry> auditLogs_;
            
            uint64_t getCurrentTimestamp() const;
        };

        // ═══════════════════════════════════════════════════════════
        // 🔧 YARDIMCI FONKSİYONLAR
        // ═══════════════════════════════════════════════════════════

        /**
         * @brief Varlık tipini string'e çevir
         * @param type Varlık tipi
         * @return String temsili
         */
        std::string assetTypeToString(AssetType type);

        /**
         * @brief Güvenlik seviyesini string'e çevir
         * @param level Güvenlik seviyesi
         * @return String temsili
         */
        std::string securityLevelToString(SecurityLevel level);

        /**
         * @brief Varlık durumunu string'e çevir
         * @param status Varlık durumu
         * @return String temsili
         */
        std::string assetStatusToString(AssetStatus status);

        /**
         * @brief Hızlı string obfuscation (global fonksiyon)
         * @param plaintext Orijinal string
         * @param key XOR anahtarı
         * @return Obfuscated string
         */
        std::string quickObfuscate(const std::string& plaintext, uint8_t key = 0x5A);

        /**
         * @brief Hızlı string deobfuscation (global fonksiyon)
         * @param obfuscated Obfuscated string
         * @param key XOR anahtarı
         * @return Orijinal string
         */
        std::string quickDeobfuscate(const std::string& obfuscated, uint8_t key = 0x5A);

    } // namespace AssetProtection
} // namespace Kerem

#endif // ASSET_PROTECTION_HPP
