/**
 * @file asset_protection.cpp
 * @brief 🛡️ VARLIK YÖNETİMİ MODÜLÜ - Implementation
 * 
 * Statik ve dinamik varlıkların korunması, varlık dokümantasyonu
 */

#include "asset_protection.hpp"
#include <cstring>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace Kerem {
    namespace AssetProtection {

        // ═══════════════════════════════════════════════════════════
        // 🔒 STATİK VARLIK KORUYUCU IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════

        StaticAssetProtector::StaticAssetProtector(uint8_t obfuscationKey)
            : obfuscationKey_(obfuscationKey) {
        }

        StaticAssetProtector::~StaticAssetProtector() {
            // Anahtarı güvenli şekilde temizle
            obfuscationKey_ = 0;
        }

        std::string StaticAssetProtector::obfuscateString(const std::string& plaintext) const {
            std::string result = plaintext;
            xorTransform(result);
            return result;
        }

        std::string StaticAssetProtector::deobfuscateString(const std::string& obfuscated) const {
            // XOR kendisinin tersidir
            std::string result = obfuscated;
            xorTransform(result);
            return result;
        }

        void StaticAssetProtector::xorTransform(std::string& data) const {
            for (size_t i = 0; i < data.size(); ++i) {
                // Multi-byte XOR için pozisyon bazlı rotasyon
                uint8_t key = obfuscationKey_ ^ static_cast<uint8_t>(i & 0xFF);
                data[i] = static_cast<char>(static_cast<uint8_t>(data[i]) ^ key);
            }
        }

        uint32_t StaticAssetProtector::computeHash(const std::string& data) const {
            // FNV-1a hash algoritması (32-bit)
            uint32_t hash = 2166136261u; // FNV offset basis
            const uint32_t prime = 16777619u; // FNV prime

            for (char c : data) {
                hash ^= static_cast<uint32_t>(static_cast<uint8_t>(c));
                hash *= prime;
            }

            return hash;
        }

        std::vector<uint8_t> StaticAssetProtector::protectKey(const std::vector<uint8_t>& key) const {
            std::vector<uint8_t> protected_key;
            protected_key.reserve(key.size() + 4); // +4 for checksum

            // Hash hesapla (bütünlük kontrolü için)
            uint32_t checksum = 0;
            for (uint8_t byte : key) {
                checksum = (checksum << 5) + checksum + byte;
            }

            // Checksum'u başa ekle
            protected_key.push_back(static_cast<uint8_t>((checksum >> 24) & 0xFF));
            protected_key.push_back(static_cast<uint8_t>((checksum >> 16) & 0xFF));
            protected_key.push_back(static_cast<uint8_t>((checksum >> 8) & 0xFF));
            protected_key.push_back(static_cast<uint8_t>(checksum & 0xFF));

            // Anahtarı XOR ile obfuscate et
            for (size_t i = 0; i < key.size(); ++i) {
                uint8_t xorKey = obfuscationKey_ ^ static_cast<uint8_t>((i * 7 + 13) & 0xFF);
                protected_key.push_back(key[i] ^ xorKey);
            }

            return protected_key;
        }

        std::vector<uint8_t> StaticAssetProtector::unprotectKey(const std::vector<uint8_t>& protectedKey) const {
            if (protectedKey.size() < 4) {
                return {}; // Geçersiz
            }

            // Checksum'u çıkar
            uint32_t storedChecksum = 
                (static_cast<uint32_t>(protectedKey[0]) << 24) |
                (static_cast<uint32_t>(protectedKey[1]) << 16) |
                (static_cast<uint32_t>(protectedKey[2]) << 8) |
                static_cast<uint32_t>(protectedKey[3]);

            // Anahtarı deobfuscate et
            std::vector<uint8_t> key;
            key.reserve(protectedKey.size() - 4);

            for (size_t i = 4; i < protectedKey.size(); ++i) {
                size_t idx = i - 4;
                uint8_t xorKey = obfuscationKey_ ^ static_cast<uint8_t>((idx * 7 + 13) & 0xFF);
                key.push_back(protectedKey[i] ^ xorKey);
            }

            // Checksum doğrula
            uint32_t computedChecksum = 0;
            for (uint8_t byte : key) {
                computedChecksum = (computedChecksum << 5) + computedChecksum + byte;
            }

            if (computedChecksum != storedChecksum) {
                return {}; // Bütünlük hatası
            }

            return key;
        }

        bool StaticAssetProtector::verifyHash(const std::string& data, uint32_t expectedHash) const {
            return computeHash(data) == expectedHash;
        }

        void StaticAssetProtector::setObfuscationKey(uint8_t newKey) {
            obfuscationKey_ = newKey;
        }

        // ═══════════════════════════════════════════════════════════
        // 🧠 DİNAMİK VARLIK KORUYUCU IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════

        DynamicAssetProtector::DynamicAssetProtector()
            : totalProtectedSize_(0) {
        }

        DynamicAssetProtector::~DynamicAssetProtector() {
            // Tüm korumalı bellekleri temizle
            for (auto& block : protectedBlocks_) {
                if (block.ptr != nullptr) {
                    secureZero(block.ptr, block.size);
                    std::free(block.ptr);
                }
            }
            protectedBlocks_.clear();
            totalProtectedSize_ = 0;
        }

        void* DynamicAssetProtector::secureAllocate(size_t size) {
            if (size == 0) {
                return nullptr;
            }

            // Canary için ek alan ayır (başta ve sonda 4'er byte)
            size_t totalSize = size + 8;
            void* rawPtr = std::malloc(totalSize);
            
            if (rawPtr == nullptr) {
                return nullptr;
            }

            // Canary değerlerini yaz
            uint8_t* bytePtr = static_cast<uint8_t*>(rawPtr);
            
            // Başlangıç canary
            bytePtr[0] = static_cast<uint8_t>(CANARY_VALUE >> 24);
            bytePtr[1] = static_cast<uint8_t>(CANARY_VALUE >> 16);
            bytePtr[2] = static_cast<uint8_t>(CANARY_VALUE >> 8);
            bytePtr[3] = static_cast<uint8_t>(CANARY_VALUE);

            // Bitiş canary
            bytePtr[size + 4] = static_cast<uint8_t>(CANARY_VALUE >> 24);
            bytePtr[size + 5] = static_cast<uint8_t>(CANARY_VALUE >> 16);
            bytePtr[size + 6] = static_cast<uint8_t>(CANARY_VALUE >> 8);
            bytePtr[size + 7] = static_cast<uint8_t>(CANARY_VALUE);

            // Kullanıcı alanını sıfırla
            std::memset(bytePtr + 4, 0, size);

            // Kayıt ekle
            ProtectedBlock block;
            block.ptr = rawPtr;
            block.size = size;
            block.canaryStart = CANARY_VALUE;
            block.canaryEnd = CANARY_VALUE;
            block.isProtected = false;
            protectedBlocks_.push_back(block);

            totalProtectedSize_ += size;

            // Kullanıcıya canary'den sonraki adresi ver
            return bytePtr + 4;
        }

        void DynamicAssetProtector::secureFree(void* ptr, size_t size) {
            if (ptr == nullptr) {
                return;
            }

            // Gerçek pointer'ı bul (canary başlangıcı)
            uint8_t* userPtr = static_cast<uint8_t*>(ptr);
            uint8_t* rawPtr = userPtr - 4;

            // Kayıttan sil
            auto it = std::find_if(protectedBlocks_.begin(), protectedBlocks_.end(),
                [rawPtr](const ProtectedBlock& block) {
                    return block.ptr == rawPtr;
                });

            if (it != protectedBlocks_.end()) {
                totalProtectedSize_ -= it->size;
                protectedBlocks_.erase(it);
            }

            // Güvenli sıfırlama
            secureZero(rawPtr, size + 8);

            // Belleği serbest bırak
            std::free(rawPtr);
        }

        bool DynamicAssetProtector::checkIntegrity(void* ptr, size_t size) const {
            if (ptr == nullptr) {
                return false;
            }

            uint8_t* userPtr = static_cast<uint8_t*>(ptr);
            uint8_t* rawPtr = userPtr - 4;

            // Başlangıç canary kontrolü
            uint32_t startCanary = 
                (static_cast<uint32_t>(rawPtr[0]) << 24) |
                (static_cast<uint32_t>(rawPtr[1]) << 16) |
                (static_cast<uint32_t>(rawPtr[2]) << 8) |
                static_cast<uint32_t>(rawPtr[3]);

            if (startCanary != CANARY_VALUE) {
                return false;
            }

            // Bitiş canary kontrolü
            uint32_t endCanary = 
                (static_cast<uint32_t>(rawPtr[size + 4]) << 24) |
                (static_cast<uint32_t>(rawPtr[size + 5]) << 16) |
                (static_cast<uint32_t>(rawPtr[size + 6]) << 8) |
                static_cast<uint32_t>(rawPtr[size + 7]);

            return endCanary == CANARY_VALUE;
        }

        bool DynamicAssetProtector::protectMemory(void* ptr, size_t size) {
            if (ptr == nullptr || size == 0) {
                return false;
            }

#ifdef _WIN32
            DWORD oldProtect;
            return VirtualProtect(ptr, size, PAGE_READONLY, &oldProtect) != 0;
#else
            // Unix-like sistemlerde mprotect kullan
            // Page-aligned olmalı, bu basit implementasyon için sadece kayıt güncelle
            for (auto& block : protectedBlocks_) {
                uint8_t* rawPtr = static_cast<uint8_t*>(block.ptr);
                if (rawPtr + 4 == ptr) {
                    block.isProtected = true;
                    return true;
                }
            }
            return false;
#endif
        }

        bool DynamicAssetProtector::unprotectMemory(void* ptr, size_t size) {
            if (ptr == nullptr || size == 0) {
                return false;
            }

#ifdef _WIN32
            DWORD oldProtect;
            return VirtualProtect(ptr, size, PAGE_READWRITE, &oldProtect) != 0;
#else
            for (auto& block : protectedBlocks_) {
                uint8_t* rawPtr = static_cast<uint8_t*>(block.ptr);
                if (rawPtr + 4 == ptr) {
                    block.isProtected = false;
                    return true;
                }
            }
            return false;
#endif
        }

        std::string DynamicAssetProtector::createSecureString(const std::string& plaintext) {
            // Simple XOR obfuscation for runtime protection
            std::string secure = plaintext;
            uint8_t key = 0x7F;
            for (size_t i = 0; i < secure.size(); ++i) {
                secure[i] = static_cast<char>(static_cast<uint8_t>(secure[i]) ^ (key + static_cast<uint8_t>(i)));
            }
            return secure;
        }

        void DynamicAssetProtector::destroySecureString(std::string& secureStr) {
            // Boş string kontrolü - empty() true ise data() kullanmak tehlikeli
            if (!secureStr.empty()) {
                // Güvenli sıfırlama
                volatile char* p = &secureStr[0];
                for (size_t i = 0; i < secureStr.size(); ++i) {
                    p[i] = 0;
                }
            }
            secureStr.clear();
            secureStr.shrink_to_fit();
        }

        size_t DynamicAssetProtector::getProtectedMemorySize() const {
            return totalProtectedSize_;
        }

        void DynamicAssetProtector::secureZero(void* ptr, size_t size) {
            if (ptr == nullptr || size == 0) {
                return;
            }

            // Volatile pointer kullan - optimizer'ın kaldırmasını engelle
            volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
            while (size--) {
                *p++ = 0;
            }

#ifdef _WIN32
            // Windows'ta SecureZeroMemory
            SecureZeroMemory(ptr, size);
#endif
        }

        // ═══════════════════════════════════════════════════════════
        // 📋 VARLIK KAYIT SİSTEMİ IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════

        AssetInfo::AssetInfo()
            : type(AssetType::SENSITIVE_DATA)
            , securityLevel(SecurityLevel::MEDIUM)
            , status(AssetStatus::ACTIVE)
            , createdAt(0)
            , lastAccessedAt(0) {
        }

        AuditLogEntry::AuditLogEntry()
            : timestamp(0)
            , success(false) {
        }

        AssetRegistry::AssetRegistry() {
        }

        AssetRegistry::~AssetRegistry() {
            // Varlık bilgilerini güvenli şekilde temizle
            for (auto& pair : assets_) {
                pair.second.id.clear();
                pair.second.name.clear();
                pair.second.description.clear();
            }
            assets_.clear();
            auditLogs_.clear();
        }

        bool AssetRegistry::registerAsset(const AssetInfo& asset) {
            if (asset.id.empty()) {
                return false;
            }

            if (hasAsset(asset.id)) {
                return false; // Zaten var
            }

            AssetInfo newAsset = asset;
            newAsset.createdAt = getCurrentTimestamp();
            newAsset.lastAccessedAt = newAsset.createdAt;

            assets_[asset.id] = newAsset;

            // Audit log
            logAccess(asset.id, "REGISTER", "SYSTEM", true, "Asset registered");

            return true;
        }

        bool AssetRegistry::unregisterAsset(const std::string& assetId) {
            auto it = assets_.find(assetId);
            if (it == assets_.end()) {
                return false;
            }

            logAccess(assetId, "UNREGISTER", "SYSTEM", true, "Asset unregistered");

            assets_.erase(it);
            return true;
        }

        AssetInfo AssetRegistry::getAsset(const std::string& assetId) const {
            auto it = assets_.find(assetId);
            if (it == assets_.end()) {
                return AssetInfo();
            }
            return it->second;
        }

        bool AssetRegistry::hasAsset(const std::string& assetId) const {
            return assets_.find(assetId) != assets_.end();
        }

        std::vector<AssetInfo> AssetRegistry::listAllAssets() const {
            std::vector<AssetInfo> result;
            result.reserve(assets_.size());
            for (const auto& pair : assets_) {
                result.push_back(pair.second);
            }
            return result;
        }

        std::vector<AssetInfo> AssetRegistry::listAssetsByType(AssetType type) const {
            std::vector<AssetInfo> result;
            for (const auto& pair : assets_) {
                if (pair.second.type == type) {
                    result.push_back(pair.second);
                }
            }
            return result;
        }

        std::vector<AssetInfo> AssetRegistry::listAssetsBySecurityLevel(SecurityLevel level) const {
            std::vector<AssetInfo> result;
            for (const auto& pair : assets_) {
                if (pair.second.securityLevel == level) {
                    result.push_back(pair.second);
                }
            }
            return result;
        }

        bool AssetRegistry::updateAssetStatus(const std::string& assetId, AssetStatus newStatus) {
            auto it = assets_.find(assetId);
            if (it == assets_.end()) {
                return false;
            }

            AssetStatus oldStatus = it->second.status;
            it->second.status = newStatus;
            it->second.lastAccessedAt = getCurrentTimestamp();

            std::stringstream details;
            details << "Status changed from " << assetStatusToString(oldStatus) 
                   << " to " << assetStatusToString(newStatus);
            logAccess(assetId, "STATUS_UPDATE", "SYSTEM", true, details.str());

            return true;
        }

        void AssetRegistry::logAccess(const std::string& assetId,
                                      const std::string& action,
                                      const std::string& actor,
                                      bool success,
                                      const std::string& details) {
            AuditLogEntry entry;
            entry.timestamp = getCurrentTimestamp();
            entry.assetId = assetId;
            entry.action = action;
            entry.actor = actor;
            entry.success = success;
            entry.details = details;

            auditLogs_.push_back(entry);

            // Varlık erişim zamanını güncelle
            auto it = assets_.find(assetId);
            if (it != assets_.end()) {
                it->second.lastAccessedAt = entry.timestamp;
            }
        }

        std::vector<AuditLogEntry> AssetRegistry::getAuditLogs(size_t limit) const {
            if (limit == 0 || limit >= auditLogs_.size()) {
                return auditLogs_;
            }

            std::vector<AuditLogEntry> result;
            result.reserve(limit);
            
            size_t start = auditLogs_.size() - limit;
            for (size_t i = start; i < auditLogs_.size(); ++i) {
                result.push_back(auditLogs_[i]);
            }

            return result;
        }

        std::vector<AuditLogEntry> AssetRegistry::getAssetAuditLogs(const std::string& assetId) const {
            std::vector<AuditLogEntry> result;
            for (const auto& entry : auditLogs_) {
                if (entry.assetId == assetId) {
                    result.push_back(entry);
                }
            }
            return result;
        }

        std::string AssetRegistry::generateSecurityReport() const {
            std::stringstream report;

            report << "# Varlik Guvenlik Raporu\n\n";
            report << "## Ozet\n\n";
            report << "- **Toplam Varlik Sayisi:** " << assets_.size() << "\n";
            report << "- **Toplam Audit Log:** " << auditLogs_.size() << "\n\n";

            // Güvenlik seviyesine göre dağılım
            report << "## Guvenlik Seviyesi Dagilimi\n\n";
            
            int low = 0, medium = 0, high = 0, critical = 0;
            for (const auto& pair : assets_) {
                switch (pair.second.securityLevel) {
                    case SecurityLevel::LOW: ++low; break;
                    case SecurityLevel::MEDIUM: ++medium; break;
                    case SecurityLevel::HIGH: ++high; break;
                    case SecurityLevel::CRITICAL: ++critical; break;
                }
            }
            
            report << "| Seviye | Sayi |\n";
            report << "|--------|------|\n";
            report << "| LOW | " << low << " |\n";
            report << "| MEDIUM | " << medium << " |\n";
            report << "| HIGH | " << high << " |\n";
            report << "| CRITICAL | " << critical << " |\n\n";

            // Varlık durumu dağılımı
            report << "## Varlik Durumu Dagilimi\n\n";
            
            int active = 0, protected_count = 0, destroyed = 0, compromised = 0;
            for (const auto& pair : assets_) {
                switch (pair.second.status) {
                    case AssetStatus::ACTIVE: ++active; break;
                    case AssetStatus::PROTECTED: ++protected_count; break;
                    case AssetStatus::DESTROYED: ++destroyed; break;
                    case AssetStatus::COMPROMISED: ++compromised; break;
                }
            }
            
            report << "| Durum | Sayi |\n";
            report << "|-------|------|\n";
            report << "| ACTIVE | " << active << " |\n";
            report << "| PROTECTED | " << protected_count << " |\n";
            report << "| DESTROYED | " << destroyed << " |\n";
            report << "| COMPROMISED | " << compromised << " |\n\n";

            // Varlık listesi
            report << "## Kayitli Varliklar\n\n";
            report << "| ID | Isim | Tip | Seviye | Durum |\n";
            report << "|----|------|-----|--------|-------|\n";
            
            for (const auto& pair : assets_) {
                const auto& asset = pair.second;
                report << "| " << asset.id 
                       << " | " << asset.name
                       << " | " << assetTypeToString(asset.type)
                       << " | " << securityLevelToString(asset.securityLevel)
                       << " | " << assetStatusToString(asset.status)
                       << " |\n";
            }

            return report.str();
        }

        size_t AssetRegistry::getAssetCount() const {
            return assets_.size();
        }

        size_t AssetRegistry::getAuditLogCount() const {
            return auditLogs_.size();
        }

        void AssetRegistry::clear() {
            assets_.clear();
            auditLogs_.clear();
        }

        std::string AssetRegistry::generateAssetId() const {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dis(0, 15);

            std::stringstream ss;
            ss << "ASSET-";
            for (int i = 0; i < 8; ++i) {
                ss << std::hex << dis(gen);
            }
            return ss.str();
        }

        uint64_t AssetRegistry::getCurrentTimestamp() const {
            auto now = std::chrono::system_clock::now();
            auto epoch = now.time_since_epoch();
            return std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
        }

        // ═══════════════════════════════════════════════════════════
        // 🔧 YARDIMCI FONKSİYONLAR IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════

        std::string assetTypeToString(AssetType type) {
            switch (type) {
                case AssetType::STATIC_STRING: return "STATIC_STRING";
                case AssetType::STATIC_KEY: return "STATIC_KEY";
                case AssetType::STATIC_CONFIG: return "STATIC_CONFIG";
                case AssetType::DYNAMIC_MEMORY: return "DYNAMIC_MEMORY";
                case AssetType::DYNAMIC_BUFFER: return "DYNAMIC_BUFFER";
                case AssetType::DYNAMIC_CREDENTIAL: return "DYNAMIC_CREDENTIAL";
                case AssetType::SENSITIVE_DATA: return "SENSITIVE_DATA";
                default: return "UNKNOWN";
            }
        }

        std::string securityLevelToString(SecurityLevel level) {
            switch (level) {
                case SecurityLevel::LOW: return "LOW";
                case SecurityLevel::MEDIUM: return "MEDIUM";
                case SecurityLevel::HIGH: return "HIGH";
                case SecurityLevel::CRITICAL: return "CRITICAL";
                default: return "UNKNOWN";
            }
        }

        std::string assetStatusToString(AssetStatus status) {
            switch (status) {
                case AssetStatus::ACTIVE: return "ACTIVE";
                case AssetStatus::PROTECTED: return "PROTECTED";
                case AssetStatus::DESTROYED: return "DESTROYED";
                case AssetStatus::COMPROMISED: return "COMPROMISED";
                default: return "UNKNOWN";
            }
        }

        std::string quickObfuscate(const std::string& plaintext, uint8_t key) {
            StaticAssetProtector protector(key);
            return protector.obfuscateString(plaintext);
        }

        std::string quickDeobfuscate(const std::string& obfuscated, uint8_t key) {
            StaticAssetProtector protector(key);
            return protector.deobfuscateString(obfuscated);
        }

    } // namespace AssetProtection
} // namespace Kerem
