/**
 * @file personalapp.cpp
 * @brief Kişisel finans danışmanı konsol uygulaması.
 */
#include <iostream>
#include <string>
#include <limits>
#include "../header/personalapp.h"
#include "../../personal/header/personal.h"
#include "../../personal/header/database.h"
// 🛡️ VERİ GÜVENLİĞİ: Merkezi güvenlik modülü
#include "../../personal/header/data_security.hpp"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <vector>
#include <conio.h> // _getch() için
#endif

#pragma execution_character_set("utf-8")   // <--- Türkçe karakterler için eklendi.

using namespace Coruh::personal;

namespace {
    // 🛡️ VERİ GÜVENLİĞİ: Şifre girişi için güvenli maskeleme (buffer limit)
    std::string getPasswordMasked() {
#ifdef _WIN32
        const size_t MAX_PASSWORD_LENGTH = 128; // Maksimum şifre uzunluğu
        std::string password;
        password.reserve(MAX_PASSWORD_LENGTH);
        
        char ch;
        while (true) {
            ch = _getch(); // Karakteri ekrana yazdırmadan oku
            if (ch == '\r' || ch == '\n') { // Enter tuşu
                break;
            } else if (ch == '\b') { // Backspace tuşu
                if (!password.empty()) {
                    password.pop_back();
                    std::cout << "\b \b"; // Ekrandan sil
                }
            } else if (ch >= 32 && ch <= 126) { // Yazdırılabilir karakterler
                // 🛡️ VERİ GÜVENLİĞİ: Maksimum uzunluk kontrolü
                if (password.length() >= MAX_PASSWORD_LENGTH) {
                    std::cout << "\a"; // Beep (limit aşıldı)
                    continue;
                }
                password += ch;
                std::cout << '*'; // Yıldız göster
            }
        }
        std::cout << '\n';
        return password;
#else
        // Linux/Mac için basit versiyon (maskeleme yok)
        const size_t MAX_PASSWORD_LENGTH = 128;
        std::string password;
        std::getline(std::cin, password);
        
        // 🛡️ VERİ GÜVENLİĞİ: Maksimum uzunluk kontrolü
        if (password.length() > MAX_PASSWORD_LENGTH) {
            password = password.substr(0, MAX_PASSWORD_LENGTH);
        }
        return password;
#endif
    }

    // --------- Ortak yardımcılar ----------
    void clearCin() {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    void clearScreen() {
#ifdef _WIN32
        system("cls");
#else
        system("clear");
#endif
    }

#ifdef _WIN32
    // --------- Windows renk yardımcıları ----------
    void setColor(WORD color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }
    void resetColor() { setColor(7); } // Beyaz
    void drawLine() { std::cout << "==========================================" << '\n'; }

    // Renkli/görsel ana menü
    void mainMenuVisual(const std::string& username = "") {
        setColor(11); // Açık mavi
        drawLine();
        std::cout << "       \xF0\x9F\x92\xBC KİŞİSEL FİNANS DANIŞMANI\n";
        if (!username.empty()) {
            setColor(10);
            std::cout << "       \xF0\x9F\x91\xA4 Hoş geldiniz, " << username << "!\n";
            setColor(11);
        }
        drawLine();
        setColor(14); // Sarı
        std::cout << " 1) \xF0\x9F\x92\xB0 Bütçe planlama ve takip\n";
        std::cout << " 2) \xF0\x9F\x93\x88 Yatırım portföy yönetimi\n";
        std::cout << " 3) \xF0\x9F\x8E\xAF Finansal hedefler\n";
        std::cout << " 4) \xF0\x9F\x93\x89 Borç azaltma stratejileri\n";
        std::cout << " 0) \xE2\x9D\x8C Çıkış\n";
        resetColor();
        drawLine();
        std::cout << "Seçiminiz: ";
    }
#else
    // Diğer platformlarda sade menü
    void drawLine() { std::cout << "==========================================" << '\n'; }
    void mainMenuVisual(const std::string& username = "") {
        drawLine();
        std::cout << "       KİŞİSEL FİNANS DANIŞMANI\n";
        if (!username.empty()) {
            std::cout << "       Hoş geldiniz, " << username << "!\n";
        }
        drawLine();
        std::cout << " 1) Bütçe planlama ve takip\n";
        std::cout << " 2) Yatırım portföy yönetimi\n";
        std::cout << " 3) Finansal hedefler\n";
        std::cout << " 4) Borç azaltma stratejileri\n";
        std::cout << " 0) Çıkış\n";
        drawLine();
        std::cout << "Seçiminiz: ";
    }
    void resetColor() {} // no-op
#endif

    // Güvenli tamsayı okuma
    bool readIntSafe(const char* prompt, int& out) {
        std::cout << prompt;
        if (!(std::cin >> out)) { clearCin(); return false; }
        clearCin(); return true;
    }

    // Login/Register menüsü
    int showAuthMenu(DatabaseManager& db, UserAuth& auth) {
        while (true) {
            clearScreen();
#ifdef _WIN32
            setColor(11);
#endif
            drawLine();
            std::cout << "       \xF0\x9F\x94\x90 KULLANICI GİRİŞİ\n";
            drawLine();
#ifdef _WIN32
            setColor(14);
#endif
            std::cout << " 1) \xF0\x9F\x93\x9D Kayıt Ol (Register)\n";
            std::cout << " 2) \xF0\x9F\x94\x91 Giriş Yap (Login)\n";
            std::cout << " 0) \xE2\x9D\x8C Çıkış\n";
            resetColor();
            drawLine();

            int choice;
            if (!readIntSafe("Seçiminiz: ", choice)) {
                std::cout << u8"Geçersiz giriş!\n";
                continue;
            }

            if (choice == 0) {
                return -1; // Çıkış
            }
            else if (choice == 1) {
                // 🛡️ VERİ GÜVENLİĞİ: Güvenli kayıt (input validation)
                clearScreen();
                std::cout << u8"\n=== KAYIT OL ===\n";
                std::string username, email;
                
                std::cout << u8"Kullanıcı adı (3-32 karakter, alfanumerik): ";
                std::getline(std::cin, username);
                
                // 🛡️ VERİ GÜVENLİĞİ: Username validation (data_security modülü)
                if (!Coruh::DataSecurity::validateInput(username, Coruh::DataSecurity::InputType::USERNAME)) {
                    std::cout << u8"\n⚠ Geçersiz kullanıcı adı! 3-32 karakter, alfanumerik olmalı.\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                    continue;
                }
                
                std::cout << u8"Şifre (min 8 karakter): ";
                std::string password = getPasswordMasked();
                
                // 🛡️ VERİ GÜVENLİĞİ: Password strength check
                if (password.length() < 8) {
                    std::cout << u8"\n⚠ Şifre en az 8 karakter olmalıdır!\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                    continue;
                }
                
                std::cout << u8"E-posta (isteğe bağlı): ";
                std::getline(std::cin, email);
                
                // 🛡️ VERİ GÜVENLİĞİ: Email validation (data_security modülü)
                if (!email.empty() && !Coruh::DataSecurity::validateInput(email, Coruh::DataSecurity::InputType::EMAIL)) {
                    std::cout << u8"\n⚠ Geçersiz e-posta formatı!\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                    continue;
                }

                // 🛡️ VERİ GÜVENLİĞİ: SecureString ile hassas veri yönetimi (data_security modülü)
                Coruh::DataSecurity::SecureString securePassword(password);
                
                if (auth.registerUser(db, username, securePassword.get(), email)) {
                    std::cout << u8"\n✓ Kayıt başarılı! Şimdi giriş yapabilirsiniz.\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                } else {
                    std::cout << u8"\n⚠ Kayıt başarısız! Kullanıcı adı zaten kullanımda veya geçersiz veri.\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                }
                
                // Hassas verileri temizle
                password.clear();
                password.shrink_to_fit();
            }
            else if (choice == 2) {
                // 🛡️ VERİ GÜVENLİĞİ: Güvenli giriş
                clearScreen();
                std::cout << u8"\n=== GİRİŞ YAP ===\n";
                std::string username;
                
                std::cout << u8"Kullanıcı adı: ";
                std::getline(std::cin, username);
                
                std::cout << u8"Şifre: ";
                std::string password = getPasswordMasked();

                // 🛡️ VERİ GÜVENLİĞİ: SecureString ile password yönetimi (data_security modülü)
                Coruh::DataSecurity::SecureString securePassword(password);
                
                int userId = auth.loginUser(db, username, securePassword.get());
                if (userId > 0) {
                    std::cout << u8"\n✓ Giriş başarılı! Hoş geldiniz, " << username << "!\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                    
                    // Hassas verileri temizle
                    password.clear();
                    password.shrink_to_fit();
                    
                    return userId; // Başarılı giriş
                } else {
                    std::cout << u8"\n⚠ Giriş başarısız! Kullanıcı adı veya şifre hatalı.\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                }
                
                // Hassas verileri temizle
                password.clear();
                password.shrink_to_fit();
            }
            else {
                std::cout << u8"Geçersiz seçim!\n";
            }
        }
    }

} // namespace

void runApplication() {
#ifdef _WIN32
    // Konsolda Türkçe karakterlerin bozulmaması için UTF-8 kod sayfasına geç
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);

    // Veritabanı yöneticisi
    DatabaseManager db;
    bool dbOpened = false;
    
    // 📂 Veritabanı dosyası - çalışma dizininde (build klasöründe)
    const std::string dbFileName = "personal_finance.db";
    
    // Veritabanını aç ve tabloları oluştur
    if (db.open(dbFileName)) {
        if (db.createTables()) {
            dbOpened = true;
            std::cout << u8"✓ Veritabanı başarıyla açıldı ve hazır.\n";
            std::cout << u8"📂 Veritabanı dosyası: " << dbFileName << "\n";
#ifdef _WIN32
            // Windows'ta tam yolu göster
            char fullPath[MAX_PATH];
            if (GetCurrentDirectoryA(MAX_PATH, fullPath)) {
                std::cout << u8"📍 Konum: " << fullPath << "\\" << dbFileName << "\n";
            }
#endif
        } else {
            std::cout << u8"⚠ Veritabanı tabloları oluşturulamadı: " << db.getLastError() << "\n";
        }
    } else {
        std::cout << u8"⚠ Veritabanı açılamadı: " << db.getLastError() << "\n";
        std::cout << u8"Veriler yalnızca bu oturum için geçerli olacak.\n";
    }

    // Kullanıcı kimlik doğrulama
    UserAuth auth;
    int currentUserId = -1;
    std::string currentUsername;

    if (dbOpened) {
        // Login/Register menüsünü göster
        currentUserId = showAuthMenu(db, auth);
        
        if (currentUserId <= 0) {
            // Kullanıcı çıkış yaptı
            std::cout << u8"\nGüle güle!\n";
            return;
        }

        // Kullanıcı bilgilerini al
        User currentUser;
        if (auth.getUserById(db, currentUserId, currentUser)) {
            currentUsername = currentUser.username;
        }
    }

    BudgetManager        budget;
    InvestmentPortfolio  portfolio;
    GoalsManager         goals;
    DebtManager          debts;

    // Veritabanından kullanıcıya özel verileri yükle
    if (dbOpened) {
        budget.loadFromDatabase(db, currentUserId);
        portfolio.loadFromDatabase(db, currentUserId);
        goals.loadFromDatabase(db, currentUserId);
        debts.loadFromDatabase(db, currentUserId);
        std::cout << u8"\n✓ Verileriniz yüklendi.\n";
        std::cout << u8"Devam etmek için Enter tuşuna basın...";
        std::cin.get();
    }

    while (true) {
        clearScreen();
        // >>> RENKLİ/EMOJİLİ ANA MENÜ <<<
        mainMenuVisual(currentUsername);

        int sel;
        if (!(std::cin >> sel)) { clearCin(); continue; }
        clearCin();

        if (sel == 0) break;

        switch (sel) {
        case 1: { // ------- BÜTÇE -------
            clearScreen();
#ifdef _WIN32
            setColor(10); // Açık yeşil başlık
            std::cout << "-- Bütçe --\n";
            resetColor();
#else
            std::cout << "-- Bütçe --\n";
#endif
            std::cout << "1) Gelir ekle\n"
                "2) Gider ekle\n"
                "3) Kategori limiti belirle\n"
                "4) Özet/uyarılar\n";
            int s; if (!readIntSafe("Seçim: ", s)) break;

            if (s == 1) {
                double a; std::cout << "Gelir tutarı: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                budget.addIncome(a);
                std::cout << u8"✓ Gelir eklendi.\n";
                if (dbOpened) {
                    if (budget.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanına kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanına kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 2) {
                std::string cat; double a;
                std::cout << "Kategori: "; std::getline(std::cin, cat);
                std::cout << "Tutar: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                budget.addExpense(cat, a);
                std::cout << u8"✓ Gider eklendi.\n";
                if (dbOpened) {
                    if (budget.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanına kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanına kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 3) {
                std::string cat; double lim;
                std::cout << "Kategori: "; std::getline(std::cin, cat);
                std::cout << "Limit: ";
                if (!(std::cin >> lim)) { clearCin(); break; } clearCin();
                budget.setCategoryLimit(cat, lim);
                std::cout << u8"✓ Limit ayarlandı.\n";
                if (dbOpened) {
                    if (budget.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanına kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanına kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 4) {
                std::cout << "Toplam gelir: " << budget.getTotalIncome() << "\n";
                std::cout << "Toplam gider: " << budget.getTotalExpenses() << "\n";
                std::cout << "Bakiye: " << budget.getBalance() << "\n";
                for (const auto& kv : budget.getCategories()) {
                    const auto& c = kv.second;
                    auto alert = budget.getCategoryAlert(c.name);
                    if (!alert.empty()) std::cout << alert << "\n";
                }
            }
            std::cout << "Devam etmek için Enter...\n"; std::cin.get();
            break;
        }
        case 2: { // ------- PORTFÖY -------
            clearScreen();
#ifdef _WIN32
            setColor(10); std::cout << "-- Portföy --\n"; resetColor();
#else
            std::cout << "-- Portföy --\n";
#endif
            std::cout << "1) Yatırım ekle\n2) Özet ve öneri\n";
            int s; if (!readIntSafe("Seçim: ", s)) break;

            if (s == 1) {
                Investment inv{};
                std::cout << "Sembol: "; std::getline(std::cin, inv.symbol);
                std::cout << "Adet/lot: ";
                if (!(std::cin >> inv.units)) { clearCin(); break; } clearCin();
                std::cout << "Mevcut fiyat: ";
                if (!(std::cin >> inv.currentPrice)) { clearCin(); break; } clearCin();
                std::cout << "Maliyet (birim): ";
                if (!(std::cin >> inv.costBasisPerUnit)) { clearCin(); break; } clearCin();
                portfolio.addInvestment(inv);
                std::cout << u8"✓ Yatırım eklendi.\n";
                if (dbOpened) {
                    if (portfolio.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanına kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanına kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 2) {
                std::cout << "Toplam değer: " << portfolio.getTotalMarketValue() << "\n";
                std::cout << "Toplam maliyet: " << portfolio.getTotalCost() << "\n";
                std::cout << "Gerçekleşmemiş PnL: " << portfolio.getTotalUnrealizedPnL() << "\n";
                std::cout << "Öneri: " << portfolio.getBasicSuggestion() << "\n";
            }
            std::cout << "Devam etmek için Enter...\n"; std::cin.get();
            break;
        }
        case 3: { // ------- HEDEFLER -------
            clearScreen();
#ifdef _WIN32
            setColor(10); std::cout << "-- Hedefler --\n"; resetColor();
#else
            std::cout << "-- Hedefler --\n";
#endif
            std::cout << "1) Hedef ekle\n2) Katkı yap\n3) İlerleme\n";
            int s; if (!readIntSafe("Seçim: ", s)) break;

            if (s == 1) {
                std::string n; double t;
                std::cout << "Ad: "; std::getline(std::cin, n);
                std::cout << "Hedef tutar: ";
                if (!(std::cin >> t)) { clearCin(); break; } clearCin();
                goals.addGoal(n, t);
                std::cout << u8"✓ Hedef eklendi.\n";
                if (dbOpened) {
                    if (goals.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanına kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanına kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 2) {
                std::string n; double a;
                std::cout << "Hedef adı: "; std::getline(std::cin, n);
                std::cout << "Katkı tutarı: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                goals.contribute(n, a);
                std::cout << u8"✓ Katkı işlendi.\n";
                if (dbOpened) {
                    if (goals.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanına kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanına kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 3) {
                for (const auto& g : goals.getGoals()) {
                    std::cout << g.name << ": "
                        << goals.getProgressPercent(g.name)
                        << "% (" << g.savedAmount << "/" << g.targetAmount << ")\n";
                }
            }
            std::cout << "Devam etmek için Enter...\n"; std::cin.get();
            break;
        }
        case 4: { // ------- BORÇLAR -------
            clearScreen();
#ifdef _WIN32
            setColor(10); std::cout << "-- Borçlar --\n"; resetColor();
#else
            std::cout << "-- Borçlar --\n";
#endif
            std::cout << "1) Borç ekle\n2) Özet ve strateji\n";
            int s; if (!readIntSafe("Seçim: ", s)) break;

            if (s == 1) {
                Debt d{};
                std::cout << "Borç adı: "; std::getline(std::cin, d.name);
                std::cout << "Anapara: ";
                if (!(std::cin >> d.principal)) { clearCin(); break; } clearCin();
                std::cout << "Yıllık faiz %: ";
                if (!(std::cin >> d.annualRatePercent)) { clearCin(); break; } clearCin();
                std::cout << "Asgari aylık ödeme: ";
                if (!(std::cin >> d.minMonthlyPayment)) { clearCin(); break; } clearCin();
                d.paidSoFar = 0.0;
                debts.addDebt(d);
                std::cout << u8"✓ Borç eklendi.\n";
                if (dbOpened) {
                    if (debts.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanına kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanına kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 2) {
                std::cout << "Toplam anapara: " << debts.getTotalPrincipal() << "\n";
                std::cout << "Tahmini aylık faiz: " << debts.getEstimatedMonthlyInterest() << "\n";
                std::cout << debts.getBasicPaydownSuggestion() << "\n";
            }
            std::cout << "Devam etmek için Enter...\n"; std::cin.get();
            break;
        }
        default:
            std::cout << "Geçersiz seçim.\n";
            std::cout << "Devam etmek için Enter...\n"; std::cin.get();
            break;
        }
    }

    // 💾 Çıkış öncesi tüm verileri kaydet
    if (dbOpened && currentUserId > 0) {
        std::cout << u8"\n💾 Verileriniz kaydediliyor...\n";
        bool saveSuccess = true;
        
        if (!budget.saveToDatabase(db, currentUserId)) {
            std::cout << u8"⚠ Bütçe verileri kaydedilemedi!\n";
            saveSuccess = false;
        }
        if (!portfolio.saveToDatabase(db, currentUserId)) {
            std::cout << u8"⚠ Portföy verileri kaydedilemedi!\n";
            saveSuccess = false;
        }
        if (!goals.saveToDatabase(db, currentUserId)) {
            std::cout << u8"⚠ Hedef verileri kaydedilemedi!\n";
            saveSuccess = false;
        }
        if (!debts.saveToDatabase(db, currentUserId)) {
            std::cout << u8"⚠ Borç verileri kaydedilemedi!\n";
            saveSuccess = false;
        }
        
        if (saveSuccess) {
            std::cout << u8"✓ Tüm verileriniz başarıyla kaydedildi.\n";
        }
    }

    std::cout << u8"\nGüle güle!\n";
}

int main() {
    runApplication();
    return 0;
}