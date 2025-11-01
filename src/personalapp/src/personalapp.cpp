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

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <vector>
#include <conio.h> // _getch() için
#endif

#pragma execution_character_set("utf-8")   // <--- Türkçe karakterler için eklendi.

using namespace Coruh::personal;

namespace {
    // Şifre girişi için maskeleme fonksiyonu (Windows)
    std::string getPasswordMasked() {
#ifdef _WIN32
        std::string password;
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
                password += ch;
                std::cout << '*'; // Yıldız göster
            }
        }
        std::cout << '\n';
        return password;
#else
        // Linux/Mac için basit versiyon (maskeleme yok)
        std::string password;
        std::getline(std::cin, password);
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
                // KAYIT OL
                clearScreen();
                std::cout << u8"\n=== KAYIT OL ===\n";
                std::string username, password, email;
                
                std::cout << u8"Kullanıcı adı: ";
                std::getline(std::cin, username);
                
                std::cout << u8"Şifre: ";
                password = getPasswordMasked();
                
                std::cout << u8"E-posta (isteğe bağlı): ";
                std::getline(std::cin, email);

                if (username.empty() || password.empty()) {
                    std::cout << u8"\n⚠ Kullanıcı adı ve şifre boş olamaz!\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                    continue;
                }

                if (auth.registerUser(db, username, password, email)) {
                    std::cout << u8"\n✓ Kayıt başarılı! Şimdi giriş yapabilirsiniz.\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                } else {
                    std::cout << u8"\n⚠ Kayıt başarısız! Kullanıcı adı zaten kullanımda olabilir.\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                }
            }
            else if (choice == 2) {
                // GİRİŞ YAP
                clearScreen();
                std::cout << u8"\n=== GİRİŞ YAP ===\n";
                std::string username, password;
                
                std::cout << u8"Kullanıcı adı: ";
                std::getline(std::cin, username);
                
                std::cout << u8"Şifre: ";
                password = getPasswordMasked();

                int userId = auth.loginUser(db, username, password);
                if (userId > 0) {
                    std::cout << u8"\n✓ Giriş başarılı! Hoş geldiniz, " << username << "!\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                    return userId; // Başarılı giriş
                } else {
                    std::cout << u8"\n⚠ Giriş başarısız! Kullanıcı adı veya şifre hatalı.\n";
                    std::cout << u8"Devam etmek için Enter tuşuna basın...";
                    std::cin.get();
                }
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
    
    // Veritabanını aç ve tabloları oluştur
    if (db.open("personal_finance.db")) {
        if (db.createTables()) {
            dbOpened = true;
            std::cout << u8"✓ Veritabanı başarıyla açıldı ve hazır.\n";
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
                std::cout << "Gelir eklendi.\n";
                if (dbOpened) budget.saveToDatabase(db, currentUserId);
            }
            else if (s == 2) {
                std::string cat; double a;
                std::cout << "Kategori: "; std::getline(std::cin, cat);
                std::cout << "Tutar: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                budget.addExpense(cat, a);
                std::cout << "Gider eklendi.\n";
                if (dbOpened) budget.saveToDatabase(db, currentUserId);
            }
            else if (s == 3) {
                std::string cat; double lim;
                std::cout << "Kategori: "; std::getline(std::cin, cat);
                std::cout << "Limit: ";
                if (!(std::cin >> lim)) { clearCin(); break; } clearCin();
                budget.setCategoryLimit(cat, lim);
                std::cout << "Limit ayarlandı.\n";
                if (dbOpened) budget.saveToDatabase(db, currentUserId);
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
                std::cout << "Yatırım eklendi.\n";
                if (dbOpened) portfolio.saveToDatabase(db, currentUserId);
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
                std::cout << "Hedef eklendi.\n";
                if (dbOpened) goals.saveToDatabase(db, currentUserId);
            }
            else if (s == 2) {
                std::string n; double a;
                std::cout << "Hedef adı: "; std::getline(std::cin, n);
                std::cout << "Katkı tutarı: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                goals.contribute(n, a);
                std::cout << "Katkı işlendi.\n";
                if (dbOpened) goals.saveToDatabase(db, currentUserId);
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
                std::cout << "Borç eklendi.\n";
                if (dbOpened) debts.saveToDatabase(db, currentUserId);
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

    std::cout << "Güle güle!\n";
}

int main() {
    runApplication();
    return 0;
}