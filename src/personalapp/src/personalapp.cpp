/**
 * @file personalapp.cpp
 * @brief Kişisel finans danışmanı konsol uygulaması.
 */
#include <iostream>
#include <string>
#include <limits>
#include "../header/personalapp.h"
#include "../../personal/header/personal.h"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <vector>
#endif

#pragma execution_character_set("utf-8")   // <--- Türkçe karakterler için eklendi.

using namespace Coruh::personal;

namespace {
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
    void mainMenuVisual() {
        setColor(11); // Açık mavi
        drawLine();
        std::cout << "       \xF0\x9F\x92\xBC KİŞİSEL FİNANS DANIŞMANI\n";
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
    void mainMenuVisual() {
        drawLine();
        std::cout << "       KİŞİSEL FİNANS DANIŞMANI\n";
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

} // namespace

void runApplication() {
#ifdef _WIN32
    // Konsolda Türkçe karakterlerin bozulmaması için UTF-8 kod sayfasına geç
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);

    BudgetManager        budget;
    InvestmentPortfolio  portfolio;
    GoalsManager         goals;
    DebtManager          debts;

    // Opsiyonel giriş
    std::cout << "Kullanıcı girişi atlanabilir. Giriş yapmak istiyor musunuz? (e/h): ";
    char ch; std::cin >> ch; clearCin();
    if (ch == 'e' || ch == 'E') {
        std::string user, pass;
        std::cout << "Kullanıcı adı: "; std::getline(std::cin, user);
        std::cout << "Parola: ";        std::getline(std::cin, pass);
        std::cout << "(Demo) Giriş başarılı sayıldı.\n";
    }

    while (true) {
        clearScreen();
        // >>> RENKLİ/EMOJİLİ ANA MENÜ <<<
        mainMenuVisual();

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
            }
            else if (s == 2) {
                std::string cat; double a;
                std::cout << "Kategori: "; std::getline(std::cin, cat);
                std::cout << "Tutar: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                budget.addExpense(cat, a);
                std::cout << "Gider eklendi.\n";
            }
            else if (s == 3) {
                std::string cat; double lim;
                std::cout << "Kategori: "; std::getline(std::cin, cat);
                std::cout << "Limit: ";
                if (!(std::cin >> lim)) { clearCin(); break; } clearCin();
                budget.setCategoryLimit(cat, lim);
                std::cout << "Limit ayarlandı.\n";
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
            }
            else if (s == 2) {
                std::string n; double a;
                std::cout << "Hedef adı: "; std::getline(std::cin, n);
                std::cout << "Katkı tutarı: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                goals.contribute(n, a);
                std::cout << "Katkı işlendi.\n";
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