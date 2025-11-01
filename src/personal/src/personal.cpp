#pragma execution_character_set("utf-8")

#include "../header/personal.h"
#include "../header/database.h"
#include "../header/data_security.hpp"  // 🛡️ Veri Güvenliği modülü
#include "../../sqlite3/sqlite3.h"
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace Coruh::personal;

// ---- UserAuth ----
// 🛡️ VERİ GÜVENLİĞİ: data_security modülünü kullan
std::string UserAuth::hashPassword(const std::string& password) {
    // DataSecurity modülündeki PBKDF2 benzeri hash fonksiyonunu kullan
    return Coruh::DataSecurity::hashPassword(password, 10000);
}

bool UserAuth::verifyPassword(const std::string& password, const std::string& hash) {
    return hashPassword(password) == hash;
}

// 🛡️ VERİ GÜVENLİĞİ: data_security modülü ile güvenli kayıt
bool UserAuth::registerUser(DatabaseManager& db, const std::string& username, 
                           const std::string& password, const std::string& email) {
    if (!db.isOpen()) return false;
    
    // 🛡️ VERİ GÜVENLİĞİ: Input validation (data_security modülü)
    if (!Coruh::DataSecurity::validateInput(username, Coruh::DataSecurity::InputType::USERNAME)) {
        return false;
    }
    if (!email.empty() && !Coruh::DataSecurity::validateInput(email, Coruh::DataSecurity::InputType::EMAIL)) {
        return false;
    }
    
    // Kullanıcı adı zaten var mı kontrol et
    User existingUser;
    if (getUserByUsername(db, username, existingUser)) {
        return false; // Kullanıcı zaten var
    }
    
    // 🛡️ VERİ GÜVENLİĞİ: SecureString ile şifreyi güvenli yönet
    Coruh::DataSecurity::SecureString securePassword(password);
    std::string passHash = hashPassword(securePassword.get());
    
    // 🛡️ VERİ GÜVENLİĞİ: Güvenli anahtar yönetimi (sabit string yerine)
    // Anahtar environment variable'dan veya kullanıcı bazlı türetilir
    std::string encryptionKey = Coruh::DataSecurity::getEncryptionKey(username, passHash);
    Coruh::DataSecurity::SecureString secureKey(encryptionKey);
    
    // 🛡️ VERİ GÜVENLİĞİ: Email'i şifrele (güvenli anahtar ile)
    std::string encryptedEmail = email.empty() ? "" : 
        Coruh::DataSecurity::encryptData(email, secureKey.get());
    
    // Yeni kullanıcı ekle
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?);";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, passHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encryptedEmail.c_str(), -1, SQLITE_TRANSIENT);
    
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    // 🛡️ VERİ GÜVENLİĞİ: Hassas verileri otomatik temizlenir (SecureString destructor)
    
    return success;
}

// 🛡️ VERİ GÜVENLİĞİ: data_security modülü ile güvenli login
int UserAuth::loginUser(DatabaseManager& db, const std::string& username, 
                       const std::string& password) {
    if (!db.isOpen()) return -1;
    
    // 🛡️ VERİ GÜVENLİĞİ: SecureString ile password yönetimi
    Coruh::DataSecurity::SecureString securePassword(password);
    
    User user;
    bool userFound = getUserByUsername(db, username, user);
    
    // 🛡️ VERİ GÜVENLİĞİ: Timing attack önleme - her durumda hash hesapla
    bool passwordValid = false;
    if (userFound) {
        passwordValid = verifyPassword(securePassword.get(), user.passwordHash);
    } else {
        // Kullanıcı bulunamadıysa da aynı sürede hash hesapla (timing attack önleme)
        std::string dummyHash = hashPassword(securePassword.get());
        (void)dummyHash; // Unused variable warning
    }
    
    // Hassas verileri otomatik temizlenir (SecureString destructor)
    
    if (!userFound || !passwordValid) {
        return -1; // Hata (detay verme - user enumeration önleme)
    }
    
    return user.id; // Başarılı giriş
}

// 🛡️ VERİ GÜVENLİĞİ: Null pointer kontrolü ve email şifre çözme
bool UserAuth::getUserById(DatabaseManager& db, int userId, User& user) {
    if (!db.isOpen()) return false;
    
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, password_hash, email FROM users WHERE id = ?;";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    
    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user.id = sqlite3_column_int(stmt, 0);
        
        // 🛡️ VERİ GÜVENLİĞİ: Null pointer kontrolü
        const unsigned char* usernameText = sqlite3_column_text(stmt, 1);
        const unsigned char* passwordText = sqlite3_column_text(stmt, 2);
        const unsigned char* emailText = sqlite3_column_text(stmt, 3);
        
        user.username = usernameText ? reinterpret_cast<const char*>(usernameText) : "";
        user.passwordHash = passwordText ? reinterpret_cast<const char*>(passwordText) : "";
        
        // 🛡️ VERİ GÜVENLİĞİ: Güvenli anahtar yönetimi ile email'i şifre çöz
        if (emailText) {
            std::string encryptedEmail = reinterpret_cast<const char*>(emailText);
            // Anahtarı kullanıcı bilgilerinden türet
            std::string encryptionKey = Coruh::DataSecurity::getEncryptionKey(user.username, user.passwordHash);
            Coruh::DataSecurity::SecureString secureKey(encryptionKey);
            user.email = Coruh::DataSecurity::decryptData(encryptedEmail, secureKey.get());
        } else {
            user.email = "";
        }
        
        found = true;
    }
    
    sqlite3_finalize(stmt);
    return found;
}

// 🛡️ VERİ GÜVENLİĞİ: Null pointer kontrolü ve email şifre çözme
bool UserAuth::getUserByUsername(DatabaseManager& db, const std::string& username, User& user) {
    if (!db.isOpen()) return false;
    
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, password_hash, email FROM users WHERE username = ?;";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    
    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user.id = sqlite3_column_int(stmt, 0);
        
        // 🛡️ VERİ GÜVENLİĞİ: Null pointer kontrolü
        const unsigned char* usernameText = sqlite3_column_text(stmt, 1);
        const unsigned char* passwordText = sqlite3_column_text(stmt, 2);
        const unsigned char* emailText = sqlite3_column_text(stmt, 3);
        
        user.username = usernameText ? reinterpret_cast<const char*>(usernameText) : "";
        user.passwordHash = passwordText ? reinterpret_cast<const char*>(passwordText) : "";
        
        // 🛡️ VERİ GÜVENLİĞİ: Güvenli anahtar yönetimi ile email'i şifre çöz
        if (emailText) {
            std::string encryptedEmail = reinterpret_cast<const char*>(emailText);
            // Anahtarı kullanıcı bilgilerinden türet
            std::string encryptionKey = Coruh::DataSecurity::getEncryptionKey(user.username, user.passwordHash);
            Coruh::DataSecurity::SecureString secureKey(encryptionKey);
            user.email = Coruh::DataSecurity::decryptData(encryptedEmail, secureKey.get());
        } else {
            user.email = "";
        }
        
        found = true;
    }
    
    sqlite3_finalize(stmt);
    return found;
}

// ---- FinanceMath ----
double FinanceMath::add(double a, double b) { return a + b; }
double FinanceMath::subtract(double a, double b) { return a - b; }
double FinanceMath::multiply(double a, double b) { return a * b; }
double FinanceMath::divide(double a, double b) {
    if (b == 0.0) throw std::invalid_argument("Division by zero is not allowed.");
    return a / b;
}

// ---- BudgetManager ----
void BudgetManager::addIncome(double amount) { totalIncome += amount; }

void BudgetManager::addExpense(const std::string& categoryName, double amount) {
    auto& cat = nameToCategory[categoryName];
    if (cat.name.empty()) { cat.name = categoryName; }
    cat.spentAmount += amount;
}

void BudgetManager::setCategoryLimit(const std::string& categoryName, double limitAmount) {
    auto& cat = nameToCategory[categoryName];
    if (cat.name.empty()) { cat.name = categoryName; }
    cat.limitAmount = limitAmount;
}

double BudgetManager::getTotalIncome() const { return totalIncome; }

double BudgetManager::getTotalExpenses() const {
    double sum = 0.0;
    for (const auto& kv : nameToCategory) sum += kv.second.spentAmount;
    return sum;
}

double BudgetManager::getBalance() const { return totalIncome - getTotalExpenses(); }

std::string BudgetManager::getCategoryAlert(const std::string& categoryName) const {
    auto it = nameToCategory.find(categoryName);
    if (it == nameToCategory.end()) return {};
    const auto& cat = it->second;
    if (cat.limitAmount > 0.0 && cat.spentAmount >= cat.limitAmount) {
        std::ostringstream oss;
        // Türkçe UTF-8 literal
        oss << u8"Uyarı: '" << cat.name << u8"' kategorisi limitini aştı ("
            << cat.spentAmount << "/" << cat.limitAmount << ")";
        return oss.str();
    }
    return {};
}

std::map<std::string, BudgetCategory> BudgetManager::getCategories() const {
    return nameToCategory;
}

bool BudgetManager::saveToDatabase(DatabaseManager& db, int userId) const {
    if (!db.isOpen()) return false;

    // Transaction başlat
    if (!db.beginTransaction()) return false;

    // Önce kullanıcıya ait mevcut verileri temizle
    std::ostringstream ossDelete;
    ossDelete << "DELETE FROM budget_categories WHERE user_id = " << userId << ";";
    if (!db.execute(ossDelete.str())) {
        db.rollbackTransaction();
        return false;
    }

    // Toplam geliri kaydet veya güncelle
    sqlite3_stmt* stmtBudget = nullptr;
    const char* sqlBudget = "INSERT OR REPLACE INTO budget (user_id, total_income) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db.getHandle(), sqlBudget, -1, &stmtBudget, nullptr) != SQLITE_OK) {
        db.rollbackTransaction();
        return false;
    }
    sqlite3_bind_int(stmtBudget, 1, userId);
    sqlite3_bind_double(stmtBudget, 2, totalIncome);
    
    if (sqlite3_step(stmtBudget) != SQLITE_DONE) {
        sqlite3_finalize(stmtBudget);
        db.rollbackTransaction();
        return false;
    }
    sqlite3_finalize(stmtBudget);

    // Kategorileri kaydet
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO budget_categories (user_id, name, limit_amount, spent_amount) VALUES (?, ?, ?, ?);";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        db.rollbackTransaction();
        return false;
    }

    for (const auto& kv : nameToCategory) {
        const auto& cat = kv.second;
        sqlite3_bind_int(stmt, 1, userId);
        sqlite3_bind_text(stmt, 2, cat.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 3, cat.limitAmount);
        sqlite3_bind_double(stmt, 4, cat.spentAmount);
        
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            db.rollbackTransaction();
            return false;
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);
    return db.commitTransaction();
}

bool BudgetManager::loadFromDatabase(DatabaseManager& db, int userId) {
    if (!db.isOpen()) return false;

    // Toplam geliri yükle
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT total_income FROM budget WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            totalIncome = sqlite3_column_double(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Kategorileri yükle
    nameToCategory.clear();
    sql = "SELECT name, limit_amount, spent_amount FROM budget_categories WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        BudgetCategory cat;
        cat.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        cat.limitAmount = sqlite3_column_double(stmt, 1);
        cat.spentAmount = sqlite3_column_double(stmt, 2);
        nameToCategory[cat.name] = cat;
    }

    sqlite3_finalize(stmt);
    return true;
}

// ---- InvestmentPortfolio ----
void InvestmentPortfolio::addInvestment(const Investment& inv) { investments.push_back(inv); }

std::vector<Investment> InvestmentPortfolio::getInvestments() const { return investments; }

double InvestmentPortfolio::getTotalMarketValue() const {
    double sum = 0.0;
    for (const auto& i : investments) sum += i.units * i.currentPrice;
    return sum;
}

double InvestmentPortfolio::getTotalCost() const {
    double sum = 0.0;
    for (const auto& i : investments) sum += i.units * i.costBasisPerUnit;
    return sum;
}

double InvestmentPortfolio::getTotalUnrealizedPnL() const {
    return getTotalMarketValue() - getTotalCost();
}

std::string InvestmentPortfolio::getBasicSuggestion() const {
    if (investments.empty()) return u8"Portföy boş. Düzenli ve küçük tutarlarla başlayın.";
    double pnl = getTotalUnrealizedPnL();
    return (pnl > 0.0)
        ? u8"Kârda görünüyorsunuz. Aşırı ağırlığı azaltmayı ve çeşitlendirmeyi düşünün."
        : u8"Zarardasınız. Panik satıştan kaçının, hedeflere ve vadeye odaklanın.";
}

bool InvestmentPortfolio::saveToDatabase(DatabaseManager& db, int userId) const {
    if (!db.isOpen()) return false;

    if (!db.beginTransaction()) return false;

    // Kullanıcıya ait mevcut yatırımları temizle
    std::ostringstream ossDelete;
    ossDelete << "DELETE FROM investments WHERE user_id = " << userId << ";";
    if (!db.execute(ossDelete.str())) {
        db.rollbackTransaction();
        return false;
    }

    // Yatırımları kaydet
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO investments (user_id, symbol, units, current_price, cost_basis_per_unit) VALUES (?, ?, ?, ?, ?);";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        db.rollbackTransaction();
        return false;
    }

    for (const auto& inv : investments) {
        sqlite3_bind_int(stmt, 1, userId);
        sqlite3_bind_text(stmt, 2, inv.symbol.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 3, inv.units);
        sqlite3_bind_double(stmt, 4, inv.currentPrice);
        sqlite3_bind_double(stmt, 5, inv.costBasisPerUnit);
        
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            db.rollbackTransaction();
            return false;
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);
    return db.commitTransaction();
}

bool InvestmentPortfolio::loadFromDatabase(DatabaseManager& db, int userId) {
    if (!db.isOpen()) return false;

    investments.clear();
    
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT symbol, units, current_price, cost_basis_per_unit FROM investments WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Investment inv;
        inv.symbol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        inv.units = sqlite3_column_double(stmt, 1);
        inv.currentPrice = sqlite3_column_double(stmt, 2);
        inv.costBasisPerUnit = sqlite3_column_double(stmt, 3);
        investments.push_back(inv);
    }

    sqlite3_finalize(stmt);
    return true;
}

// ---- GoalsManager ----
void GoalsManager::addGoal(const std::string& name, double targetAmount) {
    nameToGoal[name] = Goal{ name, targetAmount, 0.0 };
}

void GoalsManager::contribute(const std::string& name, double amount) {
    auto& g = nameToGoal[name];
    if (g.name.empty()) g.name = name;
    g.savedAmount += amount;
}

std::vector<Goal> GoalsManager::getGoals() const {
    std::vector<Goal> out; out.reserve(nameToGoal.size());
    for (const auto& kv : nameToGoal) out.push_back(kv.second);
    return out;
}

double GoalsManager::getProgressPercent(const std::string& name) const {
    auto it = nameToGoal.find(name);
    if (it == nameToGoal.end() || it->second.targetAmount <= 0.0) return 0.0;
    double pct = (it->second.savedAmount / it->second.targetAmount) * 100.0;
    if (pct < 0.0) pct = 0.0; if (pct > 100.0) pct = 100.0;
    return pct;
}

bool GoalsManager::saveToDatabase(DatabaseManager& db, int userId) const {
    if (!db.isOpen()) return false;

    if (!db.beginTransaction()) return false;

    // Kullanıcıya ait mevcut hedefleri temizle
    std::ostringstream ossDelete;
    ossDelete << "DELETE FROM goals WHERE user_id = " << userId << ";";
    if (!db.execute(ossDelete.str())) {
        db.rollbackTransaction();
        return false;
    }

    // Hedefleri kaydet
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO goals (user_id, name, target_amount, saved_amount) VALUES (?, ?, ?, ?);";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        db.rollbackTransaction();
        return false;
    }

    for (const auto& kv : nameToGoal) {
        const auto& goal = kv.second;
        sqlite3_bind_int(stmt, 1, userId);
        sqlite3_bind_text(stmt, 2, goal.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 3, goal.targetAmount);
        sqlite3_bind_double(stmt, 4, goal.savedAmount);
        
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            db.rollbackTransaction();
            return false;
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);
    return db.commitTransaction();
}

bool GoalsManager::loadFromDatabase(DatabaseManager& db, int userId) {
    if (!db.isOpen()) return false;

    nameToGoal.clear();
    
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT name, target_amount, saved_amount FROM goals WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Goal goal;
        goal.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        goal.targetAmount = sqlite3_column_double(stmt, 1);
        goal.savedAmount = sqlite3_column_double(stmt, 2);
        nameToGoal[goal.name] = goal;
    }

    sqlite3_finalize(stmt);
    return true;
}

// ---- DebtManager ----
void DebtManager::addDebt(const Debt& d) { debts.push_back(d); }

std::vector<Debt> DebtManager::getDebts() const { return debts; }

double DebtManager::getTotalPrincipal() const {
    double sum = 0.0;
    for (const auto& d : debts) sum += d.principal;
    return sum;
}

double DebtManager::getEstimatedMonthlyInterest() const {
    double sum = 0.0;
    for (const auto& d : debts) sum += d.principal * (d.annualRatePercent / 100.0) / 12.0;
    return sum;
}

std::string DebtManager::getBasicPaydownSuggestion() const {
    if (debts.empty()) return u8"Tanımlı borç yok. Borçsuz kalmak için acil durum fonu oluşturun.";
    auto it = std::max_element(
        debts.begin(), debts.end(),
        [](const Debt& a, const Debt& b) { return a.annualRatePercent < b.annualRatePercent; });
    std::ostringstream oss;
    oss << u8"Öneri: En yüksek faizli borcu önceliklendirin (" << it->name
        << u8", %" << it->annualRatePercent << u8").";
    return oss.str();
}

bool DebtManager::saveToDatabase(DatabaseManager& db, int userId) const {
    if (!db.isOpen()) return false;

    if (!db.beginTransaction()) return false;

    // Kullanıcıya ait mevcut borçları temizle
    std::ostringstream ossDelete;
    ossDelete << "DELETE FROM debts WHERE user_id = " << userId << ";";
    if (!db.execute(ossDelete.str())) {
        db.rollbackTransaction();
        return false;
    }

    // Borçları kaydet
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO debts (user_id, name, principal, annual_rate_percent, min_monthly_payment, paid_so_far) VALUES (?, ?, ?, ?, ?, ?);";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        db.rollbackTransaction();
        return false;
    }

    for (const auto& debt : debts) {
        sqlite3_bind_int(stmt, 1, userId);
        sqlite3_bind_text(stmt, 2, debt.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 3, debt.principal);
        sqlite3_bind_double(stmt, 4, debt.annualRatePercent);
        sqlite3_bind_double(stmt, 5, debt.minMonthlyPayment);
        sqlite3_bind_double(stmt, 6, debt.paidSoFar);
        
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            db.rollbackTransaction();
            return false;
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);
    return db.commitTransaction();
}

bool DebtManager::loadFromDatabase(DatabaseManager& db, int userId) {
    if (!db.isOpen()) return false;

    debts.clear();
    
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT name, principal, annual_rate_percent, min_monthly_payment, paid_so_far FROM debts WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db.getHandle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Debt debt;
        debt.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        debt.principal = sqlite3_column_double(stmt, 1);
        debt.annualRatePercent = sqlite3_column_double(stmt, 2);
        debt.minMonthlyPayment = sqlite3_column_double(stmt, 3);
        debt.paidSoFar = sqlite3_column_double(stmt, 4);
        debts.push_back(debt);
    }

    sqlite3_finalize(stmt);
    return true;
}
