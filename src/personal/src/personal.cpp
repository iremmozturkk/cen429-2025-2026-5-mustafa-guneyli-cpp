#pragma execution_character_set("utf-8")

#include "../header/personal.h"
#include <stdexcept>
#include <algorithm>
#include <sstream>

using namespace Coruh::personal;

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
