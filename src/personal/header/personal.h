#ifndef PERSONAL_H
#define PERSONAL_H

#include <string>
#include <vector>
#include <map>

namespace Coruh {
    namespace personal {

        // --- Basit yardımcı matematik sınıfı (testlerde kullanılıyor)
        class FinanceMath {
        public:
            static double add(double a, double b);
            static double subtract(double a, double b);
            static double multiply(double a, double b);
            static double divide(double a, double b); // 0'a bölmede invalid_argument fırlatır
        };

        // --- Bütçe ---
        struct BudgetCategory {
            std::string name;
            double limitAmount{ 0.0 };
            double spentAmount{ 0.0 };
        };

        class BudgetManager {
        public:
            void addIncome(double amount);
            void addExpense(const std::string& categoryName, double amount);
            void setCategoryLimit(const std::string& categoryName, double limitAmount);

            double getTotalIncome() const;
            double getTotalExpenses() const;
            double getBalance() const;

            // Limit aşıldıysa uyarı mesajı döner, aksi halde boş string
            std::string getCategoryAlert(const std::string& categoryName) const;
            std::map<std::string, BudgetCategory> getCategories() const;

        private:
            double totalIncome{ 0.0 };
            std::map<std::string, BudgetCategory> nameToCategory;
        };

        // --- Yatırım ---
        struct Investment {
            std::string symbol;
            double units{ 0.0 };
            double currentPrice{ 0.0 };
            double costBasisPerUnit{ 0.0 };
        };

        class InvestmentPortfolio {
        public:
            void addInvestment(const Investment& inv);
            std::vector<Investment> getInvestments() const;
            double getTotalMarketValue() const;
            double getTotalCost() const;
            double getTotalUnrealizedPnL() const;
            std::string getBasicSuggestion() const;

        private:
            std::vector<Investment> investments;
        };

        // --- Hedefler ---
        struct Goal {
            std::string name;
            double targetAmount{ 0.0 };
            double savedAmount{ 0.0 };
        };

        class GoalsManager {
        public:
            void addGoal(const std::string& name, double targetAmount);
            void contribute(const std::string& name, double amount);
            std::vector<Goal> getGoals() const;
            double getProgressPercent(const std::string& name) const; // [0,100]

        private:
            std::map<std::string, Goal> nameToGoal;
        };

        // --- Borçlar ---
        struct Debt {
            std::string name;
            double principal{ 0.0 };
            double annualRatePercent{ 0.0 };
            double minMonthlyPayment{ 0.0 };
            double paidSoFar{ 0.0 };
        };

        class DebtManager {
        public:
            void addDebt(const Debt& d);
            std::vector<Debt> getDebts() const;
            double getTotalPrincipal() const;
            double getEstimatedMonthlyInterest() const; // kaba: principal * (rate/12)
            std::string getBasicPaydownSuggestion() const;

        private:
            std::vector<Debt> debts;
        };

    } // namespace personal
} // namespace Coruh

#endif // PERSONAL_H