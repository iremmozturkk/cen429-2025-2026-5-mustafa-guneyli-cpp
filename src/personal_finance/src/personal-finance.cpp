#include "../header/personal-finance.h"
#include <stdexcept>

using namespace Coruh::personal-finance;

double personal-finance::add(double a, double b) {
    return a + b;
}

double personal-finance::subtract(double a, double b) {
    return a - b;
}

double personal-finance::multiply(double a, double b) {
    return a * b;
}

double personal-finance::divide(double a, double b) {
    if (b == 0) {
        throw std::invalid_argument("Division by zero is not allowed.");
    }
    return a / b;
}