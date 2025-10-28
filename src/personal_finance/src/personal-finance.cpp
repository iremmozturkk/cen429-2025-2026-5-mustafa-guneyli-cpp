#include "../header/personal.h"
#include <stdexcept>

using namespace Coruh::personal;

double personal::add(double a, double b) {
    return a + b;
}

double personal::subtract(double a, double b) {
    return a - b;
}

double personal::multiply(double a, double b) {
    return a * b;
}

double personal::divide(double a, double b) {
    if (b == 0) {
        throw std::invalid_argument("Division by zero is not allowed.");
    }
    return a / b;
}