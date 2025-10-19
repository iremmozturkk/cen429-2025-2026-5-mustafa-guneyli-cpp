//#define ENABLE_personal-finance_TEST  // Uncomment this line to enable the personal-finance tests

#include "gtest/gtest.h"
#include "../../personal-finance/header/personal-finance.h"  // Adjust this include path based on your project structure

using namespace Coruh::personal-finance;

class personal-financeTest : public ::testing::Test {
protected:
	void SetUp() override {
		// Setup test data
	}

	void TearDown() override {
		// Clean up test data
	}
};

TEST_F(personal-financeTest, TestAdd) {
	double result = personal-finance::add(5.0, 3.0);
	EXPECT_DOUBLE_EQ(result, 8.0);
}

TEST_F(personal-financeTest, TestSubtract) {
	double result = personal-finance::subtract(5.0, 3.0);
	EXPECT_DOUBLE_EQ(result, 2.0);
}

TEST_F(personal-financeTest, TestMultiply) {
	double result = personal-finance::multiply(5.0, 3.0);
	EXPECT_DOUBLE_EQ(result, 15.0);
}

TEST_F(personal-financeTest, TestDivide) {
	double result = personal-finance::divide(6.0, 3.0);
	EXPECT_DOUBLE_EQ(result, 2.0);
}

TEST_F(personal-financeTest, TestDivideByZero) {
	EXPECT_THROW(personal-finance::divide(5.0, 0.0), std::invalid_argument);
}

/**
 * @brief The main function of the test program.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line argument strings.
 * @return int The exit status of the program.
 */
int main(int argc, char** argv) {
#ifdef ENABLE_personal-finance_TEST
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
#else
	return 0;
#endif
}