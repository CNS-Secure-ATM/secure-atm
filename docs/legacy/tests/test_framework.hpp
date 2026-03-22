// Minimal test framework - no external dependencies
#ifndef TEST_FRAMEWORK_HPP
#define TEST_FRAMEWORK_HPP

#include <iostream>
#include <string>
#include <vector>
#include <functional>

namespace test {

struct TestCase {
    std::string name;
    std::function<bool()> func;
};

inline std::vector<TestCase>& get_tests() {
    static std::vector<TestCase> tests;
    return tests;
}

inline void register_test(const char* name, std::function<bool()> func) {
    get_tests().push_back({name, func});
}

#define TEST(name) \
    bool test_##name(); \
    namespace { struct Register_##name { \
        Register_##name() { test::register_test(#name, test_##name); } \
    } register_##name; } \
    bool test_##name()

#define EXPECT_TRUE(expr) \
    do { if (!(expr)) { \
        std::cerr << "  FAIL: " << #expr << " (line " << __LINE__ << ")\n"; \
        return false; \
    } } while(0)

#define EXPECT_FALSE(expr) EXPECT_TRUE(!(expr))

#define EXPECT_EQ(a, b) \
    do { if ((a) != (b)) { \
        std::cerr << "  FAIL: " << #a << " != " << #b << " (line " << __LINE__ << ")\n"; \
        return false; \
    } } while(0)

inline int run_tests() {
    int passed = 0, failed = 0;
    for (const auto& tc : get_tests()) {
        std::cout << "Running: " << tc.name << "... ";
        std::cout.flush();
        if (tc.func()) {
            std::cout << "PASS\n";
            passed++;
        } else {
            std::cout << "FAIL\n";
            failed++;
        }
    }
    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    return failed > 0 ? 1 : 0;
}

} // namespace test

#endif // TEST_FRAMEWORK_HPP
