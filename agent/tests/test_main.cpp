/**
 * @file test_main.cpp
 * @brief Minimal self-contained test harness for the DCI/PII unit tests.
 *
 * PRITRAK Enterprise DLP Agent
 *
 * No external test framework is pulled in (keeps the dependency surface to
 * the DCI libraries under test). Tests register via the TEST() macro and are
 * run in registration order. Exit code is 0 only when every check passes.
 */

#include "test_main.h"

namespace dci_test {

std::vector<TestCase>& Registry() {
    static std::vector<TestCase> registry;
    return registry;
}

int g_checks = 0;
int g_failures = 0;

void RecordCheck(bool ok, const char* file, int line, const char* expr) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::printf("FAIL %s:%d: %s\n", file, line, expr);
    }
}

} // namespace dci_test

int main() {
    std::printf("Pritrak DLP DCI test suite\n");
    for (const auto& test : ::dci_test::Registry()) {
        std::printf("[ RUN  ] %s\n", test.name);
        test.fn();
    }
    std::printf("%d checks, %d failures\n", ::dci_test::g_checks, ::dci_test::g_failures);
    return ::dci_test::g_failures == 0 ? 0 : 1;
}