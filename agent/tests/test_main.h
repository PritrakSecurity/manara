/**
 * @file test_main.h
 * @brief Shared declarations and macros for the self-contained DCI test harness.
 *
 * PRITRAK Enterprise DLP Agent
 */

#pragma once

#include <cstdio>
#include <string>
#include <vector>

namespace dci_test {

struct TestCase {
    const char* name;
    void (*fn)();
};

std::vector<TestCase>& Registry();
void RecordCheck(bool ok, const char* file, int line, const char* expr);

extern int g_checks;
extern int g_failures;

struct Registrar {
    Registrar(const char* name, void (*fn)()) {
        Registry().push_back({name, fn});
    }
};

} // namespace dci_test

#define TEST(name) \
    static void dci_test_fn_##name(); \
    static ::dci_test::Registrar dci_test_reg_##name(#name, &dci_test_fn_##name); \
    static void dci_test_fn_##name()

#define CHECK(cond) \
    ::dci_test::RecordCheck((cond), __FILE__, __LINE__, #cond)

#define CHECK_EQ(a, b) \
    ::dci_test::RecordCheck((a) == (b), __FILE__, __LINE__, #a " == " #b)

#define CHECK_NE(a, b) \
    ::dci_test::RecordCheck((a) != (b), __FILE__, __LINE__, #a " != " #b)

#define CHECK_CONTAINS(haystack, needle) \
    ::dci_test::RecordCheck((haystack).find(needle) != std::string::npos, \
        __FILE__, __LINE__, #haystack " contains " #needle)

#define CHECK_NOT_CONTAINS(haystack, needle) \
    ::dci_test::RecordCheck((haystack).find(needle) == std::string::npos, \
        __FILE__, __LINE__, #haystack " does not contain " #needle)