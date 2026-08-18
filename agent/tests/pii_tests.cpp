/**
 * @file pii_tests.cpp
 * @brief Tests for the RE2-backed PII scanner (ScanTextForPII, IsValidLuhn,
 *        MaskSensitiveData) in DeepContentInspector.
 *
 * PRITRAK Enterprise DLP Agent
 *
 * These tests pin the existing PII patterns, result semantics and
 * false-positive controls (Luhn validation for credit cards).
 */

#include "DeepContentInspector.h"

#include <chrono>
#include <string>
#include <vector>

#include "test_main.h"

using Pritrak::DLP::DeepContentInspector;

TEST(luhn_valid_card) {
    CHECK(DeepContentInspector::IsValidLuhn("4111111111111111"));  // Visa test number
    CHECK(DeepContentInspector::IsValidLuhn("5555555555554444"));  // Mastercard test number
    CHECK(DeepContentInspector::IsValidLuhn("378282246310005"));   // Amex test number (15 digits)
}

TEST(luhn_invalid_card) {
    CHECK(!DeepContentInspector::IsValidLuhn("4111111111111112"));  // bad check digit
    CHECK(!DeepContentInspector::IsValidLuhn("4111111111111110"));
    CHECK(!DeepContentInspector::IsValidLuhn(""));
    CHECK(!DeepContentInspector::IsValidLuhn("1234abcd"));
}

TEST(pii_credit_card_valid_luhn_detected) {
    std::vector<std::string> hits =
        DeepContentInspector::ScanTextForPII("My card is 4111 1111 1111 1111, keep it safe.");
    bool found = false;
    for (const auto& h : hits) {
        if (h.find("4111") != std::string::npos) {
            found = true;
        }
    }
    CHECK(found);
}

TEST(pii_credit_card_invalid_luhn_not_detected) {
    std::vector<std::string> hits =
        DeepContentInspector::ScanTextForPII("Card number 4111 1111 1111 1112 is bogus.");
    for (const auto& h : hits) {
        CHECK(h.find("4111") == std::string::npos);
    }
}

TEST(pii_ssn_positive) {
    std::vector<std::string> hits =
        DeepContentInspector::ScanTextForPII("Employee SSN: 123-45-6789 on file.");
    bool found = false;
    for (const auto& h : hits) {
        if (h == "123-45-6789") {
            found = true;
        }
    }
    CHECK(found);
}

TEST(pii_ssn_negative) {
    std::vector<std::string> hits =
        DeepContentInspector::ScanTextForPII("Not an SSN: 123-45-678 or 123456789.");
    for (const auto& h : hits) {
        CHECK(h.find("123-45-678") == std::string::npos);
    }
}

TEST(pii_api_key_aws_positive) {
    std::vector<std::string> hits =
        DeepContentInspector::ScanTextForPII("access key AKIAIOSFODNN7EXAMPLE here");
    bool found = false;
    for (const auto& h : hits) {
        if (h == "AKIAIOSFODNN7EXAMPLE") {
            found = true;
        }
    }
    CHECK(found);
}

TEST(pii_api_key_aws_negative) {
    std::vector<std::string> hits =
        DeepContentInspector::ScanTextForPII("short key AKIAIOSFODNN7EXAMPL is 15 chars");
    for (const auto& h : hits) {
        CHECK(h.find("AKIAIOSFODNN7EXAMPL") == std::string::npos);
    }
}

TEST(pii_api_key_github_positive) {
    const std::string token = "ghp_" + std::string(36, 'a');
    std::vector<std::string> hits = DeepContentInspector::ScanTextForPII("token " + token);
    bool found = false;
    for (const auto& h : hits) {
        if (h == token) {
            found = true;
        }
    }
    CHECK(found);
}

TEST(pii_api_key_openai_positive) {
    const std::string token = "sk-" + std::string(48, 'b');
    std::vector<std::string> hits = DeepContentInspector::ScanTextForPII("key " + token + " end");
    bool found = false;
    for (const auto& h : hits) {
        if (h == token) {
            found = true;
        }
    }
    CHECK(found);
}

TEST(pii_plain_text_no_pii) {
    std::vector<std::string> hits =
        DeepContentInspector::ScanTextForPII("The quick brown fox jumps over the lazy dog.");
    CHECK(hits.empty());
}

TEST(pii_empty_match_no_infinite_loop) {
    // Strings full of separators / boundaries must not cause an empty-match
    // infinite loop.
    std::vector<std::string> hits = DeepContentInspector::ScanTextForPII("!!!   ###   ---   ");
    CHECK(hits.empty());
    hits = DeepContentInspector::ScanTextForPII("      ");
    CHECK(hits.empty());
    hits = DeepContentInspector::ScanTextForPII("");
    CHECK(hits.empty());
}

TEST(pii_linear_time_smoke) {
    // A large digit-heavy input should complete quickly (RE2 is linear-time).
    std::string big;
    for (int i = 0; i < 200000; ++i) {
        big += "12 345 6789 ";
    }
    auto start = std::chrono::steady_clock::now();
    std::vector<std::string> hits = DeepContentInspector::ScanTextForPII(big);
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(elapsed < std::chrono::seconds(5));
    // 200k*13 digits can contain valid Luhn sequences; just ensure we didn't
    // crash or hang - results must be a sane number of matches.
    CHECK(hits.size() < 1000000);
}

TEST(mask_ssn_keeps_last4) {
    std::string masked = DeepContentInspector::MaskSensitiveData("ssn 123-45-6789 end");
    CHECK_CONTAINS(masked, "***-**-6789");
    CHECK_NOT_CONTAINS(masked, "123-45-6789");
}

TEST(mask_credit_card_keeps_last4) {
    std::string masked = DeepContentInspector::MaskSensitiveData("card 4111 1111 1111 1111 end");
    CHECK_CONTAINS(masked, "****1111");
    CHECK_NOT_CONTAINS(masked, "4111 1111 1111 1111");
}

TEST(mask_api_key_redacted) {
    std::string masked = DeepContentInspector::MaskSensitiveData("key AKIAIOSFODNN7EXAMPLE end");
    CHECK_CONTAINS(masked, "***REDACTED***");
    CHECK_NOT_CONTAINS(masked, "AKIAIOSFODNN7EXAMPLE");
}

TEST(mask_plain_text_unchanged) {
    std::string masked = DeepContentInspector::MaskSensitiveData("hello world, nothing sensitive here");
    CHECK_EQ(masked, "hello world, nothing sensitive here");
}