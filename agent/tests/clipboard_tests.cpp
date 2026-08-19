/**
 * @file clipboard_tests.cpp
 * @brief Unit tests for Phase 1 Clipboard Visibility (detection-only).
 *
 * PRITRAK Enterprise DLP Agent
 *
 * Covers the pure, unit-testable pieces (bounded UTF-16 extraction, conversion,
 * config validation, privacy-safe serialization, latest-value coalescing queue,
 * typed findings) plus a real lifecycle start/stop test that is skipped
 * gracefully when running in a non-interactive session.
 *
 * All tests use only synthetic data. Assertions also confirm sample clipboard
 * content never appears in the produced event strings.
 */

#include "ClipboardMonitor.h"
#include "DeepContentInspector.h"

#include <string>
#include <vector>

#include "test_main.h"

using namespace Pritrak::DLP;

// ============================================================================
// UTF-16 -> wstring extraction (ClipUtf16ToWstring)
// ============================================================================

TEST(clip_utf16_null_terminated) {
    const wchar_t buf[] = L"hello\0world";
    bool truncated = false, missing = false;
    std::wstring out = ClipUtf16ToWstring(buf, sizeof(buf), 1024, &truncated, &missing);
    CHECK_EQ(out, L"hello");
    CHECK(!truncated);
    CHECK(!missing);
}

TEST(clip_utf16_missing_null) {
    const wchar_t buf[] = {L'A', L'B'};
    bool truncated = false, missing = false;
    std::wstring out = ClipUtf16ToWstring(buf, sizeof(buf), 1024, &truncated, &missing);
    CHECK(out.empty());
    CHECK(!truncated);
    CHECK(missing);
}

TEST(clip_utf16_empty_first_char_null) {
    const wchar_t buf[] = {L'\0', L'A'};
    bool truncated = false, missing = false;
    std::wstring out = ClipUtf16ToWstring(buf, sizeof(buf), 1024, &truncated, &missing);
    CHECK(out.empty());
    CHECK(!truncated);
    CHECK(!missing);
}

TEST(clip_utf16_oversized_capped) {
    const wchar_t buf[] = L"ABCD";
    // Cap at 4 bytes = 2 wchar units.
    bool truncated = false, missing = false;
    std::wstring out = ClipUtf16ToWstring(buf, sizeof(buf), 4, &truncated, &missing);
    CHECK(truncated);
    CHECK(!missing);
    CHECK_EQ(out, L"AB"); // bounded prefix; no surrogate split here
}

TEST(clip_utf16_oversized_no_surrogate_split) {
    // A + high surrogate D83D + low surrogate DE00 + B
    std::wstring content;
    content.push_back(L'A');
    content.push_back(0xD83D);
    content.push_back(0xDE00);
    content.push_back(L'B');
    // Cap at 4 bytes = 2 units: keeps 'A' and the high surrogate; the high
    // surrogate must be dropped so the kept text is not split mid-pair.
    bool truncated = false, missing = false;
    std::wstring out = ClipUtf16ToWstring(content.data(),
        content.size() * sizeof(wchar_t), 4, &truncated, &missing);
    CHECK(truncated);
    CHECK(!missing);
    CHECK_EQ(out, L"A");
}

TEST(clip_utf16_never_reads_beyond_allocation) {
    // A short physical buffer; ensure we never walk past sizeBytes.
    const wchar_t buf[] = {L'X'};
    bool truncated = false, missing = false;
    std::wstring out = ClipUtf16ToWstring(buf, sizeof(buf), 1024, &truncated, &missing);
    CHECK(missing);   // no null within the single unit
    CHECK(out.empty());
    CHECK(!truncated);
}

// ============================================================================
// UTF-16 -> UTF-8 conversion (Utf16ToUtf8)
// ============================================================================

TEST(convert_ascii) {
    CHECK_EQ(Utf16ToUtf8(L"Hello, world"), std::string("Hello, world"));
}

TEST(convert_unicode) {
    CHECK_EQ(Utf16ToUtf8(L"\u00e9\u4e2d\u6587"), std::string("\xC3\xA9\xE4\xB8\xAD\xE6\x96\x87"));
}

TEST(convert_surrogate_pair) {
    // U+1F600 (grinning face) as a surrogate pair.
    std::wstring w;
    w.push_back(0xD83D);
    w.push_back(0xDE00);
    std::string u = Utf16ToUtf8(w);
    CHECK_EQ(u, std::string("\xF0\x9F\x98\x80"));
}

TEST(convert_invalid_utf16_unpaired_surrogate) {
    std::wstring w;
    w.push_back(0xD800); // lone high surrogate
    CHECK(Utf16ToUtf8(w).empty());
}

TEST(convert_empty) {
    CHECK(Utf16ToUtf8(L"").empty());
}

// ============================================================================
// Config validation
// ============================================================================

TEST(config_default_is_valid) {
    ClipboardConfig c;
    std::string reason;
    CHECK(ValidateClipboardConfig(c, &reason));
}

TEST(config_rejects_invalid_values) {
    ClipboardConfig c;
    std::string reason;

    ClipboardConfig neg = c; neg.maxUtf16Bytes = 0;
    CHECK(!ValidateClipboardConfig(neg, &reason));

    ClipboardConfig zeroRetry = c; zeroRetry.openRetryCount = 0;
    CHECK(!ValidateClipboardConfig(zeroRetry, &reason));

    ClipboardConfig negDelay = c; negDelay.openRetryDelayMs = -5;
    CHECK(!ValidateClipboardConfig(negDelay, &reason));

    ClipboardConfig hugeQueue = c; hugeQueue.maxQueuedEvents = 10000;
    CHECK(!ValidateClipboardConfig(hugeQueue, &reason));

    ClipboardConfig hugeRetry = c; hugeRetry.openRetryCount = 500;
    CHECK(!ValidateClipboardConfig(hugeRetry, &reason));

    ClipboardConfig hugeSize = c; hugeSize.maxUtf16Bytes = 1024ULL * 1024 * 1024;
    CHECK(!ValidateClipboardConfig(hugeSize, &reason));
}

// ============================================================================
// Privacy-safe serialization
// ============================================================================

TEST(format_event_is_privacy_safe) {
    ClipboardScanMetadata m;
    m.sensitiveDetected = true;
    m.findingCount = 1;
    m.hardEvidence = true;
    m.entityTypes = {"CREDIT_CARD"};
    m.durationMs = 4;
    m.sequenceNumber = 42;
    const std::string sample = "4111 1111 1111 1111";
    std::string ev = FormatClipboardEvent(m, true);
    CHECK_EQ(ev, std::string("[CLIPBOARD] Sensitive content detected: types=CREDIT_CARD count=1 hard_evidence=true duration_ms=4"));
    CHECK_NOT_CONTAINS(ev, sample);
    CHECK_NOT_CONTAINS(ev, "4111");
}

TEST(format_event_empty_when_not_sensitive) {
    ClipboardScanMetadata m;
    m.sensitiveDetected = false;
    CHECK(FormatClipboardEvent(m, false).empty());
    m.sensitiveDetected = true;
    m.entityTypes = {};
    m.findingCount = 0;
    CHECK_EQ(FormatClipboardEvent(m, true),
        std::string("[CLIPBOARD] Sensitive content detected: types= count=0 hard_evidence=false duration_ms=0"));
}

// ============================================================================
// Bounded latest-value coalescing queue
// ============================================================================

TEST(queue_latest_value_coalescing) {
    BoundedSeqQueue q(1);
    CHECK(q.Update(1));
    CHECK(q.Update(2));   // newer supersedes pending
    CHECK(q.Update(3));
    CHECK_EQ(q.Size(), static_cast<size_t>(1));
    CHECK(q.CoalescedCount() >= 2);   // stale intermediates coalesced
    unsigned int out = 0;
    CHECK(q.Take(out));
    CHECK_EQ(out, 3u);    // only the latest is scanned
    CHECK(!q.HasPending());
}

TEST(queue_duplicate_pending_suppressed) {
    BoundedSeqQueue q(1);
    CHECK(q.Update(10));
    CHECK(!q.Update(10)); // duplicate of pending -> suppressed
    CHECK_EQ(q.Size(), static_cast<size_t>(1));
    unsigned int out = 0;
    CHECK(q.Take(out));
    CHECK_EQ(out, 10u);
}

// ============================================================================
// Typed findings (no raw values exposed)
// ============================================================================

TEST(typed_findings_credit_card_hard) {
    auto res = DeepContentInspector::ScanTextForPIITyped("card 4111 1111 1111 1111 end");
    CHECK(!res.scannerError);
    bool found = false;
    for (const auto& f : res.findings) {
        if (f.entity == DeepContentInspector::PiiEntity::CreditCard) {
            found = true;
            CHECK(f.hardEvidence);               // Luhn-validated => hard
            CHECK(f.strength == DeepContentInspector::EvidenceStrength::Strong);
            CHECK(f.count >= 1);
            CHECK(f.startOffset < f.endOffset);  // offsets within the input
        }
    }
    CHECK(found);
}

TEST(typed_findings_ssn_not_hard) {
    auto res = DeepContentInspector::ScanTextForPIITyped("SSN 123-45-6789 on file");
    CHECK(!res.scannerError);
    bool found = false;
    for (const auto& f : res.findings) {
        if (f.entity == DeepContentInspector::PiiEntity::Ssn) {
            found = true;
            CHECK(!f.hardEvidence);              // structural, not hard evidence
            CHECK(f.strength == DeepContentInspector::EvidenceStrength::Moderate);
        }
    }
    CHECK(found);
}

TEST(typed_findings_api_key) {
    auto res = DeepContentInspector::ScanTextForPIITyped("key AKIAIOSFODNN7EXAMPLE here");
    CHECK(!res.scannerError);
    bool found = false;
    for (const auto& f : res.findings) {
        if (f.entity == DeepContentInspector::PiiEntity::ApiKey) {
            found = true;
            CHECK(!f.hardEvidence);
        }
    }
    CHECK(found);
}

TEST(typed_findings_plain_text_none) {
    auto res = DeepContentInspector::ScanTextForPIITyped("the quick brown fox");
    CHECK(!res.scannerError);
    CHECK(res.findings.empty());
}

TEST(typed_findings_empty_input) {
    auto res = DeepContentInspector::ScanTextForPIITyped("");
    CHECK(!res.scannerError);
    CHECK(res.findings.empty());
}

TEST(entity_names_stable) {
    CHECK_EQ(std::string(DeepContentInspector::PiiEntityName(DeepContentInspector::PiiEntity::CreditCard)), "CREDIT_CARD");
    CHECK_EQ(std::string(DeepContentInspector::PiiEntityName(DeepContentInspector::PiiEntity::Ssn)), "SSN");
    CHECK_EQ(std::string(DeepContentInspector::PiiEntityName(DeepContentInspector::PiiEntity::ApiKey)), "API_KEY");
    CHECK_EQ(std::string(DeepContentInspector::PiiEntityName(DeepContentInspector::PiiEntity::Unknown)), "UNKNOWN");
}

// ScanTextForPII (legacy, raw strings) must still work for existing callers.
TEST(legacy_scan_text_for_pii_compat) {
    std::vector<std::string> hits = DeepContentInspector::ScanTextForPII("SSN 123-45-6789");
    bool found = false;
    for (const auto& h : hits) {
        if (h == "123-45-6789") found = true;
    }
    CHECK(found);
}

// ============================================================================
// Lifecycle (real window + threads); skipped gracefully in non-interactive
// sessions.
// ============================================================================

TEST(clipboard_lifecycle_repeated_start_stop) {
    ClipboardMonitor mon;
    ClipboardConfig cfg;
    mon.Configure(cfg);

    const bool first = mon.Start();
    if (!first) {
        // Session 0 / non-interactive, or environment cannot create a window.
        // Verify shutdown is safe and leaves nothing running.
        mon.Stop();
        CHECK(!mon.IsRunning());
        return;
    }

    CHECK(mon.IsRunning());
    CHECK(mon.IsActiveInSession());
    mon.Stop();
    CHECK(!mon.IsRunning());

    // Repeated start/stop must be idempotent and leak-free.
    CHECK(mon.Start());
    CHECK(mon.Start());          // idempotent
    mon.Stop();
    mon.Stop();                  // idempotent
    CHECK(!mon.IsRunning());

    CHECK(mon.Start());
    mon.Stop();
    CHECK(!mon.IsRunning());
}
