/**
 * @file DeepContentInspector.h
 * @brief Phase 2 DSPM Deep Content Inspection (DCI) - extraction and PII scanning
 *
 * PRITRAK Enterprise DLP Agent
 *
 * Copyright (C) 2026 Pritrak Security
 *
 * Detects document type by content signature (never by extension alone),
 * extracts UTF-8 text from plain text and OOXML (DOCX/XLSX/PPTX) containers,
 * and provides a ReDoS-safe PII scanner backed by Google's RE2.
 *
 * PDF extraction is intentionally NOT implemented in this phase: pdfium is a
 * Chromium-scale dependency that cannot be added via CMake FetchContent, and
 * MuPDF is AGPL/commercial licensed. PDFs are detected by signature and
 * reported as error_category "unsupported" with a warning. Extracting PDF text
 * by scanning raw streams is explicitly forbidden by the DCI specification.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <atomic>
#include <string>
#include <vector>

namespace Pritrak {
namespace DLP {

// ============================================================================
// DCI SAFETY LIMITS (documented memory budget)
// ============================================================================
//
// Memory budget for a single ExtractDocument() call:
//   - input buffer ......................... <= 15 MB   (kMaxInputBytes)
//   - per-part decompression buffer ....... <= 16 MB   (kMaxPartBytesForParse)
//   - total decompressed archive content .. <= 50 MB   (kMaxUncompressedBytes)
//   - accumulated extracted text .......... <=  2 MB   (kMaxExtractedTextBytes)
//   - XML DOM for a single part ........... bounded by kMaxPartBytesForParse
// The worst case is roughly 15 + 50 + 2 MB of live allocations per file.
namespace DciLimits {
inline constexpr size_t kMaxInputBytes          = 15ULL * 1024 * 1024;  // 15 MB
inline constexpr size_t kMaxExtractedTextBytes  = 2ULL * 1024 * 1024;   // 2 MB
inline constexpr uint32_t kMaxArchiveEntries    = 10000;                // entries
inline constexpr uint64_t kMaxUncompressedBytes = 50ULL * 1024 * 1024;  // 50 MB
inline constexpr uint64_t kMaxCompressionRatio  = 100;                  // 100:1
inline constexpr int kMaxNestingDepth           = 0;                    // no nested archives
inline constexpr uint32_t kDefaultDeadlineMs    = 5000;                 // 5 s
inline constexpr size_t kMaxPartBytesForParse   = 16ULL * 1024 * 1024;  // 16 MB / part
} // namespace DciLimits

// Deterministic error categories (never expose file content through these).
namespace DciError {
inline constexpr const char* kNone               = "";
inline constexpr const char* kUnsupported        = "unsupported";
inline constexpr const char* kCorrupt            = "corrupt";
inline constexpr const char* kEncrypted          = "encrypted";
inline constexpr const char* kTooLarge           = "too_large";
inline constexpr const char* kZipBomb            = "zip_bomb";
inline constexpr const char* kTooManyEntries     = "too_many_entries";
inline constexpr const char* kPathTraversal      = "path_traversal";
inline constexpr const char* kTimeout            = "timeout";
inline constexpr const char* kBinary             = "binary";
inline constexpr const char* kMalformedEncoding  = "malformed_encoding";
inline constexpr const char* kReadFailed         = "read_failed";
} // namespace DciError

/**
 * @struct ExtractionResult
 * @brief Structured result of a single DCI extraction.
 */
struct ExtractionResult {
    std::string fileType;          // "text", "docx", "xlsx", "pptx", "pdf", "zip", "ole", "binary"
    std::string extractedText;     // UTF-8, capped at DciLimits::kMaxExtractedTextBytes
    bool truncationStatus = false; // true if extracted text was truncated by the size cap
    std::vector<std::string> warnings;   // fixed, non-sensitive diagnostic strings
    std::string errorCategory;     // one of DciError::* ("" means success)
};

/**
 * @class DeepContentInspector
 * @brief Detects and extracts text from supported document types and scans for PII.
 */
class DeepContentInspector {
public:
    DeepContentInspector();
    ~DeepContentInspector() = default;

    DeepContentInspector(const DeepContentInspector&) = delete;
    DeepContentInspector& operator=(const DeepContentInspector&) = delete;

    /**
     * Set the per-file processing deadline. A deadline of 0 ms causes an
     * immediate timeout (used for deterministic tests).
     */
    void SetDeadline(std::chrono::milliseconds deadline);
    std::chrono::milliseconds GetDeadline() const;

    /**
     * Request cancellation of an in-flight ExtractDocument() call. Checked
     * alongside the deadline; the operation aborts at the next safe point and
     * returns error_category "timeout".
     */
    void Cancel();
    void ResetCancel();

    /**
     * Detect the document type by content signature and extract UTF-8 text.
     * Applies every DCI safety limit (size, entries, ratio, deadline, paths).
     */
    ExtractionResult ExtractDocument(const std::wstring& filePath);

    // --- PII scanning (RE2; linear-time, ReDoS-safe) -------------------------

    /**
     * Scan UTF-8 text for PII. Credit cards are Luhn-validated; SSNs and API
     * keys are matched with the existing (unchanged) patterns.
     */
    static std::vector<std::string> ScanTextForPII(const std::string& text);

    /** Classic Luhn checksum over a digit string. */
    static bool IsValidLuhn(const std::string& digits);

    /** Mask SSNs, credit cards (keep last 4) and API keys in the given text. */
    static std::string MaskSensitiveData(const std::string& text);

private:
    bool DeadlineExpired() const;

    std::chrono::milliseconds deadline_{std::chrono::milliseconds(DciLimits::kDefaultDeadlineMs)};
    std::atomic<bool> cancelled_{false};
};

} // namespace DLP
} // namespace Pritrak