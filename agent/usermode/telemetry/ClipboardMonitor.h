/**
 * @file ClipboardMonitor.h
 * @brief Phase 1 Clipboard Visibility - DETECTION ONLY.
 *
 * PRITRAK Enterprise DLP Agent
 *
 * This component detects clipboard changes via a message-only window and
 * AddClipboardFormatListener, then captures a BOUNDED copy of the clipboard
 * text and runs it through the existing DCI/PII engine for privacy-safe
 * telemetry.
 *
 * DETECTION ONLY:
 *   - It never blocks, empties, replaces, delays or otherwise modifies the
 *     clipboard.
 *   - It never identifies the future paste destination. AddClipboardFormatListener
 *     reports clipboard changes but does not reliably identify which process
 *     will paste next.
 *
 * Architecture:
 *   - A dedicated, joinable listener thread owns a unique window class, a
 *     message-only window (HWND_MESSAGE) and the clipboard format listener.
 *   - The window procedure is intentionally lightweight: on WM_CLIPBOARDUPDATE
 *     it only records the sequence number into a bounded queue.
 *   - A dedicated worker thread drains that queue and performs clipboard
 *     capture, bounded UTF-16 -> UTF-8 conversion and classification. This keeps
 *     all clipboard access and classification OFF the listener message loop.
 */

#pragma once

#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace Pritrak {
namespace DLP {

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * Conservative, bounded configuration for clipboard monitoring. Values are
 * validated by ValidateClipboardConfig() before use; invalid values fall back
 * to defaults rather than being used unsafely.
 */
struct ClipboardConfig {
    bool enabled            = true;                 // master switch
    size_t maxUtf16Bytes    = 2ULL * 1024 * 1024;   // 2 MiB default cap
    int    openRetryCount   = 5;                    // bounded open retries
    int    openRetryDelayMs = 50;                   // 25-50ms recommended
    size_t maxQueuedEvents  = 16;                   // bounded worker queue
    int    scanTimeoutMs    = 2000;                 // classification guard
};

// ============================================================================
// OUTCOMES (STEP 7 - explicit internal outcomes)
// ============================================================================

enum class ClipboardOutcome {
    Scanned,          // content captured and classified
    Empty,            // clipboard text is empty
    UnsupportedFormat,// CF_UNICODETEXT not available
    Oversized,        // content exceeded the configured byte cap
    Busy,             // clipboard locked by another process
    TimedOut,         // classification exceeded the scan timeout
    Unavailable,      // clipboard data could not be retrieved
    InvalidInput,     // malformed UTF-16 / conversion failure
    Cancelled         // aborted because shutdown began
};

// ============================================================================
// RESULT METADATA (privacy-safe: never holds content)
// ============================================================================

/**
 * Structured, content-free result of a clipboard scan. Only counts, types,
 * strength flags and the sequence number are recorded - never the text itself.
 */
struct ClipboardScanMetadata {
    ClipboardOutcome outcome        = ClipboardOutcome::Scanned;
    int      findingCount           = 0;
    bool     hardEvidence           = false;
    bool     sensitiveDetected      = false;
    std::vector<std::string> entityTypes;   // e.g. "CREDIT_CARD", "SSN", "API_KEY"
    long long durationMs            = 0;
    unsigned int sequenceNumber     = 0;
};

// ============================================================================
// PURE, UNIT-TESTABLE HELPERS
// ============================================================================

/**
 * Boundedly extract a UTF-16 string from raw clipboard memory.
 * Never reads beyond sizeBytes. Stops at the first null terminator. If no
 * terminator is found within maxBytes the content is oversized (truncated=true)
 * and the copy is capped; if no terminator exists in the whole allocation,
 * missingNull=true.
 * @param sizeBytes   allocated size returned by GlobalSize()
 * @param maxBytes    configured cap in bytes
 */
std::wstring ClipUtf16ToWstring(const void* ptr, SIZE_T sizeBytes,
                                size_t maxBytes, bool* truncated, bool* missingNull);

/** Bounded UTF-16 -> UTF-8 conversion using WideCharToMultiByte. Returns an
 *  empty string on invalid UTF-16 (WC_ERR_INVALID_CHARS). Never throws. */
std::string Utf16ToUtf8(const std::wstring& wide);

/** Validate a ClipboardConfig; on failure writes a reason and returns false. */
bool ValidateClipboardConfig(const ClipboardConfig& cfg, std::string* reason);

/**
 * Format a privacy-safe sensitive-data event string. The result contains only
 * counts/types/strength flags - NEVER clipboard content. Returns "" when not
 * sensitive.
 */
std::string FormatClipboardEvent(const ClipboardScanMetadata& meta, bool sensitive);

/**
 * Bounded sequence queue with duplicate suppression. Encapsulates the
 * "schedule clipboard capture" decision so it can be unit-tested without a
 * window or thread.
 */
struct BoundedSeqQueue {
    explicit BoundedSeqQueue(size_t capacity);
    /** Returns true if the sequence was scheduled; false for a duplicate that
     *  was already scheduled or when the queue is full (safely dropped). */
    bool Push(unsigned int seq);
    /** Pop the next pending sequence; false when empty. */
    bool Pop(unsigned int& out);
    size_t Size() const;
    size_t Capacity() const { return max_; }

private:
    size_t max_;
    std::deque<unsigned int> items_;
    unsigned int last_ = 0;
    bool hasLast_ = false;
};

// ============================================================================
// CLIPBOARD MONITOR
// ============================================================================

/**
 * Clipboard change listener with bounded, privacy-safe detection.
 *
 * Lifecycle is idempotent: Start()/Stop() may be called repeatedly. The
 * listener and worker threads are always joined (never detached).
 */
class ClipboardMonitor {
public:
    ClipboardMonitor();
    ~ClipboardMonitor();

    ClipboardMonitor(const ClipboardMonitor&) = delete;
    ClipboardMonitor& operator=(const ClipboardMonitor&) = delete;

    /** Set configuration. Must be called before Start(). */
    void Configure(const ClipboardConfig& cfg);

    /**
     * Start monitoring. Returns true when the listener thread, message-only
     * window and format listener were all created successfully AND the process
     * is running in the interactive (active console) session. Returns false
     * (safely) if disabled, not in an interactive session, or on any
     * initialization failure - in which case nothing is leaked.
     */
    bool Start();

    /** Idempotent shutdown: posts a private WM_APP message, joins both
     *  threads, and cleans up the window/class/listener. */
    void Stop();

    bool IsRunning() const { return started_.load(); }
    /** True when clipboard monitoring is effective in this session. */
    bool IsActiveInSession() const;

    /** Number of pending, unscheduled queue entries (test seam). */
    size_t PendingQueueSize() const;

private:
    // Listener thread (owns window + class + listener registration).
    void ListenerThread(std::shared_ptr<std::promise<bool>> ready);
    // Worker thread (capture + convert + classify, off the message loop).
    void WorkerThread();

    static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    LRESULT HandleMessage(HWND hwnd, UINT msg);

    void OnClipboardUpdate();
    void Schedule(unsigned int seq);
    void ProcessClipboard(unsigned int seq);
    ClipboardScanMetadata RunClassification(const std::string& utf8,
                                             const ClipboardScanMetadata& meta) const;
    void EmitDiagnostic(const ClipboardScanMetadata& meta) const;
    bool IsInteractiveSession() const;
    void CleanupListener();

    std::atomic<bool> running_{false};
    std::atomic<bool> started_{false};
    std::thread listenerThread_;
    std::thread workerThread_;
    std::thread::id listenerThreadId_;

    HWND hwnd_{nullptr};
    std::wstring windowClassName_;
    bool classOwned_ = false;

    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    BoundedSeqQueue queue_{16};

    ClipboardConfig cfg_;
};

} // namespace DLP
} // namespace Pritrak
