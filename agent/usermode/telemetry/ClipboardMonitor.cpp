/**
 * @file ClipboardMonitor.cpp
 * @brief Phase 1 Clipboard Visibility - DETECTION ONLY. Implementation.
 *
 * PRITRAK Enterprise DLP Agent
 */

#include "ClipboardMonitor.h"

#include "../classification/DeepContentInspector.h"
#include "../../common/utils/logging.h"

#include <algorithm>
#include <chrono>

namespace Pritrak {
namespace DLP {

namespace {
constexpr UINT kShutdownMsg = WM_APP + 0x41;
std::atomic<unsigned long long> g_classCounter{0};

// Maps an outcome to a fixed, content-free diagnostic string.
const char* OutcomeString(ClipboardOutcome o) {
    switch (o) {
        case ClipboardOutcome::Empty:             return "status=empty";
        case ClipboardOutcome::UnsupportedFormat: return "status=unsupported_format";
        case ClipboardOutcome::Oversized:         return "status=oversized";
        case ClipboardOutcome::Busy:              return "status=busy";
        case ClipboardOutcome::TimedOut:          return "status=timed_out";
        case ClipboardOutcome::Unavailable:       return "";
        case ClipboardOutcome::InvalidInput:      return "status=invalid_input";
        case ClipboardOutcome::ScanError:         return "status=scan_error";
        case ClipboardOutcome::Cancelled:         return "status=cancelled";
        case ClipboardOutcome::Scanned:
        default:                                  return "";
    }
}
} // namespace

// ============================================================================
// PURE HELPERS
// ============================================================================

std::wstring ClipUtf16ToWstring(const void* ptr, SIZE_T sizeBytes,
                                size_t maxBytes, bool* truncated, bool* missingNull)
{
    *truncated = false;
    *missingNull = false;
    if (ptr == nullptr || sizeBytes < sizeof(wchar_t)) {
        return L"";
    }
    const wchar_t* p = static_cast<const wchar_t*>(ptr);
    const size_t maxUnits = maxBytes / sizeof(wchar_t);
    const size_t units = static_cast<size_t>(sizeBytes) / sizeof(wchar_t);
    const size_t n = std::min(maxUnits, units);

    for (size_t i = 0; i < n; ++i) {
        if (p[i] == L'\0') {
            return std::wstring(p, i);
        }
    }

    // No null terminator within the first n code units.
    if (n < units) {
        // The content extends beyond maxBytes: oversized. Copy a bounded prefix
        // without splitting a UTF-16 surrogate pair.
        *truncated = true;
        size_t copy = n;
        if (copy > 0 && p[copy - 1] >= 0xD800 && p[copy - 1] <= 0xDBFF) {
            --copy; // drop a trailing high surrogate so the kept text stays valid
        }
        return std::wstring(p, copy);
    }

    // Scanned the entire allocation with no terminator.
    *missingNull = true;
    return L"";
}

std::string Utf16ToUtf8(const std::wstring& wide) {
    if (wide.empty()) {
        return "";
    }
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) {
        return ""; // invalid UTF-16 (e.g. unpaired surrogate)
    }
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        wide.data(), static_cast<int>(wide.size()), &out[0], n, nullptr, nullptr);
    return out;
}

bool ValidateClipboardConfig(const ClipboardConfig& cfg, std::string* reason) {
    auto fail = [&reason](const char* msg) -> bool {
        if (reason) *reason = msg;
        return false;
    };
    // Reject negative / unsafe / unbounded values.
    if (cfg.maxUtf16Bytes < 2) return fail("maxUtf16Bytes must be at least 2 bytes");
    if (cfg.maxUtf16Bytes > (64ULL * 1024 * 1024)) return fail("maxUtf16Bytes is excessive");
    if (cfg.openRetryCount < 1) return fail("openRetryCount must be >= 1");
    if (cfg.openRetryCount > 20) return fail("openRetryCount is excessive");
    if (cfg.openRetryDelayMs < 1) return fail("openRetryDelayMs must be >= 1");
    if (cfg.openRetryDelayMs > 500) return fail("openRetryDelayMs is excessive");
    if (cfg.maxQueuedEvents < 1) return fail("maxQueuedEvents must be >= 1");
    if (cfg.maxQueuedEvents > 64) return fail("maxQueuedEvents is excessive");
    if (cfg.scanTimeoutMs < 0) return fail("scanTimeoutMs must be >= 0");
    if (cfg.scanTimeoutMs > 60000) return fail("scanTimeoutMs is excessive");
    return true;
}

std::string FormatClipboardEvent(const ClipboardScanMetadata& meta, bool sensitive) {
    if (!sensitive) {
        return "";
    }
    std::string types;
    for (size_t i = 0; i < meta.entityTypes.size(); ++i) {
        if (i) types += ",";
        types += meta.entityTypes[i];
    }
    return "[CLIPBOARD] Sensitive content detected: types=" + types +
        " count=" + std::to_string(meta.findingCount) +
        " hard_evidence=" + (meta.hardEvidence ? "true" : "false") +
        " duration_ms=" + std::to_string(meta.durationMs);
}

// ============================================================================
// BOUNDED LATEST-VALUE QUEUE
// ============================================================================

BoundedSeqQueue::BoundedSeqQueue(size_t capacity) : max_(capacity == 0 ? 1 : capacity) {}

bool BoundedSeqQueue::Update(unsigned int seq) {
    if (hasPending_) {
        if (seq == pending_) {
            return false; // exact duplicate of the currently pending value
        }
        ++coalesced_; // a newer value supersedes the pending one: coalesce
    }
    pending_ = seq;
    hasPending_ = true;
    return true;
}

bool BoundedSeqQueue::Take(unsigned int& out) {
    if (!hasPending_) {
        return false;
    }
    out = pending_;
    hasPending_ = false;
    return true;
}

bool BoundedSeqQueue::HasPending() const { return hasPending_; }
size_t BoundedSeqQueue::Size() const { return hasPending_ ? 1 : 0; }
size_t BoundedSeqQueue::CoalescedCount() const { return coalesced_; }

// ============================================================================
// LIFECYCLE
// ============================================================================

ClipboardMonitor::ClipboardMonitor() {
    shutdownEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

ClipboardMonitor::~ClipboardMonitor() {
    Stop();
    if (shutdownEvent_) {
        CloseHandle(shutdownEvent_);
        shutdownEvent_ = nullptr;
    }
}

void ClipboardMonitor::Configure(const ClipboardConfig& cfg) {
    cfg_ = cfg;
    std::string reason;
    if (!ValidateClipboardConfig(cfg_, &reason)) {
        LOG_WARNING("[CLIPBOARD] Invalid configuration (%s); using conservative defaults",
            reason.c_str());
        cfg_ = ClipboardConfig();
    }
}

bool ClipboardMonitor::IsInteractiveSession() const {
    DWORD sessionId = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
        return false;
    }
    // Session 0 is the non-interactive service session. Clipboard changes only
    // occur in interactive sessions, so monitoring is only supported when NOT
    // in Session 0. (No service-to-user spawning is attempted in this phase.)
    return sessionId != 0;
}

bool ClipboardMonitor::IsActiveInSession() const {
    return started_.load() && IsInteractiveSession();
}

bool ClipboardMonitor::Start() {
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (started_.load()) {
        return true;
    }
    if (!cfg_.enabled) {
        LOG_INFO("[CLIPBOARD] Monitoring disabled by configuration");
        return false;
    }
    if (!IsInteractiveSession()) {
        LOG_WARNING("[CLIPBOARD] Clipboard visibility requires an interactive user session; "
            "running in Session 0 (service). Clipboard monitoring is NOT ACTIVE. "
            "Production deployment requires a per-user companion process or user-session agent.");
        return false;
    }

    if (shutdownEvent_) {
        ResetEvent(shutdownEvent_);
    }
    running_.store(true);
    started_.store(true);

    auto ready = std::make_shared<std::promise<bool>>();
    auto future = ready->get_future();
    listenerThread_ = std::thread(&ClipboardMonitor::ListenerThread, this, ready);
    workerThread_ = std::thread(&ClipboardMonitor::WorkerThread, this);

    const bool ok = future.get();
    if (!ok) {
        // Initialization failed: stop both threads and report no leak.
        running_.store(false);
        queueCv_.notify_all();
        if (shutdownEvent_) SetEvent(shutdownEvent_);
        if (listenerThread_.joinable()) listenerThread_.join();
        if (workerThread_.joinable()) workerThread_.join();
        started_.store(false);
        LOG_WARNING("[CLIPBOARD] Listener initialization failed; monitoring not started");
        return false;
    }
    LOG_INFO("[CLIPBOARD] Clipboard visibility active");
    return true;
}

void ClipboardMonitor::Stop() {
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (!started_.load()) {
        // Not running: ensure any abandoned thread is joined and nothing leaks.
        if (listenerThread_.joinable()) listenerThread_.join();
        if (workerThread_.joinable()) workerThread_.join();
        return;
    }

    running_.store(false);
    queueCv_.notify_all();                       // wake the worker
    if (shutdownEvent_) SetEvent(shutdownEvent_); // interrupt retry sleeps

    // Deliver shutdown to the listener only after its message queue exists.
    // Start() returned successfully, which guarantees the window (and thus the
    // queue) was created before Stop() could be reached.
    if (hwnd_) {
        PostMessageW(hwnd_, kShutdownMsg, 0, 0);
    }

    if (workerThread_.joinable()) workerThread_.join();
    if (listenerThread_.joinable()) listenerThread_.join();

    started_.store(false);
}

// ============================================================================
// LISTENER THREAD (owns window + class + listener)
// ============================================================================

void ClipboardMonitor::ListenerThread(std::shared_ptr<std::promise<bool>> ready) {
    MSG msg;
    // Force the message queue to exist before we signal readiness.
    PeekMessageW(&msg, nullptr, 0, 0, PM_NOREMOVE);

    windowClassName_ = L"PritrakDLPClipboardListener_" +
        std::to_wstring(GetCurrentProcessId()) + L"_" +
        std::to_wstring(g_classCounter.fetch_add(1));

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &ClipboardMonitor::StaticWndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = windowClassName_.c_str();

    const ATOM atom = RegisterClassExW(&wc);
    if (!atom) {
        ready->set_value(false);
        return;
    }
    classOwned_ = true;

    hwnd_ = CreateWindowExW(0, windowClassName_.c_str(), L"PritrakDLPClipboard",
        0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), this);
    if (!hwnd_) {
        CleanupListener();
        ready->set_value(false);
        return;
    }

    if (!AddClipboardFormatListener(hwnd_)) {
        CleanupListener();
        ready->set_value(false);
        return;
    }

    // Success is reported only after window creation AND listener registration.
    ready->set_value(true);

    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Cleanup runs on the listener thread, so WndProc can never race it.
    CleanupListener();
}

void ClipboardMonitor::CleanupListener() {
    if (hwnd_) {
        RemoveClipboardFormatListener(hwnd_);
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
    if (classOwned_) {
        UnregisterClassW(windowClassName_.c_str(), GetModuleHandleW(nullptr));
        classOwned_ = false;
    }
}

// ============================================================================
// WINDOW PROCEDURE (kept lightweight)
// ============================================================================

LRESULT CALLBACK ClipboardMonitor::StaticWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    ClipboardMonitor* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = static_cast<ClipboardMonitor*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<ClipboardMonitor*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (self) {
        return self->HandleMessage(hwnd, msg);
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT ClipboardMonitor::HandleMessage(HWND hwnd, UINT msg) {
    switch (msg) {
        case WM_CLIPBOARDUPDATE:
            // Lightweight: only record the sequence; capture happens on the
            // worker thread. No classification, sleep or retry here.
            OnClipboardUpdate();
            return 0;
        case kShutdownMsg:
            PostQuitMessage(0);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, 0, 0);
    }
}

// ============================================================================
// SCHEDULING (latest-value coalescing)
// ============================================================================

void ClipboardMonitor::OnClipboardUpdate() {
    Schedule(GetClipboardSequenceNumber());
}

void ClipboardMonitor::Schedule(unsigned int seq) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    if (queue_.Update(seq)) {
        queueCv_.notify_one();
    }
}

size_t ClipboardMonitor::PendingQueueSize() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return queue_.Size();
}

// ============================================================================
// WORKER THREAD (capture + convert + classify)
// ============================================================================

void ClipboardMonitor::WorkerThread() {
    while (true) {
        unsigned int seq = 0;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCv_.wait(lock, [this] { return !running_.load() || queue_.HasPending(); });
            if (!running_.load() && !queue_.HasPending()) {
                break;
            }
            if (!queue_.Take(seq)) {
                continue;
            }
            if (!running_.load()) {
                break; // stop promptly; drop stale pending work
            }
        }
        ProcessClipboard(seq);
    }
}

void ClipboardMonitor::ProcessClipboard(unsigned int seq) {
    if (!running_.load()) {
        return; // cancelled (shutdown)
    }
    const auto t0 = std::chrono::steady_clock::now();

    // The notified sequence may already be stale; if so, re-schedule the
    // current one rather than scanning mismatched content.
    const DWORD before = GetClipboardSequenceNumber();
    if (before != seq) {
        Schedule(static_cast<unsigned int>(before));
        return;
    }

    // Bounded, shutdown-aware open (another process may own the clipboard).
    bool opened = false;
    for (int attempt = 0; attempt < cfg_.openRetryCount; ++attempt) {
        if (!running_.load()) {
            return;
        }
        if (OpenClipboard(nullptr)) {
            opened = true;
            break;
        }
        if (GetLastError() != ERROR_ACCESS_DENIED) {
            break;
        }
        if (attempt + 1 < cfg_.openRetryCount) {
            // Interruptible wait: returns WAIT_OBJECT_0 when Stop() is called.
            if (WaitForSingleObject(shutdownEvent_, static_cast<DWORD>(cfg_.openRetryDelayMs)) ==
                WAIT_OBJECT_0) {
                return; // shutdown during retry
            }
        }
    }

    ClipboardScanMetadata meta;
    meta.sequenceNumber = seq;

    if (!opened) {
        meta.outcome = ClipboardOutcome::Busy;
        EmitDiagnostic(meta);
        return;
    }

    std::wstring wide;
    bool haveContent = false;
    {
        // Clipboard is open in this scope; CloseClipboard runs on scope exit.
        struct ClipboardCloser { ~ClipboardCloser() { CloseClipboard(); } } closer;

        if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) {
            meta.outcome = ClipboardOutcome::UnsupportedFormat;
        } else {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (!hData) {
                meta.outcome = ClipboardOutcome::Unavailable;
            } else {
                void* locked = GlobalLock(hData);
                if (!locked) {
                    meta.outcome = ClipboardOutcome::Unavailable;
                } else {
                    // GlobalUnlock runs on scope exit. We never call GlobalFree
                    // on clipboard-owned memory and never touch the pointer
                    // after unlock: the text is copied into our own buffer here.
                    struct GlobalUnlocker { HANDLE h; ~GlobalUnlocker() { GlobalUnlock(h); } } unlocker{hData};
                    const SIZE_T sizeBytes = GlobalSize(hData);
                    bool truncated = false, missingNull = false;
                    wide = ClipUtf16ToWstring(locked, sizeBytes, cfg_.maxUtf16Bytes,
                        &truncated, &missingNull);
                    if (truncated) {
                        meta.outcome = ClipboardOutcome::Oversized;
                    } else if (missingNull) {
                        meta.outcome = ClipboardOutcome::InvalidInput;
                    } else if (wide.empty()) {
                        meta.outcome = ClipboardOutcome::Empty;
                    } else {
                        haveContent = true;
                    }
                }
            }
        }
    } // clipboard now closed and unlocked

    if (!haveContent) {
        EmitDiagnostic(meta);
        return;
    }

    // If the sequence changed while we captured, the content we read may not
    // match `seq`. Discard the sample and re-schedule the latest sequence.
    const DWORD after = GetClipboardSequenceNumber();
    if (after != seq) {
        Schedule(static_cast<unsigned int>(after));
        return;
    }

    // Convert + classify only AFTER the clipboard is closed.
    const std::string utf8 = Utf16ToUtf8(wide);
    if (utf8.empty()) {
        meta.outcome = ClipboardOutcome::InvalidInput;
        EmitDiagnostic(meta);
        return;
    }

    meta = RunClassification(utf8, meta);
    meta.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    if (meta.sensitiveDetected) {
        LOG_INFO("%s", FormatClipboardEvent(meta, true).c_str());
    }
    // No event when nothing sensitive was found (content-free by design).
}

// ============================================================================
// CLASSIFICATION (reuses the DCI/PII engine; typed, content-free metadata)
// ============================================================================

ClipboardScanMetadata ClipboardMonitor::RunClassification(
    const std::string& utf8, const ClipboardScanMetadata& meta) const
{
    const auto t0 = std::chrono::steady_clock::now();

    // Typed findings carry no raw values.
    const DeepContentInspector::PiiScanResult res =
        DeepContentInspector::ScanTextForPIITyped(utf8);

    const long long elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    ClipboardScanMetadata m = meta;
    if (res.scannerError) {
        // A scanner failure must NOT be interpreted as clean or safe content.
        m.outcome = ClipboardOutcome::ScanError;
        m.durationMs = elapsedMs;
        EmitDiagnostic(m);
        return m;
    }
    if (cfg_.scanTimeoutMs > 0 && elapsedMs > cfg_.scanTimeoutMs) {
        m.outcome = ClipboardOutcome::TimedOut;
        m.durationMs = elapsedMs;
        EmitDiagnostic(m);
        return m;
    }

    m.outcome = ClipboardOutcome::Scanned;
    if (res.findings.empty()) {
        return m;
    }

    int total = 0;
    bool hard = false;
    std::vector<std::string> types;
    for (const auto& f : res.findings) {
        total += static_cast<int>(f.count);
        if (f.hardEvidence) {
            hard = true;
        }
        const char* name = DeepContentInspector::PiiEntityName(f.entity);
        if (name && name[0] != '\0' && std::string(name) != "UNKNOWN") {
            if (std::find(types.begin(), types.end(), name) == types.end()) {
                types.push_back(name);
            }
        }
    }
    m.findingCount = total;
    m.hardEvidence = hard;
    m.sensitiveDetected = true;
    m.entityTypes = std::move(types);
    m.durationMs = elapsedMs;
    return m;
}

void ClipboardMonitor::EmitDiagnostic(const ClipboardScanMetadata& meta) const {
    // Content-free diagnostics only; never log clipboard data.
    const char* suffix = OutcomeString(meta.outcome);
    if (meta.outcome == ClipboardOutcome::Unavailable) {
        LOG_DEBUG("[CLIPBOARD] Clipboard unavailable");
    } else if (suffix && suffix[0] != '\0') {
        LOG_DEBUG("[CLIPBOARD] %s", suffix);
    }
}

} // namespace DLP
} // namespace Pritrak
