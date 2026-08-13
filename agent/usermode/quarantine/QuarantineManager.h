#pragma once

#include <windows.h>
#include <string>
#include <vector>

class LocalCache;

/**
 * Secure quarantine manager.
 *
 * When an exfiltration policy fires the target file is atomically
 * renamed/moved into a protected workspace folder
 * (C:\ProgramData\PritrakDLP\Quarantine\) that grants access to
 * NT AUTHORITY\SYSTEM only. A GUID is used as the stored filename and the
 * original path, classification, timestamp and user details are persisted to
 * the local SQLite database (cache.db).
 *
 * If the move fails the file is NEVER deleted; instead an exclusive access
 * lock is placed on it (or the failure is reported) and the original file is
 * left untouched.
 */
class QuarantineManager {
public:
    QuarantineManager();
    ~QuarantineManager();

    QuarantineManager(const QuarantineManager&) = delete;
    QuarantineManager& operator=(const QuarantineManager&) = delete;

    /**
     * Initialize the quarantine store.
     *
     * @param cache LocalCache used to persist quarantine metadata (may be null)
     * @return true if the quarantine workspace could be created and locked down
     */
    bool Initialize(LocalCache* cache);

    /**
     * Release any held access locks.
     */
    void Shutdown();

    /**
     * Atomically move a file into quarantine.
     *
     * @param filePath          Full path of the file to quarantine
     * @param classification    Classification string for metadata
     * @param userId            User id associated with the incident
     * @param reason            Policy/reason that triggered quarantine
     * @param quarantinePathOut Optional output receiving the new location
     * @return true if the file was quarantined successfully
     */
    bool QuarantineFile(const std::wstring& filePath,
                        const std::wstring& classification,
                        const std::wstring& userId,
                        const std::wstring& reason,
                        std::wstring* quarantinePathOut = nullptr);

    /**
     * @return true if the quarantine workspace is ready
     */
    bool IsInitialized() const { return initialized_; }

private:
    static std::wstring GetQuarantineRoot();
    static bool EnsureDirectoryExists(const std::wstring& directory);
    static bool ApplySystemOnlyAcl(const std::wstring& directory);
    static std::wstring GenerateGuidFileName(const std::wstring& originalPath);
    // Places an exclusive access lock on the file; the handle is retained in
    // lockedHandles_ until Shutdown.
    bool LockFileHandle(const std::wstring& filePath);

    LocalCache* cache_;
    bool initialized_;
    std::wstring quarantineRoot_;
    std::vector<HANDLE> lockedHandles_;
};
