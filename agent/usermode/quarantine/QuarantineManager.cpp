#include "QuarantineManager.h"
#include "../cache/LocalCache.h"
#include "../../common/utils/logging.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlwapi.h>
#include <objbase.h>
#include <string>
#include <sstream>
#include <chrono>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

namespace {

std::wstring WideFromUtf8(const std::string& utf8) {
    if (utf8.empty()) {
        return L"";
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), &result[0], size);
    return result;
}

std::string Utf8FromWide(const std::wstring& wide) {
    if (wide.empty()) {
        return "";
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), &result[0], size, nullptr, nullptr);
    return result;
}

} // namespace

QuarantineManager::QuarantineManager()
    : cache_(nullptr)
    , initialized_(false)
{
}

QuarantineManager::~QuarantineManager() {
    Shutdown();
}

std::wstring QuarantineManager::GetQuarantineRoot() {
    return L"C:\\ProgramData\\PritrakDLP\\Quarantine";
}

bool QuarantineManager::Initialize(LocalCache* cache) {
    cache_ = cache;
    quarantineRoot_ = GetQuarantineRoot();

    if (!EnsureDirectoryExists(quarantineRoot_)) {
        LOG_ERROR("Quarantine: failed to create root directory");
        return false;
    }

    if (!ApplySystemOnlyAcl(quarantineRoot_)) {
        LOG_ERROR("Quarantine: failed to restrict ACL to SYSTEM");
        return false;
    }

    initialized_ = true;
    LOG_INFO("Quarantine manager initialized: %ws", quarantineRoot_.c_str());
    return true;
}

void QuarantineManager::Shutdown() {
    for (HANDLE h : lockedHandles_) {
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
    lockedHandles_.clear();
    initialized_ = false;
    cache_ = nullptr;
}

bool QuarantineManager::EnsureDirectoryExists(const std::wstring& directory) {
    // Create the directory (and parents) if it does not exist.
    if (!CreateDirectoryW(directory.c_str(), nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            LOG_WARNING("Quarantine: CreateDirectory failed (%lu)", err);
            return false;
        }
    }
    return true;
}

bool QuarantineManager::ApplySystemOnlyAcl(const std::wstring& directory) {
    // DACL granting full control to NT AUTHORITY\SYSTEM only, with no
    // inherited ACEs (protected DACL) so ordinary users and administrators
    // cannot read or write quarantined artifacts.
    LPCWSTR sdString = L"D:P(A;;FA;;;SY)";
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sdString, SDDL_REVISION_1, &sd, nullptr)) {
        LOG_ERROR("Quarantine: ConvertStringSecurityDescriptorToSecurityDescriptor failed (%lu)", GetLastError());
        return false;
    }

    if (!GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) ||
        !daclPresent || dacl == nullptr) {
        LOG_ERROR("Quarantine: failed to extract DACL from security descriptor");
        LocalFree(sd);
        return false;
    }

    // Apply the SYSTEM-only DACL. PROTECTED_DACL prevents inheritance from
    // the parent so no other principal can gain access.
    DWORD result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(directory.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        dacl,
        nullptr);

    LocalFree(sd);

    if (result != ERROR_SUCCESS) {
        LOG_ERROR("Quarantine: SetNamedSecurityInfo failed (%lu)", result);
        return false;
    }

    return true;
}

std::wstring QuarantineManager::GenerateGuidFileName(const std::wstring& originalPath) {
    GUID guid = {0};
    if (FAILED(CoCreateGuid(&guid))) {
        // Extremely unlikely; fall back to a time-based unique name.
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        std::wstring fallback = L"quarantine-" + std::to_wstring(now);
        return fallback;
    }

    WCHAR guidBuffer[64] = {0};
    swprintf_s(guidBuffer, _countof(guidBuffer),
        L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

    // Preserve the original extension for forensic convenience.
    std::wstring extension;
    size_t dotPos = originalPath.find_last_of(L'.');
    size_t slashPos = originalPath.find_last_of(L"\\/");
    if (dotPos != std::wstring::npos && (slashPos == std::wstring::npos || dotPos > slashPos)) {
        extension = originalPath.substr(dotPos);
    }

    return std::wstring(guidBuffer) + extension;
}

bool QuarantineManager::QuarantineFile(const std::wstring& filePath,
                                       const std::wstring& classification,
                                       const std::wstring& userId,
                                       const std::wstring& reason,
                                       std::wstring* quarantinePathOut) {
    if (!initialized_ || filePath.empty()) {
        return false;
    }

    // The file must exist; if it no longer exists there is nothing to move.
    DWORD attrs = GetFileAttributesW(filePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        LOG_WARNING("Quarantine: source file not accessible: %ws", filePath.c_str());
        return false;
    }

    std::wstring destination = quarantineRoot_ + L"\\" + GenerateGuidFileName(filePath);

    // Atomic rename/move. MOVEFILE_COPY_ALLOWED permits cross-volume moves;
    // MOVEFILE_WRITE_THROUGH flushes the metadata to disk. On the same volume
    // this is an atomic rename operation.
    BOOL moved = MoveFileExW(
        filePath.c_str(),
        destination.c_str(),
        MOVEFILE_WRITE_THROUGH | MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);

    if (!moved) {
        DWORD err = GetLastError();
        LOG_ERROR("Quarantine: move failed for %ws (%lu)", filePath.c_str(), err);

        // Fallback: do NOT delete the file. Attempt to place an exclusive
        // access lock on it; if that fails, report the failure only.
        if (LockFileHandle(filePath)) {
            LOG_WARNING("Quarantine: file locked in place (access denied to other processes): %ws", filePath.c_str());
        } else {
            LOG_ERROR("Quarantine: could not lock or quarantine %ws; file left untouched", filePath.c_str());
        }
        return false;
    }

    // Persist quarantine metadata to the local SQLite database.
    if (cache_ != nullptr) {
        cache_->StoreQuarantineRecord(
            Utf8FromWide(filePath),
            Utf8FromWide(destination),
            Utf8FromWide(classification),
            Utf8FromWide(userId),
            Utf8FromWide(reason));
    }

    LOG_INFO("Quarantined: %ws -> %ws", filePath.c_str(), destination.c_str());

    if (quarantinePathOut != nullptr) {
        *quarantinePathOut = destination;
    }

    return true;
}

bool QuarantineManager::LockFileHandle(const std::wstring& filePath) {
    // Open the file with FILE_SHARE_NONE so no other process can open it while
    // the lock handle is held. The handle is retained for the lifetime of the
    // manager (RAII cleanup on Shutdown).
    HANDLE handle = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        0,  // FILE_SHARE_NONE: exclusive access lock
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    lockedHandles_.push_back(handle);
    return true;
}
