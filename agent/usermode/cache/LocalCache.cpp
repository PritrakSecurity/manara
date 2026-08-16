#include "LocalCache.h"
#include "../comms/SecureComm.h"
#include "../../common/utils/logging.h"
#include <sqlite3.h>
#include <sstream>
#include <chrono>

LocalCache::LocalCache()
    : db_(nullptr)
    , initialized_(false)
{
}

LocalCache::~LocalCache() {
    Shutdown();
}

bool LocalCache::Initialize(const std::string& dbPath) {
    std::lock_guard<std::mutex> lock(dbMutex_);

    dbPath_ = dbPath;

    // Ensure the parent directory exists before opening the database.
    size_t slashPos = dbPath_.find_last_of("\\/");
    if (slashPos != std::string::npos) {
        std::string dir = dbPath_.substr(0, slashPos);
        CreateDirectoryA(dir.c_str(), nullptr);
    }

    // Open or create database
    int rc = sqlite3_open(dbPath.c_str(), reinterpret_cast<sqlite3**>(&db_));
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to open cache database: %s", sqlite3_errmsg(reinterpret_cast<sqlite3*>(db_)));
        return false;
    }

    // Set a busy timeout so concurrent connections (e.g. quarantine manager)
    // do not fail immediately with SQLITE_BUSY.
    sqlite3_busy_timeout(reinterpret_cast<sqlite3*>(db_), 5000);

    // WAL journal improves durability and allows concurrent readers.
    sqlite3_exec(reinterpret_cast<sqlite3*>(db_), "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    // Create tables
    if (!CreateTables()) {
        sqlite3_close(reinterpret_cast<sqlite3*>(db_));
        db_ = nullptr;
        return false;
    }

    initialized_ = true;
    LOG_INFO("Local cache initialized: %s", dbPath.c_str());
    return true;
}

void LocalCache::Shutdown() {
    std::lock_guard<std::mutex> lock(dbMutex_);

    if (db_) {
        sqlite3_close(reinterpret_cast<sqlite3*>(db_));
        db_ = nullptr;
    }
    initialized_ = false;
}

bool LocalCache::CreateTables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_json TEXT NOT NULL,
            synced INTEGER DEFAULT 0,
            synced_at INTEGER,
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_synced ON events(synced);

        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            classification TEXT NOT NULL,
            user_id TEXT,
            reason TEXT,
            quarantined_at INTEGER NOT NULL
        );
    )";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(reinterpret_cast<sqlite3*>(db_), sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to create tables: %s", errMsg);
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

bool LocalCache::StorePolicy(const std::string& policyJson) {
    std::lock_guard<std::mutex> lock(dbMutex_);

    if (!initialized_) {
        return false;
    }

    const char* sql = "INSERT OR REPLACE INTO policies (id, policy_json, updated_at) VALUES (1, ?, ?)";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db_), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement: %s", sqlite3_errmsg(reinterpret_cast<sqlite3*>(db_)));
        return false;
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    sqlite3_bind_text(stmt, 1, policyJson.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to store policy: %s", sqlite3_errmsg(reinterpret_cast<sqlite3*>(db_)));
        return false;
    }

    return true;
}

std::string LocalCache::LoadPolicy() {
    std::lock_guard<std::mutex> lock(dbMutex_);

    if (!initialized_) {
        return "";
    }

    const char* sql = "SELECT policy_json FROM policies WHERE id = 1";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db_), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return "";
    }

    std::string policyJson;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* json = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (json) {
            policyJson = json;
        }
    }

    sqlite3_finalize(stmt);
    return policyJson;
}

bool LocalCache::StoreEvent(const Event& event) {
    std::lock_guard<std::mutex> lock(dbMutex_);

    if (!initialized_) {
        return false;
    }

    const char* sql = "INSERT INTO events (event_json, synced, created_at) VALUES (?, 0, ?)";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db_), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    std::string eventJson = event.ToJson();
    auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    sqlite3_bind_text(stmt, 1, eventJson.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to store event: %s", sqlite3_errmsg(reinterpret_cast<sqlite3*>(db_)));
        return false;
    }

    return true;
}

bool LocalCache::GetPendingEvents(std::vector<Event>& events, int batchSize) {
    std::lock_guard<std::mutex> lock(dbMutex_);

    events.clear();

    if (!initialized_ || batchSize <= 0) {
        return false;
    }

    const char* sql = "SELECT id, event_json FROM events WHERE synced = 0 ORDER BY created_at ASC, id ASC LIMIT ?";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db_), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare pending events query: %s", sqlite3_errmsg(reinterpret_cast<sqlite3*>(db_)));
        return false;
    }

    sqlite3_bind_int(stmt, 1, batchSize);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* payload = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (payload == nullptr) {
            continue;
        }

        Event event;
        if (Event::FromJson(payload, event)) {
            events.push_back(std::move(event));
        } else {
            LOG_WARNING("Skipping malformed pending event payload");
        }
    }

    sqlite3_finalize(stmt);
    return true;
}

bool LocalCache::GetPendingEventIds(std::vector<uint64_t>& ids, int batchSize) {
    std::lock_guard<std::mutex> lock(dbMutex_);

    ids.clear();

    if (!initialized_ || batchSize <= 0) {
        return false;
    }

    const char* sql = "SELECT id FROM events WHERE synced = 0 ORDER BY created_at ASC, id ASC LIMIT ?";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db_), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int(stmt, 1, batchSize);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ids.push_back(static_cast<uint64_t>(sqlite3_column_int64(stmt, 0)));
    }

    sqlite3_finalize(stmt);
    return true;
}

bool LocalCache::MarkEventsSynced(const std::vector<uint64_t>& eventIds) {
    std::lock_guard<std::mutex> lock(dbMutex_);

    if (!initialized_ || eventIds.empty()) {
        return true;
    }

    sqlite3* db = reinterpret_cast<sqlite3*>(db_);

    // Transactional acknowledgment: mark exactly the delivered batch as synced.
    if (!BeginTransaction()) {
        return false;
    }

    const char* sql = "UPDATE events SET synced = 1, synced_at = CURRENT_TIMESTAMP WHERE id = ?";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare sync statement: %s", sqlite3_errmsg(db));
        RollbackTransaction();
        return false;
    }

    bool ok = true;
    for (uint64_t id : eventIds) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(id));

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            LOG_ERROR("Failed to mark event %llu synced: %s",
                static_cast<unsigned long long>(id), sqlite3_errmsg(db));
            ok = false;
            break;
        }
    }

    sqlite3_finalize(stmt);

    if (ok) {
        if (!CommitTransaction()) {
            return false;
        }
        LOG_DEBUG("Marked %zu events synced", eventIds.size());
        return true;
    }

    RollbackTransaction();
    return false;
}

size_t LocalCache::SyncEvents(SecureComm* secureComm) {
    if (!initialized_ || !secureComm || !secureComm->IsConnected()) {
        return 0;
    }

    // Resolve the exact batch (IDs + payloads) in one consistent pass.
    std::vector<uint64_t> ids;
    if (!GetPendingEventIds(ids, 100) || ids.empty()) {
        return 0;
    }

    std::vector<Event> events;
    if (!GetPendingEvents(events, static_cast<int>(ids.size())) || events.empty()) {
        return 0;
    }

    if (secureComm->SendEvents(events)) {
        if (MarkEventsSynced(ids)) {
            return events.size();
        }
        LOG_WARNING("Events delivered but local acknowledgment failed; will retry");
        return 0;
    }

    return 0;
}

bool LocalCache::StoreQuarantineRecord(const std::string& originalPath,
                                       const std::string& quarantinePath,
                                       const std::string& classification,
                                       const std::string& userId,
                                       const std::string& reason) {
    std::lock_guard<std::mutex> lock(dbMutex_);

    if (!initialized_) {
        return false;
    }

    const char* sql = "INSERT INTO quarantine (original_path, quarantine_path, classification, user_id, reason, quarantined_at) "
                      "VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db_), sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare quarantine insert: %s", sqlite3_errmsg(reinterpret_cast<sqlite3*>(db_)));
        return false;
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    sqlite3_bind_text(stmt, 1, originalPath.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, quarantinePath.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, classification.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, userId.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to store quarantine record: %s", sqlite3_errmsg(reinterpret_cast<sqlite3*>(db_)));
        return false;
    }

    return true;
}

bool LocalCache::BeginTransaction() {
    return sqlite3_exec(reinterpret_cast<sqlite3*>(db_), "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool LocalCache::CommitTransaction() {
    return sqlite3_exec(reinterpret_cast<sqlite3*>(db_), "COMMIT;", nullptr, nullptr, nullptr) == SQLITE_OK;
}

void LocalCache::RollbackTransaction() {
    sqlite3_exec(reinterpret_cast<sqlite3*>(db_), "ROLLBACK;", nullptr, nullptr, nullptr);
}
