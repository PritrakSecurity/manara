#pragma once

#include "../core/EventTypes.h"
#include <string>
#include <vector>

// Forward declaration
class SecureComm;

/**
 * Local Cache for offline operation
 * Stores policies, events and quarantine metadata in SQLite for sync when the
 * backend is available.
 *
 * Event outbox state machine:
 *   StoreEvent()           -> INSERT event with synced = 0
 *   GetPendingEvents()     -> SELECT unsynced events (oldest first)
 *   MarkEventsSynced()     -> transactionally mark acknowledged events synced
 */
class LocalCache {
public:
    LocalCache();
    ~LocalCache();

    /**
     * Initialize cache with database path
     * @param dbPath Path to SQLite database file
     * @return true if initialization successful, false otherwise
     */
    bool Initialize(const std::string& dbPath);

    /**
     * Shutdown and close database
     */
    void Shutdown();

    /**
     * Store policy locally
     * @param policyJson Policy JSON string
     * @return true if stored successfully, false otherwise
     */
    bool StorePolicy(const std::string& policyJson);

    /**
     * Load policy from cache
     * @return Policy JSON string, empty if not found
     */
    std::string LoadPolicy();

    /**
     * Store event for later sync
     * @param event Event to store
     * @return true if stored successfully, false otherwise
     */
    bool StoreEvent(const Event& event);

    /**
     * Get pending (unsynced) events, oldest first.
     *
     * @param events    Output vector that receives the deserialized events
     * @param batchSize Maximum number of events to return
     * @return true if the query succeeded, false otherwise
     */
    bool GetPendingEvents(std::vector<Event>& events, int batchSize);

    /**
     * Get the database IDs of pending (unsynced) events, oldest first.
     * Used to acknowledge exactly the events returned by GetPendingEvents.
     *
     * @param ids       Output vector that receives the event IDs
     * @param batchSize Maximum number of IDs to return
     * @return true if the query succeeded, false otherwise
     */
    bool GetPendingEventIds(std::vector<uint64_t>& ids, int batchSize);

    /**
     * Mark events as synced (transactional UPDATE).
     *
     * @param eventIds IDs of events to mark as acknowledged
     * @return true if all updates succeeded, false otherwise
     */
    bool MarkEventsSynced(const std::vector<uint64_t>& eventIds);

    /**
     * Sync events to backend
     * @param secureComm Secure communication client
     * @return Number of events synced
     */
    size_t SyncEvents(SecureComm* secureComm);

    /**
     * Record a quarantine action's metadata.
     *
     * @param originalPath   Original location of the quarantined file
     * @param quarantinePath New location inside the quarantine store
     * @param classification Classification at time of quarantine
     * @param userId         User associated with the incident
     * @param reason         Policy/reason that triggered quarantine
     * @return true if the record was persisted, false otherwise
     */
    bool StoreQuarantineRecord(const std::string& originalPath,
                               const std::string& quarantinePath,
                               const std::string& classification,
                               const std::string& userId,
                               const std::string& reason);

private:
    void* db_; // SQLite database handle (void* to avoid including sqlite3.h in header)
    std::string dbPath_;
    bool initialized_;

    bool CreateTables();
    bool BeginTransaction();
    bool CommitTransaction();
    void RollbackTransaction();
};
