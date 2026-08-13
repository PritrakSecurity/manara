#pragma once

#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <mutex>

class HttpClient;

/**
 * Secure communication client for agent-backend communication.
 *
 * All transport is provided by HttpClient (WinHTTP on Windows) with strict
 * TLS validation against the configured CA certificate (ca.crt) and an
 * authorization bearer token injected on every request. There is no raw
 * HTTP/1.1-over-OpenSSL implementation anymore.
 */
class SecureComm {
public:
    SecureComm();
    ~SecureComm();

    SecureComm(const SecureComm&) = delete;
    SecureComm& operator=(const SecureComm&) = delete;

    /**
     * Initialize secure communication
     * @param serverUrl Backend server URL (e.g., "https://backend.example.com:8443")
     * @param certPath Path to the CA certificate file used to validate the server
     * @return true if initialization successful, false otherwise
     */
    bool Initialize(const std::string& serverUrl, const std::string& certPath);

    /**
     * Connect to backend server (validates TLS handshake)
     * @return true if connection successful, false otherwise
     */
    bool Connect();

    /**
     * Disconnect from backend
     */
    void Disconnect();

    /**
     * Check if connected to backend
     * @return true if connected, false otherwise
     */
    bool IsConnected() const { return isConnected_; }

    /**
     * Send events to backend
     * @param events Vector of Event objects
     * @return true if sent successfully, false otherwise
     */
    bool SendEvents(const std::vector<struct Event>& events);

    /**
     * Fetch policy from backend
     * @return Policy JSON string, empty if failed
     */
    std::string FetchPolicy();

    /**
     * Send heartbeat to backend
     * @return true if heartbeat successful, false otherwise
     */
    bool SendHeartbeat();

    /**
     * Set the authorization bearer token injected on every request
     */
    void SetAuthToken(const std::string& token);

    /**
     * Enroll this device with the backend (POST /api/devices/register).
     *
     * Uses a plain-HTTP client so it works against the development backend
     * (http://server:8080) which does not require TLS/CA validation.
     *
     * @param serverUrl    Backend base URL (e.g. "http://192.168.1.10:8080")
     * @param hostname     Device hostname
     * @param osVersion    OS version string
     * @param agentVersion Agent version string
     * @param outToken     Receives the issued device bearer token (JWT)
     * @param outDeviceId  Receives the backend device id
     * @return true if the device was enrolled successfully
     */
    static bool RegisterDevice(const std::string& serverUrl,
                               const std::string& hostname,
                               const std::string& osVersion,
                               const std::string& agentVersion,
                               std::string& outToken,
                               std::string& outDeviceId);

    /**
     * Report a discovered sensitive file to the DSPM inventory
     * (POST /api/v1/dspm/inventory).
     *
     * Uses the persisted backend URL and bearer token from config, so it can be
     * called from anywhere in the agent. Only metadata is sent - never content.
     *
     * @param payloadJson JSON payload with file_path, file_hash, file_size,
     *                    classification, matched_keywords, hostname.
     * @return true if the update was accepted by the backend.
     */
    static bool SendInventoryUpdate(const std::string& payloadJson);

private:
    bool ParseBackendUrl(const std::string& url);
    bool EstablishConnection();

    std::unique_ptr<HttpClient> httpClient_;
    std::atomic<bool> isConnected_;

    std::string serverUrl_;
    std::string serverHost_;
    std::string caCertPath_;

    std::mutex stateMutex_;
};
