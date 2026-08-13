#pragma once

#include <string>
#include <map>
#include <functional>

/**
 * HTTP client for agent-backend communication.
 *
 * Uses WinHTTP on Windows (strict TLS validation by default), libcurl on
 * Linux. When a CA certificate path is configured the client verifies the
 * server identity against that CA and rejects unknown issuers, expired
 * certificates and hostname mismatches.
 */
class HttpClient {
public:
    struct Response {
        int statusCode;
        std::string body;
        std::map<std::string, std::string> headers;
        bool success;
        std::string error;
    };

    HttpClient();
    ~HttpClient();

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    /**
     * Set the base URL for all requests
     * @param baseUrl Base URL (e.g., "https://dlp.example.com:8443")
     */
    void SetBaseUrl(const std::string& baseUrl);

    /**
     * Set a default header for all requests
     */
    void SetHeader(const std::string& name, const std::string& value);

    /**
     * Set connection timeout in milliseconds
     */
    void SetTimeout(int timeoutMs);

    /**
     * Configure strict server-identity validation against a CA certificate.
     *
     * @param caCertPath Path to the CA certificate (PEM) to trust
     * @return true if the CA was loaded successfully
     */
    bool SetCaCertificatePath(const std::string& caCertPath);

    /**
     * Inject an authorization token header (Authorization: Bearer <token>)
     * on every request.
     */
    void SetAuthToken(const std::string& token);

    /**
     * Perform HTTP GET request
     * @param path Request path (e.g., "/api/health")
     * @return Response structure
     */
    Response Get(const std::string& path);

    /**
     * Perform HTTP POST request with JSON body
     * @param path Request path
     * @param jsonBody JSON body string
     * @return Response structure
     */
    Response Post(const std::string& path, const std::string& jsonBody);

    /**
     * Perform HTTP PUT request with JSON body
     */
    Response Put(const std::string& path, const std::string& jsonBody);

    /**
     * Check if last request was successful
     */
    bool IsLastRequestSuccessful() const { return lastSuccess_; }

private:
    Response PerformRequest(const std::string& method, const std::string& path, const std::string& body);

    std::string baseUrl_;
    std::map<std::string, std::string> defaultHeaders_;
    int timeoutMs_;
    bool lastSuccess_;
    void* hSession_;        // HINTERNET for WinHTTP
    void* caCertStore_;     // HCERTSTORE loaded from ca.crt (validated trust anchor)
};
