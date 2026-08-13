#include "HttpClient.h"
#include "../../common/utils/logging.h"

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#else
#include <curl/curl.h>
#endif

#include <sstream>
#include <algorithm>

#ifdef _WIN32

namespace {

// RAII guard for WinHTTP handles so every exit path releases resources.
class WinHttpHandle {
public:
    explicit WinHttpHandle(HINTERNET handle = nullptr) : handle_(handle) {}
    ~WinHttpHandle() {
        Reset();
    }
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    HINTERNET get() const { return handle_; }

    void Reset(HINTERNET handle = nullptr) {
        if (handle_) {
            WinHttpCloseHandle(handle_);
        }
        handle_ = handle;
    }

    HINTERNET* operator&() { return &handle_; }

private:
    HINTERNET handle_;
};

std::wstring ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], size);
    return result;
}

bool ParseUrl(const std::string& url, std::wstring& host, int& port, std::wstring& path, bool& isHttps) {
    std::string work = url;
    isHttps = false;

    if (work.substr(0, 8) == "https://") {
        isHttps = true;
        work = work.substr(8);
        port = 443;
    } else if (work.substr(0, 7) == "http://") {
        work = work.substr(7);
        port = 80;
    } else {
        return false;
    }

    size_t pathStart = work.find('/');
    std::string hostPart;
    if (pathStart != std::string::npos) {
        hostPart = work.substr(0, pathStart);
        path = ToWide(work.substr(pathStart));
    } else {
        hostPart = work;
        path = L"/";
    }

    size_t colonPos = hostPart.find(':');
    if (colonPos != std::string::npos) {
        host = ToWide(hostPart.substr(0, colonPos));
        port = std::stoi(hostPart.substr(colonPos + 1));
    } else {
        host = ToWide(hostPart);
    }

    return true;
}

} // namespace

#endif // _WIN32

HttpClient::HttpClient()
    : timeoutMs_(30000)
    , lastSuccess_(false)
    , hSession_(nullptr)
    , caCertStore_(nullptr)
{
    defaultHeaders_["Content-Type"] = "application/json";
    defaultHeaders_["Accept"] = "application/json";
    defaultHeaders_["User-Agent"] = "PritrakDLP-Agent/1.0";

#ifdef _WIN32
    // Initialize WinHTTP session
    hSession_ = WinHttpOpen(
        L"PritrakDLP-Agent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
#endif
}

HttpClient::~HttpClient() {
#ifdef _WIN32
    if (caCertStore_) {
        CertCloseStore(static_cast<HCERTSTORE>(caCertStore_), 0);
        caCertStore_ = nullptr;
    }
    if (hSession_) {
        WinHttpCloseHandle((HINTERNET)hSession_);
        hSession_ = nullptr;
    }
#endif
}

void HttpClient::SetBaseUrl(const std::string& baseUrl) {
    baseUrl_ = baseUrl;
    while (!baseUrl_.empty() && baseUrl_.back() == '/') {
        baseUrl_.pop_back();
    }
}

void HttpClient::SetHeader(const std::string& name, const std::string& value) {
    defaultHeaders_[name] = value;
}

void HttpClient::SetTimeout(int timeoutMs) {
    timeoutMs_ = timeoutMs;
}

bool HttpClient::SetCaCertificatePath(const std::string& caCertPath) {
#ifdef _WIN32
    if (caCertPath.empty()) {
        return false;
    }

    // Open an in-memory store and add the CA certificate (PEM).
    HCERTSTORE store = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        0,
        0,
        0,
        nullptr
    );
    if (!store) {
        return false;
    }

    HANDLE file = CreateFileA(caCertPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        CertCloseStore(store, 0);
        return false;
    }

    DWORD fileSize = GetFileSize(file, nullptr);
    std::string pem;
    if (fileSize > 0) {
        pem.resize(fileSize);
        DWORD bytesRead = 0;
        if (ReadFile(file, &pem[0], fileSize, &bytesRead, nullptr)) {
            pem.resize(bytesRead);
        } else {
            pem.clear();
        }
    }
    CloseHandle(file);

    if (pem.empty() ||
        !CertAddEncodedCertificateToStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            reinterpret_cast<const BYTE*>(pem.c_str()),
            static_cast<DWORD>(pem.size()),
            CERT_STORE_ADD_REPLACE_EXISTING,
            nullptr)) {
        CertCloseStore(store, 0);
        return false;
    }

    caCertStore_ = store;
    return true;
#else
    (void)caCertPath;
    return false;
#endif
}

void HttpClient::SetAuthToken(const std::string& token) {
    if (token.empty()) {
        defaultHeaders_.erase("Authorization");
    } else {
        defaultHeaders_["Authorization"] = "Bearer " + token;
    }
}

HttpClient::Response HttpClient::Get(const std::string& path) {
    return PerformRequest("GET", path, "");
}

HttpClient::Response HttpClient::Post(const std::string& path, const std::string& jsonBody) {
    return PerformRequest("POST", path, jsonBody);
}

HttpClient::Response HttpClient::Put(const std::string& path, const std::string& jsonBody) {
    return PerformRequest("PUT", path, jsonBody);
}

#ifdef _WIN32

HttpClient::Response HttpClient::PerformRequest(const std::string& method, const std::string& path, const std::string& body) {
    Response response;
    response.statusCode = 0;
    response.success = false;

    if (!hSession_) {
        response.error = "HTTP session not initialized";
        LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
        return response;
    }

    std::string fullUrl = baseUrl_ + path;
    LOG_INFO("Sending HTTP request to: %s", fullUrl.c_str());
    std::wstring host;
    int port;
    std::wstring urlPath;
    bool isHttps = false;

    if (!ParseUrl(fullUrl, host, port, urlPath, isHttps)) {
        response.error = "Invalid URL: " + fullUrl;
        LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
        return response;
    }

    WinHttpHandle hConnect(WinHttpConnect(
        (HINTERNET)hSession_,
        host.c_str(),
        (INTERNET_PORT)port,
        0
    ));

    if (!hConnect.get()) {
        response.error = "Failed to connect to " + std::string(host.begin(), host.end());
        LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
        return response;
    }

    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    std::wstring wMethod = ToWide(method);

    WinHttpHandle hRequest(WinHttpOpenRequest(
        hConnect.get(),
        wMethod.c_str(),
        urlPath.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    ));

    if (!hRequest.get()) {
        response.error = "Failed to create request";
        LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
        return response;
    }

    WinHttpSetTimeouts(hRequest.get(), timeoutMs_, timeoutMs_, timeoutMs_, timeoutMs_);

    if (isHttps) {
        // Strict TLS: do NOT ignore unknown CAs, certificate dates or
        // hostname mismatches. A value of 0 disables all bypass flags.
        DWORD secFlags = 0;
        WinHttpSetOption(hRequest.get(), WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

        // When a private CA is configured, validate strictly against that CA
        // store rather than the machine trust store.
#if defined(WINHTTP_OPTION_ROOT_CERT_STORE)
        if (caCertStore_) {
            WinHttpSetOption(
                hRequest.get(),
                WINHTTP_OPTION_ROOT_CERT_STORE,
                &caCertStore_,
                sizeof(caCertStore_)
            );
        }
#endif
    }

    // Add default headers (including the Authorization bearer token).
    std::wstring headerString;
    for (const auto& h : defaultHeaders_) {
        headerString += ToWide(h.first + ": " + h.second + "\r\n");
    }
    if (!headerString.empty()) {
        WinHttpAddRequestHeaders(hRequest.get(), headerString.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL result = WinHttpSendRequest(
        hRequest.get(),
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.c_str(),
        body.empty() ? 0 : (DWORD)body.size(),
        body.empty() ? 0 : (DWORD)body.size(),
        0
    );

    if (!result) {
        DWORD err = GetLastError();
        if (isHttps && err == ERROR_WINHTTP_SECURE_FAILURE) {
            response.error = "TLS handshake failed: server certificate could not be validated (secure failure)";
        } else {
            response.error = "Failed to send request, error: " + std::to_string(err);
        }
        LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
        return response;
    }

    result = WinHttpReceiveResponse(hRequest.get(), nullptr);
    if (!result) {
        DWORD err = GetLastError();
        if (isHttps && err == ERROR_WINHTTP_SECURE_FAILURE) {
            response.error = "TLS handshake failed: server certificate could not be validated (secure failure)";
        } else {
            response.error = "Failed to receive response, error: " + std::to_string(err);
        }
        LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
        return response;
    }

    // Post-handshake server identity verification against the pinned CA.
#if defined(WINHTTP_OPTION_ROOT_CERT_STORE)
    if (isHttps && caCertStore_) {
        CERT_CONTEXT* serverCert = nullptr;
        DWORD certSize = sizeof(CERT_CONTEXT*);
        if (WinHttpQueryOption(hRequest.get(), WINHTTP_OPTION_SERVER_CERT_CONTEXT, &serverCert, &certSize) &&
            serverCert) {
            // Build and validate the chain against our CA store.
            CERT_CHAIN_PARA chainPara = {};
            chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
            CERT_CHAIN_ENGINE_CONFIG engineConfig = {};
            engineConfig.cbSize = sizeof(CERT_CHAIN_ENGINE_CONFIG);
            engineConfig.hExclusiveRoot = static_cast<HCERTSTORE>(caCertStore_);

            HCERTCHAINENGINE engine = nullptr;
            if (!CertCreateCertificateChainEngine(&engineConfig, &engine)) {
                CertFreeCertificateContext(serverCert);
                response.error = "TLS validation failed: could not create chain engine";
                LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
                return response;
            }

            PCCERT_CHAIN_CONTEXT chainContext = nullptr;
            if (!CertGetCertificateChain(
                    engine,
                    serverCert,
                    nullptr,
                    static_cast<HCERTSTORE>(caCertStore_),
                    &chainPara,
                    0,
                    nullptr,
                    &chainContext)) {
                CertFreeCertificateChainEngine(engine);
                CertFreeCertificateContext(serverCert);
                response.error = "TLS validation failed: could not build certificate chain";
                LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
                return response;
            }

            DWORD trustStatus = 0;
            if (chainContext->cChain > 0) {
                trustStatus = chainContext->rgpChain[0]->TrustStatus.dwErrorStatus;
            }

            bool valid = (trustStatus == 0);
            CertFreeCertificateChain(chainContext);
            CertFreeCertificateChainEngine(engine);
            CertFreeCertificateContext(serverCert);

            if (!valid) {
                response.error = "TLS validation failed: certificate not trusted by configured CA";
                LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
                return response;
            }
        } else {
            response.error = "TLS validation failed: server did not present a certificate";
            LOG_ERROR("HTTP Request failed: %s", response.error.c_str());
            return response;
        }
    }
#endif

    // Get status code
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(
        hRequest.get(),
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &size,
        WINHTTP_NO_HEADER_INDEX
    );
    response.statusCode = statusCode;

    // Read response body
    std::stringstream responseBody;
    DWORD bytesAvailable = 0;
    do {
        bytesAvailable = 0;
        WinHttpQueryDataAvailable(hRequest.get(), &bytesAvailable);

        if (bytesAvailable > 0) {
            std::string chunk(bytesAvailable, '\0');
            DWORD bytesRead = 0;
            if (WinHttpReadData(hRequest.get(), &chunk[0], bytesAvailable, &bytesRead)) {
                chunk.resize(bytesRead);
                responseBody << chunk;
            }
        }
    } while (bytesAvailable > 0);

    response.body = responseBody.str();
    response.success = (statusCode >= 200 && statusCode < 300);
    lastSuccess_ = response.success;

    LOG_INFO("HTTP response status: %d", statusCode);
    LOG_INFO("HTTP Response Body: %s", response.body.c_str());

    return response;
}

#else
// Linux implementation using libcurl (placeholder)
HttpClient::Response HttpClient::PerformRequest(const std::string& method, const std::string& path, const std::string& body) {
    Response response;
    response.statusCode = 0;
    response.success = false;
    response.error = "libcurl implementation not yet available";
    return response;
}
#endif
