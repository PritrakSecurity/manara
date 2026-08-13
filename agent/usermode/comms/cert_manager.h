#pragma once

#include <windows.h>
#include <string>
#include <vector>

/**
 * CertManager - Manages client certificates for mTLS communication
 */
class CertManager {
public:
    CertManager();
    ~CertManager();

    /**
     * Load client certificate from file
     * @param certPath Path to certificate file (PEM format)
     * @param keyPath Path to private key file (PEM format)
     * @return true if load successful, false otherwise
     */
    bool LoadClientCertificate(
        const std::wstring& certPath,
        const std::wstring& keyPath
    );

    /**
     * Load certificate from Windows certificate store
     * @param storeName Certificate store name (e.g., "MY")
     * @param subjectName Certificate subject name
     * @return true if load successful, false otherwise
     */
    bool LoadCertificateFromStore(
        const std::wstring& storeName,
        const std::wstring& subjectName
    );

    /**
     * Get certificate data (PEM format)
     * @return Certificate data as string
     */
    std::string GetCertificateData() const;

    /**
     * Get private key data (PEM format)
     * @return Private key data as string
     */
    std::string GetPrivateKeyData() const;

    /**
     * Check if certificate is valid and not expired
     * @return true if valid, false otherwise
     */
    bool IsCertificateValid() const;

    /**
     * Get certificate expiration date
     * @return Expiration timestamp
     */
    time_t GetCertificateExpiration() const;

    /**
     * Get certificate subject name (CN)
     * @return Subject name
     */
    std::wstring GetCertificateSubject() const;

private:
    std::string certData;
    std::string keyData;
    std::wstring subjectName;
    time_t expirationTime;
    bool isValid;
};
