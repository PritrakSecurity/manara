#include "cert_manager.h"
#include <fstream>
#include <sstream>
#include <wincrypt.h>
#include <windows.h>

#pragma comment(lib, "crypt32.lib")

CertManager::CertManager()
    : expirationTime(0)
    , isValid(false)
{
}

CertManager::~CertManager()
{
    // Clear sensitive data from memory
    if (!certData.empty()) {
        SecureZeroMemory(&certData[0], certData.size());
    }
    if (!keyData.empty()) {
        SecureZeroMemory(&keyData[0], keyData.size());
    }
}

bool CertManager::LoadClientCertificate(
    const std::wstring& certPath,
    const std::wstring& keyPath
)
{
    // Read certificate file
    std::ifstream certFile(certPath, std::ios::binary);
    if (!certFile.is_open()) {
        return false;
    }

    std::stringstream certStream;
    certStream << certFile.rdbuf();
    certData = certStream.str();
    certFile.close();

    // Read private key file
    std::ifstream keyFile(keyPath, std::ios::binary);
    if (!keyFile.is_open()) {
        certData.clear();
        return false;
    }

    std::stringstream keyStream;
    keyStream << keyFile.rdbuf();
    keyData = keyStream.str();
    keyFile.close();

    // TODO: Parse certificate and validate
    // This should:
    // 1. Parse PEM certificate
    // 2. Extract subject name (CN)
    // 3. Check expiration date
    // 4. Validate certificate chain

    isValid = true;
    return true;
}

bool CertManager::LoadCertificateFromStore(
    const std::wstring& storeName,
    const std::wstring& subjectName
)
{
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    bool success = false;

    // Open certificate store
    hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        storeName.c_str()
    );

    if (hStore == NULL) {
        return false;
    }

    // Find certificate by subject name
    pCertContext = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        subjectName.c_str(),
        NULL
    );

    if (pCertContext != NULL) {
        // TODO: Extract certificate data
        // TODO: Extract private key (requires CryptoAPI)
        // TODO: Validate certificate
        
        this->subjectName = subjectName;
        isValid = true;
        success = true;
    }

    if (pCertContext != NULL) {
        CertFreeCertificateContext(pCertContext);
    }

    CertCloseStore(hStore, 0);
    return success;
}

std::string CertManager::GetCertificateData() const
{
    return certData;
}

std::string CertManager::GetPrivateKeyData() const
{
    return keyData;
}

bool CertManager::IsCertificateValid() const
{
    if (!isValid) {
        return false;
    }

    // TODO: Check expiration
    time_t currentTime = time(NULL);
    if (expirationTime > 0 && currentTime >= expirationTime) {
        return false;
    }

    return true;
}

time_t CertManager::GetCertificateExpiration() const
{
    return expirationTime;
}

std::wstring CertManager::GetCertificateSubject() const
{
    return subjectName;
}
