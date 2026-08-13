#pragma once

#include <windows.h>
#include <string>
#include <map>

namespace dlp {
namespace config {

class ConfigManager {
public:
    static ConfigManager& GetInstance();
    
    bool LoadFromFile(const std::wstring& configPath);
    bool LoadFromRegistry(const std::wstring& keyPath);
    void SaveToFile(const std::wstring& configPath);
    
    std::wstring GetString(const std::wstring& key, const std::wstring& defaultValue = L"");
    int GetInt(const std::wstring& key, int defaultValue = 0);
    bool GetBool(const std::wstring& key, bool defaultValue = false);
    
    void SetString(const std::wstring& key, const std::wstring& value);
    void SetInt(const std::wstring& key, int value);
    void SetBool(const std::wstring& key, bool value);

private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    std::map<std::wstring, std::wstring> configMap;
};

} // namespace config
} // namespace dlp
