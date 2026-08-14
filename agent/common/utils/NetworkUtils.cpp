#include "NetworkUtils.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

std::string NetworkUtils::GetPrimaryIPv4Address() {
    ULONG bufLen = 15000;
    std::vector<BYTE> buffer(bufLen);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    DWORD ret = GetAdaptersAddresses(AF_INET,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
        nullptr, addresses, &bufLen);

    // Handle buffer too small
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufLen);
        addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        ret = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr, addresses, &bufLen);
    }

    if (ret != NO_ERROR) {
        return "127.0.0.1";
    }

    // Preferred adapter types in order: Ethernet, Wi-Fi, then others
    const std::vector<IFTYPE> preferredTypes = {
        IF_TYPE_ETHERNET_CSMACD,   // 6
        IF_TYPE_IEEE80211,          // 71
        IF_TYPE_IEEE1394,           // 144 (FireWire, rare)
    };

    std::string bestCandidate;
    int bestScore = -1;

    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter; adapter = adapter->Next) {
        // Skip down adapters
        if (adapter->OperStatus != IfOperStatusUp) continue;

        // Skip loopback
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        // Skip tunnels (VPN, Teredo, etc.)
        if (adapter->IfType == IF_TYPE_TUNNEL) continue;

        // Skip virtual/proprietary virtual
        if (adapter->IfType == IF_TYPE_PROP_VIRTUAL) continue;

        // Skip adapters with no unicast address
        if (!adapter->FirstUnicastAddress) continue;

        // Skip IPv6-only adapters (we asked for AF_INET, but be safe)
        if (adapter->FirstUnicastAddress->Address.lpSockaddr->sa_family != AF_INET) continue;

        sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(adapter->FirstUnicastAddress->Address.lpSockaddr);
        char ipStr[INET_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr))) continue;

        std::string ip(ipStr);

        // Skip APIPA (link-local) addresses: 169.254.x.x
        if (ip.rfind("169.254.", 0) == 0) continue;

        // Skip loopback range 127.x.x.x
        if (ip.rfind("127.", 0) == 0) continue;

        // Score this adapter
        int score = 0;

        // Prefer physical types
        for (size_t i = 0; i < preferredTypes.size(); ++i) {
            if (adapter->IfType == preferredTypes[i]) {
                score += static_cast<int>((preferredTypes.size() - i) * 10);
                break;
            }
        }

        // Bonus if it has a default gateway (means it routes to internet/LAN)
        if (adapter->FirstGatewayAddress != nullptr) {
            score += 5;
        }

        // Bonus for DHCP-enabled (typical for real NICs, not static virtuals)
        if (adapter->Dhcpv4Enabled) {
            score += 2;
        }

        // Prefer non-virtual friendly names
        std::wstring friendlyName(adapter->FriendlyName ? adapter->FriendlyName : L"");
        std::string friendlyNameStr(friendlyName.begin(), friendlyName.end());
        std::string lowerName = friendlyNameStr;
        for (auto& c : lowerName) c = static_cast<char>(tolower(c));

        if (lowerName.find("virtual") != std::string::npos ||
            lowerName.find("vmware") != std::string::npos ||
            lowerName.find("hyper-v") != std::string::npos ||
            lowerName.find("docker") != std::string::npos ||
            lowerName.find("wsl") != std::string::npos ||
            lowerName.find("tap") != std::string::npos ||
            lowerName.find("tun") != std::string::npos) {
            score -= 50;  // Heavy penalty for virtual adapters
        }

        if (score > bestScore) {
            bestScore = score;
            bestCandidate = ip;
        }
    }

    return bestCandidate.empty() ? "127.0.0.1" : bestCandidate;
}
