#include "DLPAgent.h"
#include "../../common/utils/logging.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>

// Hardcoded crash logger - writes the exception to a file using only the
// standard library so it works even when the main logger is not initialized.
void WriteCrashLog(const std::string& message) {
    std::ofstream crashFile("C:\\ProgramData\\PritrakDLP\\logs\\crash.log", std::ios::app);
    if (crashFile.is_open()) {
        crashFile << "[" << __TIMESTAMP__ << "] " << message << std::endl;
        crashFile.close();
    }
}

// Service control handler
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
DLPAgent* g_agent = nullptr;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD ctrlCode);
void RunAsService();
void RunAsConsole();

int main(int argc, char* argv[]) {
    // Parse command line arguments
    bool installService = false;
    bool uninstallService = false;
    bool consoleMode = false;
    bool testMode = false;
    std::string configPath = "C:\\ProgramData\\PritrakDLP\\config.json";

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--install-service") {
            installService = true;
        } else if (arg == "--uninstall-service") {
            uninstallService = true;
        } else if (arg == "--console") {
            consoleMode = true;
        } else if (arg == "--test") {
            testMode = true;
        } else if (arg == "--config" && i + 1 < argc) {
            configPath = argv[++i];
        }
    }

    // Initialize logging to C:\ProgramData\PritrakDLP\logs\agent.log.
    // The logs directory may not exist yet (e.g. first install), so create it.
    CreateDirectoryW(L"C:\\ProgramData\\PritrakDLP", NULL);
    CreateDirectoryW(L"C:\\ProgramData\\PritrakDLP\\logs", NULL);
    dlp::utils::Logger::GetInstance().Initialize(L"C:\\ProgramData\\PritrakDLP\\logs\\agent.log");
    LOG_INFO("Pritrak DLP Agent starting. Mode: MONITOR_ONLY");

    // Service management
    if (installService) {
        if (DLPAgent::InstallService()) {
            std::cout << "Service installed successfully" << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to install service" << std::endl;
            return 1;
        }
    }

    if (uninstallService) {
        if (DLPAgent::UninstallService()) {
            std::cout << "Service uninstalled successfully" << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to uninstall service" << std::endl;
            return 1;
        }
    }

    // Run as service or console
    if (DLPAgent::IsServiceInstalled() && !consoleMode) {
        RunAsService();
    } else {
        RunAsConsole();
    }

    return 0;
}

void RunAsService() {
    SERVICE_TABLE_ENTRY serviceTable[] = {
        { (LPWSTR)L"PritrakDLP", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(serviceTable)) {
        LOG_ERROR("Failed to start service control dispatcher");
    }
}

void RunAsConsole() {
    std::cout << "Pritrak DLP Agent - Console Mode" << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;

    DLPAgent agent;
    if (!agent.Initialize("C:\\ProgramData\\PritrakDLP\\config.json")) {
        std::cerr << "Failed to initialize agent" << std::endl;
        return;
    }

    if (!agent.Start()) {
        std::cerr << "Failed to start agent" << std::endl;
        return;
    }

    // Wait for Ctrl+C
    SetConsoleCtrlHandler([](DWORD ctrlType) -> BOOL {
        if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
            if (g_agent) {
                g_agent->Stop();
            }
            return TRUE;
        }
        return FALSE;
    }, TRUE);

    g_agent = &agent;

    // Keep running
    while (agent.IsRunning()) {
        Sleep(1000);
    }

    agent.Shutdown();
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    WriteCrashLog("ServiceMain entered.");

    serviceStatusHandle = RegisterServiceCtrlHandler(L"PritrakDLP", ServiceCtrlHandler);
    if (!serviceStatusHandle) {
        WriteCrashLog("Failed to register service ctrl handler.");
        return;
    }

    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    serviceStatus.dwWin32ExitCode = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    try {
        WriteCrashLog("Initializing DLPAgent...");
        DLPAgent agent;
        g_agent = &agent;

        if (!agent.Initialize("C:\\ProgramData\\PritrakDLP\\config.json")) {
            throw std::runtime_error("agent.Initialize() returned false.");
        }

        WriteCrashLog("Agent initialized. Setting service to RUNNING.");
        serviceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        WriteCrashLog("Starting agent...");
        if (!agent.Start()) {
            throw std::runtime_error("agent.Start() returned false.");
        }

        WriteCrashLog("Agent started successfully. Entering wait loop.");
        while (agent.IsRunning()) {
            Sleep(1000);
        }

        WriteCrashLog("Agent stopped. Shutting down.");
        agent.Shutdown();

    } catch (const std::exception& e) {
        WriteCrashLog(std::string("CRASH (std::exception): ") + e.what());
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        serviceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    } catch (...) {
        WriteCrashLog("CRASH (Unknown exception)");
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        serviceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }

    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(serviceStatusHandle, &serviceStatus);
            if (g_agent) {
                g_agent->Stop();
            }
            break;
        default:
            break;
    }
}
