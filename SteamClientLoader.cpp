#include <windows.h>
#include <mmsystem.h>
#include <string>
#include <fstream>
#include <mutex>
#include <algorithm>

HMODULE g_original_dll = nullptr;
std::mutex g_load_mutex{};
static bool g_initialized = false;
static bool g_steam_loaded = false;
static bool g_registry_restored = false;
static bool g_is_version_dll = false;

struct RegBackup {
    bool valid = false;
    WCHAR data[1024] = { 0 };
    DWORD size = sizeof(data);
    DWORD dword_val = 0;
} reg_hkcu, reg_hkcu_path;

constexpr static const wchar_t STEAM_UNIVERSE[] = L"Public";
const static DWORD UserId = 0x03100004;

std::string get_exe_dir() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    std::string path = buffer;
    size_t pos = path.find_last_of("\\/");
    return (pos != std::string::npos) ? path.substr(0, pos + 1) : "";
}

std::wstring to_wide(const std::string& str) {
    if (str.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}

std::string get_dll_dir() {
    HMODULE hModule = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&get_dll_dir, &hModule)) {
        char buffer[MAX_PATH];
        GetModuleFileNameA(hModule, buffer, MAX_PATH);
        std::string path = buffer;
        size_t pos = path.find_last_of("\\/");
        return (pos != std::string::npos) ? path.substr(0, pos + 1) : "";
    }
    return "";
}

std::string read_app_id() {
    std::ifstream file(get_dll_dir() + "steam_settings\\steam_appid.txt");
    std::string appid;
    if (file.is_open()) {
        std::getline(file, appid);
        appid.erase(0, appid.find_first_not_of(" \t\r\n"));
        appid.erase(appid.find_last_not_of(" \t\r\n") + 1);
    }
    return appid;
}

bool patch_steam_registry(const std::string& client64_path, const std::string& app_id) {
    auto exe_path_w = to_wide(get_exe_dir());
    if (!exe_path_w.empty() && exe_path_w.back() == L'\\') exe_path_w.pop_back();

    auto client64_path_w = to_wide(client64_path);
    DWORD pid = GetCurrentProcessId();

    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam\\ActiveProcess", 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS) {
        reg_hkcu.valid = true;
        DWORD type = REG_SZ;
        RegQueryValueExW(key, L"SteamClientDll64", 0, &type, (LPBYTE)reg_hkcu.data, &reg_hkcu.size);
        DWORD size = sizeof(DWORD);
        RegQueryValueExW(key, L"ActiveUser", 0, &type, (LPBYTE)&reg_hkcu.dword_val, &size);
        RegCloseKey(key);
    }

    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam\\ActiveProcess", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &key, nullptr) != ERROR_SUCCESS) return false;

    auto reg_set = [&](const wchar_t* name, DWORD type, const void* data, DWORD size) {
        return RegSetValueExW(key, name, 0, type, (const BYTE*)data, size) == ERROR_SUCCESS;
        };

    bool success = reg_set(L"pid", REG_DWORD, &pid, sizeof(DWORD)) &&
        reg_set(L"SteamClientDll64", REG_SZ, client64_path_w.c_str(), (DWORD)((client64_path_w.size() + 1) * sizeof(wchar_t))) &&
        reg_set(L"ActiveUser", REG_DWORD, &UserId, sizeof(DWORD)) &&
        reg_set(L"Universe", REG_SZ, STEAM_UNIVERSE, sizeof(STEAM_UNIVERSE));

    RegCloseKey(key);
    if (!success) return false;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS) {
        reg_hkcu_path.valid = true;
        DWORD type = REG_SZ;
        RegQueryValueExW(key, L"SteamPath", 0, &type, (LPBYTE)reg_hkcu_path.data, &reg_hkcu_path.size);
        RegCloseKey(key);
    }

    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &key, nullptr) != ERROR_SUCCESS) return false;

    if (!app_id.empty()) {
        try {
            DWORD appid_dword = std::stoul(app_id);
            RegSetValueExW(key, L"RunningAppID", 0, REG_DWORD, (const BYTE*)&appid_dword, sizeof(DWORD));
        }
        catch (...) {}
    }

    RegSetValueExW(key, L"SteamPath", 0, REG_SZ, (const BYTE*)exe_path_w.c_str(),
        (DWORD)((exe_path_w.size() + 1) * sizeof(wchar_t)));

    RegCloseKey(key);
    return true;
}

void cleanup_registry() {
    if (g_registry_restored) return;

    auto restore = [](HKEY root, const wchar_t* path, const wchar_t* value_name, const RegBackup& backup, bool is_dword = false) {
        if (!backup.valid) return;
        HKEY key;
        if (RegOpenKeyExW(root, path, 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS) {
            if (backup.size > 0 || is_dword) {
                RegSetValueExW(key, value_name, 0, is_dword ? REG_DWORD : REG_SZ,
                    is_dword ? (LPBYTE)&backup.dword_val : (LPBYTE)backup.data,
                    is_dword ? sizeof(DWORD) : backup.size);
            }
            else {
                RegDeleteValueW(key, value_name);
            }
            RegCloseKey(key);
        }
        };

    restore(HKEY_CURRENT_USER, L"Software\\Valve\\Steam\\ActiveProcess", L"SteamClientDll64", reg_hkcu);
    restore(HKEY_CURRENT_USER, L"Software\\Valve\\Steam\\ActiveProcess", L"ActiveUser", reg_hkcu, true);
    restore(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath", reg_hkcu_path);

    g_registry_restored = true;
}

void perform_steam_injection() {
    if (g_steam_loaded) return;

    std::string app_id = read_app_id();
    if (app_id.empty()) return;

    std::string client64_path = get_exe_dir() + "steamclient64.dll";
    if (GetFileAttributesA(client64_path.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    if (GetModuleHandleA("steamclient64.dll")) {
        g_steam_loaded = true;
        return;
    }

    const char* env_vars[][2] = {
        {"SteamAppId", app_id.c_str()}, {"SteamGameId", app_id.c_str()},
        {"SteamClientLaunch", "1"}, {"SteamEnv", "1"}
    };
    for (auto& [name, value] : env_vars) SetEnvironmentVariableA(name, value);

    if (!patch_steam_registry(client64_path, app_id)) return;

    HMODULE steam_client = LoadLibraryA(client64_path.c_str());
    if (steam_client) {
        g_steam_loaded = true;

        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            Sleep(7000);
            cleanup_registry();
            return 0;
            }, nullptr, 0, nullptr);
    }
}

// Detect which DLL it's supposed to be based on filename
bool detect_dll_type() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(GetModuleHandle(nullptr), buffer, MAX_PATH);
    std::string path = buffer;

    HMODULE hModule = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&detect_dll_type, &hModule)) {
        GetModuleFileNameA(hModule, buffer, MAX_PATH);
        std::string dll_path = buffer;

        size_t pos = dll_path.find_last_of("\\/");
        if (pos != std::string::npos) {
            std::string filename = dll_path.substr(pos + 1);
            std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
            return filename == "version.dll";
        }
    }
    return false;
}

bool load_original_dll() {
    std::lock_guard<std::mutex> lock(g_load_mutex);
    if (g_original_dll) return true;

    wchar_t buffer[MAX_PATH];
    if (GetSystemDirectoryW(buffer, MAX_PATH) == 0) return false;

    std::wstring path = std::wstring(buffer) + (g_is_version_dll ? L"\\version.dll" : L"\\winmm.dll");
    g_original_dll = LoadLibraryW(path.c_str());
    return g_original_dll != nullptr;
}

template<typename T>
T get_proc(const char* name) {
    return g_original_dll ? reinterpret_cast<T>(GetProcAddress(g_original_dll, name)) : nullptr;
}

#define PROXY_FUNC(func, ret, params, args) \
    extern "C" __declspec(dllexport) ret WINAPI func params { \
        load_original_dll(); \
        auto f = get_proc<ret(WINAPI*)params>(#func); \
        return f ? f args : (ret)0; \
    }

// Version.dll functions
PROXY_FUNC(GetFileVersionInfoA, BOOL, (LPCSTR a, DWORD b, DWORD c, LPVOID d), (a, b, c, d))
PROXY_FUNC(GetFileVersionInfoW, BOOL, (LPCWSTR a, DWORD b, DWORD c, LPVOID d), (a, b, c, d))
PROXY_FUNC(GetFileVersionInfoSizeA, DWORD, (LPCSTR a, LPDWORD b), (a, b))
PROXY_FUNC(GetFileVersionInfoSizeW, DWORD, (LPCWSTR a, LPDWORD b), (a, b))
PROXY_FUNC(VerQueryValueA, BOOL, (LPCVOID a, LPCSTR b, LPVOID* c, PUINT d), (a, b, c, d))
PROXY_FUNC(VerQueryValueW, BOOL, (LPCVOID a, LPCWSTR b, LPVOID* c, PUINT d), (a, b, c, d))
PROXY_FUNC(GetFileVersionInfoExW, BOOL, (DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e), (a, b, c, d, e))
PROXY_FUNC(GetFileVersionInfoSizeExW, DWORD, (DWORD a, LPCWSTR b, LPDWORD c), (a, b, c))

// Winmm.dll functions
PROXY_FUNC(timeBeginPeriod, MMRESULT, (UINT uPeriod), (uPeriod))
PROXY_FUNC(timeEndPeriod, MMRESULT, (UINT uPeriod), (uPeriod))
PROXY_FUNC(timeGetTime, DWORD, (void), ())
PROXY_FUNC(timeGetDevCaps, MMRESULT, (LPTIMECAPS ptc, UINT cbtc), (ptc, cbtc))
PROXY_FUNC(timeGetSystemTime, MMRESULT, (LPMMTIME pmmt, UINT cbmmt), (pmmt, cbmmt))
PROXY_FUNC(timeSetEvent, MMRESULT, (UINT uDelay, UINT uResolution, LPTIMECALLBACK fptc, DWORD_PTR dwUser, UINT fuEvent), (uDelay, uResolution, fptc, dwUser, fuEvent))
PROXY_FUNC(timeKillEvent, MMRESULT, (UINT uTimerID), (uTimerID))

PROXY_FUNC(PlaySoundA, BOOL, (LPCSTR pszSound, HMODULE hmod, DWORD fdwSound), (pszSound, hmod, fdwSound))
PROXY_FUNC(PlaySoundW, BOOL, (LPCWSTR pszSound, HMODULE hmod, DWORD fdwSound), (pszSound, hmod, fdwSound))
PROXY_FUNC(sndPlaySoundA, BOOL, (LPCSTR pszSound, UINT fuSound), (pszSound, fuSound))
PROXY_FUNC(sndPlaySoundW, BOOL, (LPCWSTR pszSound, UINT fuSound), (pszSound, fuSound))

PROXY_FUNC(mciSendStringA, MCIERROR, (LPCSTR lpstrCommand, LPSTR lpstrReturnString, UINT uReturnLength, HWND hwndCallback), (lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback))
PROXY_FUNC(mciSendStringW, MCIERROR, (LPCWSTR lpstrCommand, LPWSTR lpstrReturnString, UINT uReturnLength, HWND hwndCallback), (lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback))
PROXY_FUNC(mciSendCommandA, MCIERROR, (MCIDEVICEID IDDevice, UINT uMsg, DWORD_PTR fdwCommand, DWORD_PTR dwParam), (IDDevice, uMsg, fdwCommand, dwParam))
PROXY_FUNC(mciSendCommandW, MCIERROR, (MCIDEVICEID IDDevice, UINT uMsg, DWORD_PTR fdwCommand, DWORD_PTR dwParam), (IDDevice, uMsg, fdwCommand, dwParam))
PROXY_FUNC(mciGetErrorStringA, BOOL, (MCIERROR mcierr, LPSTR pszText, UINT cchText), (mcierr, pszText, cchText))
PROXY_FUNC(mciGetErrorStringW, BOOL, (MCIERROR mcierr, LPWSTR pszText, UINT cchText), (mcierr, pszText, cchText))

PROXY_FUNC(waveOutOpen, MMRESULT, (LPHWAVEOUT phwo, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phwo, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen))PROXY_FUNC(waveOutClose, MMRESULT, (HWAVEOUT hwo), (hwo))
PROXY_FUNC(waveOutPrepareHeader, MMRESULT, (HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh), (hwo, pwh, cbwh))
PROXY_FUNC(waveOutUnprepareHeader, MMRESULT, (HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh), (hwo, pwh, cbwh))
PROXY_FUNC(waveOutWrite, MMRESULT, (HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh), (hwo, pwh, cbwh))
PROXY_FUNC(waveOutPause, MMRESULT, (HWAVEOUT hwo), (hwo))
PROXY_FUNC(waveOutRestart, MMRESULT, (HWAVEOUT hwo), (hwo))
PROXY_FUNC(waveOutReset, MMRESULT, (HWAVEOUT hwo), (hwo))
PROXY_FUNC(waveOutBreakLoop, MMRESULT, (HWAVEOUT hwo), (hwo))
PROXY_FUNC(waveOutGetPosition, MMRESULT, (HWAVEOUT hwo, LPMMTIME pmmt, UINT cbmmt), (hwo, pmmt, cbmmt))
PROXY_FUNC(waveOutGetPitch, MMRESULT, (HWAVEOUT hwo, LPDWORD pdwPitch), (hwo, pdwPitch))
PROXY_FUNC(waveOutSetPitch, MMRESULT, (HWAVEOUT hwo, DWORD dwPitch), (hwo, dwPitch))
PROXY_FUNC(waveOutGetPlaybackRate, MMRESULT, (HWAVEOUT hwo, LPDWORD pdwRate), (hwo, pdwRate))
PROXY_FUNC(waveOutSetPlaybackRate, MMRESULT, (HWAVEOUT hwo, DWORD dwRate), (hwo, dwRate))
PROXY_FUNC(waveOutGetID, MMRESULT, (HWAVEOUT hwo, LPUINT puDeviceID), (hwo, puDeviceID))
PROXY_FUNC(waveOutMessage, MMRESULT, (HWAVEOUT hwo, UINT uMessage, DWORD_PTR dw1, DWORD_PTR dw2), (hwo, uMessage, dw1, dw2))
PROXY_FUNC(waveOutGetNumDevs, UINT, (void), ())
PROXY_FUNC(waveOutGetDevCapsA, MMRESULT, (UINT_PTR uDeviceID, LPWAVEOUTCAPSA pwoc, UINT cbwoc), (uDeviceID, pwoc, cbwoc))
PROXY_FUNC(waveOutGetDevCapsW, MMRESULT, (UINT_PTR uDeviceID, LPWAVEOUTCAPSW pwoc, UINT cbwoc), (uDeviceID, pwoc, cbwoc))
PROXY_FUNC(waveOutGetVolume, MMRESULT, (HWAVEOUT hwo, LPDWORD pdwVolume), (hwo, pdwVolume))
PROXY_FUNC(waveOutSetVolume, MMRESULT, (HWAVEOUT hwo, DWORD dwVolume), (hwo, dwVolume))
PROXY_FUNC(waveOutGetErrorTextA, MMRESULT, (MMRESULT mmrError, LPSTR pszText, UINT cchText), (mmrError, pszText, cchText))
PROXY_FUNC(waveOutGetErrorTextW, MMRESULT, (MMRESULT mmrError, LPWSTR pszText, UINT cchText), (mmrError, pszText, cchText))

PROXY_FUNC(waveInOpen, MMRESULT, (LPHWAVEIN phwi, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phwi, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen))PROXY_FUNC(waveInPrepareHeader, MMRESULT, (HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh), (hwi, pwh, cbwh))
PROXY_FUNC(waveInUnprepareHeader, MMRESULT, (HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh), (hwi, pwh, cbwh))
PROXY_FUNC(waveInAddBuffer, MMRESULT, (HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh), (hwi, pwh, cbwh))
PROXY_FUNC(waveInStart, MMRESULT, (HWAVEIN hwi), (hwi))
PROXY_FUNC(waveInStop, MMRESULT, (HWAVEIN hwi), (hwi))
PROXY_FUNC(waveInReset, MMRESULT, (HWAVEIN hwi), (hwi))
PROXY_FUNC(waveInGetPosition, MMRESULT, (HWAVEIN hwi, LPMMTIME pmmt, UINT cbmmt), (hwi, pmmt, cbmmt))
PROXY_FUNC(waveInGetID, MMRESULT, (HWAVEIN hwi, LPUINT puDeviceID), (hwi, puDeviceID))
PROXY_FUNC(waveInMessage, MMRESULT, (HWAVEIN hwi, UINT uMessage, DWORD_PTR dw1, DWORD_PTR dw2), (hwi, uMessage, dw1, dw2))
PROXY_FUNC(waveInGetNumDevs, UINT, (void), ())
PROXY_FUNC(waveInGetDevCapsA, MMRESULT, (UINT_PTR uDeviceID, LPWAVEINCAPSA pwic, UINT cbwic), (uDeviceID, pwic, cbwic))
PROXY_FUNC(waveInGetDevCapsW, MMRESULT, (UINT_PTR uDeviceID, LPWAVEINCAPSW pwic, UINT cbwic), (uDeviceID, pwic, cbwic))
PROXY_FUNC(waveInGetErrorTextA, MMRESULT, (MMRESULT mmrError, LPSTR pszText, UINT cchText), (mmrError, pszText, cchText))
PROXY_FUNC(waveInGetErrorTextW, MMRESULT, (MMRESULT mmrError, LPWSTR pszText, UINT cchText), (mmrError, pszText, cchText))

PROXY_FUNC(mixerOpen, MMRESULT, (LPHMIXER phmx, UINT uMxId, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phmx, uMxId, dwCallback, dwInstance, fdwOpen))
PROXY_FUNC(mixerClose, MMRESULT, (HMIXER hmx), (hmx))
PROXY_FUNC(mixerGetLineInfoA, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINEA pmxl, DWORD fdwInfo), (hmxobj, pmxl, fdwInfo))
PROXY_FUNC(mixerGetLineInfoW, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINEW pmxl, DWORD fdwInfo), (hmxobj, pmxl, fdwInfo))
PROXY_FUNC(mixerGetID, MMRESULT, (HMIXEROBJ hmxobj, UINT FAR* puMxId, DWORD fdwId), (hmxobj, puMxId, fdwId))
PROXY_FUNC(mixerGetLineControlsA, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINECONTROLSA pmxlc, DWORD fdwControls), (hmxobj, pmxlc, fdwControls))
PROXY_FUNC(mixerGetLineControlsW, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINECONTROLSW pmxlc, DWORD fdwControls), (hmxobj, pmxlc, fdwControls))
PROXY_FUNC(mixerGetControlDetailsA, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails), (hmxobj, pmxcd, fdwDetails))
PROXY_FUNC(mixerGetControlDetailsW, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails), (hmxobj, pmxcd, fdwDetails))
PROXY_FUNC(mixerSetControlDetails, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails), (hmxobj, pmxcd, fdwDetails))
PROXY_FUNC(mixerGetNumDevs, UINT, (void), ())
PROXY_FUNC(mixerGetDevCapsA, MMRESULT, (UINT_PTR uMxId, LPMIXERCAPSA pmxcaps, UINT cbmxcaps), (uMxId, pmxcaps, cbmxcaps))
PROXY_FUNC(mixerGetDevCapsW, MMRESULT, (UINT_PTR uMxId, LPMIXERCAPSW pmxcaps, UINT cbmxcaps), (uMxId, pmxcaps, cbmxcaps))
PROXY_FUNC(mixerMessage, DWORD, (HMIXER hmx, UINT uMessage, DWORD_PTR dwParam1, DWORD_PTR dwParam2), (hmx, uMessage, dwParam1, dwParam2))

PROXY_FUNC(auxGetNumDevs, UINT, (void), ())
PROXY_FUNC(auxGetDevCapsA, MMRESULT, (UINT_PTR uDeviceID, LPAUXCAPSA pac, UINT cbac), (uDeviceID, pac, cbac))
PROXY_FUNC(auxGetDevCapsW, MMRESULT, (UINT_PTR uDeviceID, LPAUXCAPSW pac, UINT cbac), (uDeviceID, pac, cbac))
PROXY_FUNC(auxSetVolume, MMRESULT, (UINT uDeviceID, DWORD dwVolume), (uDeviceID, dwVolume))
PROXY_FUNC(auxGetVolume, MMRESULT, (UINT uDeviceID, LPDWORD pdwVolume), (uDeviceID, pdwVolume))
PROXY_FUNC(auxOutMessage, MMRESULT, (UINT uDeviceID, UINT uMessage, DWORD_PTR dw1, DWORD_PTR dw2), (uDeviceID, uMessage, dw1, dw2))

PROXY_FUNC(joyGetNumDevs, UINT, (void), ())
PROXY_FUNC(joyGetDevCapsA, MMRESULT, (UINT_PTR uJoyID, LPJOYCAPSA pjc, UINT cbjc), (uJoyID, pjc, cbjc))
PROXY_FUNC(joyGetDevCapsW, MMRESULT, (UINT_PTR uJoyID, LPJOYCAPSW pjc, UINT cbjc), (uJoyID, pjc, cbjc))
PROXY_FUNC(joyGetPos, MMRESULT, (UINT uJoyID, LPJOYINFO pji), (uJoyID, pji))
PROXY_FUNC(joyGetPosEx, MMRESULT, (UINT uJoyID, LPJOYINFOEX pji), (uJoyID, pji))
PROXY_FUNC(joyGetThreshold, MMRESULT, (UINT uJoyID, LPUINT puThreshold), (uJoyID, puThreshold))
PROXY_FUNC(joySetThreshold, MMRESULT, (UINT uJoyID, UINT uThreshold), (uJoyID, uThreshold))
PROXY_FUNC(joyReleaseCapture, MMRESULT, (UINT uJoyID), (uJoyID))
PROXY_FUNC(joySetCapture, MMRESULT, (HWND hwnd, UINT uJoyID, UINT uPeriod, BOOL fChanged), (hwnd, uJoyID, uPeriod, fChanged))


BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        if (!g_initialized) {
            g_initialized = true;
            g_is_version_dll = detect_dll_type();
            CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
                perform_steam_injection();
                return 0;
                }, nullptr, 0, nullptr);
        }
        break;

    case DLL_PROCESS_DETACH:
        cleanup_registry();
        if (g_original_dll) {
            FreeLibrary(g_original_dll);
            g_original_dll = nullptr;
        }
        break;
    }
    return TRUE;
}