//author https://github.com/autergame
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <stdint.h>
#include <locale.h>
#include <stdio.h>
#include <psapi.h>
#include <time.h>
#pragma comment(lib, "ntdll")

#define NT_SUCCESS(status) (status >= 0)

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

typedef enum PROCESSINFOCLASS {
    ProcessHandleInformation = 51
} PROCESSINFOCLASS;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

NTSTATUS NTAPI NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectNameInformation = 1
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

NTSTATUS NTAPI NtQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength);

DWORD FindGenshin()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    Process32First(hSnapshot, &pe);

    DWORD pid = 0;
    while (Process32Next(hSnapshot, &pe)) 
    {
        if (strcmp(pe.szExeFile, "GenshinImpact.exe") == 0)
        {
            pid = pe.th32ProcessID;
            break;
        }
    }

    CloseHandle(hSnapshot);
    return pid;
}

BOOL isinjected(HANDLE hProcess, char* dllname)
{
    DWORD cbNeeded;
    HMODULE hMods[1024];
    char szModName[MAX_PATH];
    if (K32EnumProcessModules(hProcess, hMods, 1024, &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            memset(szModName, 0, MAX_PATH);
            if (K32GetModuleBaseNameA(hProcess, hMods[i], szModName, MAX_PATH))
            {
                if (strcmp(szModName, dllname) == 0)
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}

int main(int argc, char** argv)
{
    FILE* file = fopen("config.txt", "rb");
    if (!file)
    {
        printf("Cannot open config file\n");
        system("pause");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* fp = (char*)calloc(1, fsize + 1);
    if (fread(fp, fsize, 1, file) == NULL)
    {
        printf("Cannot read config file\n");
        system("pause");
        return 1;
    }
    fp[fsize] = 0;
    fclose(file);

    srand(time(NULL));
    char* winname = (char*)calloc(16, 1);
    for (int i = 0; i < 15; i++)
        winname[i] = (rand() % 26) + 'A';
    SetConsoleTitle(winname);

    char* currentdir = (char*)calloc(256, 1);
    strcat_s(currentdir, 256, argv[0]);
    char* currentdirpos = strrchr(currentdir, '\\');
    currentdir[currentdirpos - currentdir] = '\0';
    strcat_s(currentdir, 256, "\\");
    strcat_s(currentdir, 256, fp);

    DWORD pid = FindGenshin();
    if (pid == 0) 
    {
        printf("Failed to locate media player\n");
        system("pause");
        return 1;
    }
    printf("Located genshin: PID=%u\n", pid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_DUP_HANDLE | 
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) 
    {
        printf("Failed to open WMP process handle (error=%u)\n", GetLastError());
        system("pause");
        return 1;
    }

    if (!isinjected(hProcess, fp))
    {
        ULONG size = 1 << 10;
        BYTE* buffer = calloc(size, 1);
        while (1)
        {
            NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessHandleInformation, buffer, size, &size);
            if (NT_SUCCESS(status))
                break;
            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                size += 1 << 10;
                buffer = (BYTE*)realloc(buffer, size);
                continue;
            }
            printf("Error enumerating handles");
            system("pause");
            return 1;
        }
        
        int passed = 0;
        BYTE nameBuffer[8192];
        HANDLE hTarget, hSource;
        HANDLE hCurrent = GetCurrentProcess();
        PROCESS_HANDLE_SNAPSHOT_INFORMATION* info = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)buffer;
        for (ULONG i = 0; i < 500; i++)
        {
            hSource = info->Handles[i].HandleValue;
            if (!DuplicateHandle(hProcess, hSource, hCurrent, &hTarget, 0, FALSE, DUPLICATE_SAME_ACCESS))
                continue;
            NTSTATUS status = NtQueryObject(hTarget, ObjectNameInformation, nameBuffer, 8192, NULL);
            CloseHandle(hTarget);
            if (!NT_SUCCESS(status))
            {
                memset(nameBuffer, 0, 8192);
                continue;
            }
            UNICODE_STRING* name = (UNICODE_STRING*)nameBuffer;
            if (name->Buffer)
            {
                if (_wcsnicmp(name->Buffer, L"\\Device\\mhyprot2", 17) == 0)
                {
                    DuplicateHandle(hProcess, hSource, hCurrent, &hTarget, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
                    CloseHandle(hTarget);
                    printf("Mhyprot2 closed\n");
                    passed = 1;
                    break;
                }
            }
            memset(nameBuffer, 0, 8192);
        }

        if (passed)
        {
            printf("Waiting 60 seconds\n");
            Sleep(60000);
        }

        printf("Injecting\n");

        size_t sizef = strlen(currentdir);
        LPVOID dll_path_remote = VirtualAllocEx(hProcess, NULL, sizef + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!dll_path_remote)
        {
            CloseHandle(hProcess);
            printf("Failed to alloc space try again\n");
            system("pause");
            return 1;
        }

        if (!WriteProcessMemory(hProcess, dll_path_remote, currentdir, sizef + 1, NULL))
        {
            VirtualFreeEx(hProcess, dll_path_remote, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            printf("Failed to write memory\n");
            system("pause");
            return 1;
        }

        FARPROC loadlib = GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
        HANDLE thread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, dll_path_remote, 0, NULL);
        if (!thread || thread == INVALID_HANDLE_VALUE)
        {
            VirtualFreeEx(hProcess, dll_path_remote, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            printf("Failed to create thread\n");
            system("pause");
            return 1;
        }

        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        VirtualFreeEx(hProcess, dll_path_remote, 0, MEM_RELEASE);

        if (isinjected(hProcess, fp))
        {
            printf("Successful injected\n");
            system("pause");
            return 0;
        }
        else {
            printf("Error injecting\n");
            system("pause");
            return 1;
        }
    }

    CloseHandle(hProcess);
    printf("Already injected\n");
    system("pause");
    return 0;
}