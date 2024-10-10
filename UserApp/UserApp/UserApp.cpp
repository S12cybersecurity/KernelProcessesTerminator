#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define IOCTL_GET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

using namespace std;

int getPIDbyProcName(const string& procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe32) != FALSE) {
        while (pid == 0 && Process32NextW(hSnap, &pe32) != FALSE) {
            wstring wideProcName(procName.begin(), procName.end());
            if (wcscmp(pe32.szExeFile, wideProcName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
            }
        }
    }
    CloseHandle(hSnap);
    return pid;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <process_name>" << endl;
        return 1;
    }

    string procName = argv[1];  

    HANDLE hDevice = CreateFile(L"\\\\.\\MyDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        cout << "Failed to open device, error: " << GetLastError() << endl;
        return 1;
    }

    ULONG pid = getPIDbyProcName(procName);  
    if (pid == 0) {
        cout << "Process not found: " << procName << endl;
        CloseHandle(hDevice);
        return 1;
    }

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice, IOCTL_GET_PID, &pid, sizeof(pid), &pid, sizeof(pid), &bytesReturned, NULL);

    if (result)
    {
        cout << "PID: " << pid << endl;
    }
    else
    {
        cout << "Failed to send PID" << endl;
    }

    CloseHandle(hDevice);
    return 0;
}
