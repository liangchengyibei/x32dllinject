//第一种注入方式，模仿微软DetourCreateProcessWithDll 注入dll
//原理是在进程创建初期，修改导入表，将我们的dll加入进去。
#include "CImageX32.h"
#include "framework.h"
#include "DLLInjectTool.h"
#include "DLLInjectToolDlg.h"
#include "afxdialogex.h"
#include<psapi.h>
#include<tchar.h>
#include "FunInject.h"
//CreateProcessA 函数指针
#define my_ERROR(T) MessageBox(NULL,T,TEXT("my_ERROR!"),0)

typedef BOOL(WINAPI*PDETOUR_CREATE_PROCESS_ROUTINE)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

//定义DetourCreateProcessWithDll 原型
BOOL DetourCreateProcessWithDll(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	LPTSTR				  lpDllName,
	PDETOUR_CREATE_PROCESS_ROUTINE pfCreateProcess
);


ULONG_PTR FindImageBase(HANDLE hProc, LPSTR lpCommandLine)
{
	//原理，通过比较内存页，第一个页属性为MEM_IMAGE的为EXE实际加载基址
	//获取页大小 dwPageSize
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	DWORD dwPageSize = sysinfo.dwPageSize;
	MEMORY_BASIC_INFORMATION mbi;
	TCHAR* pFileNameToCheck = _tcsrchr((TCHAR*)lpCommandLine, TCHAR('\\'));

	//查找第一个具有MEM_IMAGE属性的页
	PBYTE lpAddress = (PBYTE)sysinfo.lpMinimumApplicationAddress;
	while (lpAddress < (PBYTE)sysinfo.lpMaximumApplicationAddress)
	{
		ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
		DWORD dwSize = VirtualQueryEx(hProc, lpAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		//如果dwSize = 0，调用失败，则继续下次循环
		if (dwSize == 0)
		{
			lpAddress += dwPageSize;
			continue;
		}

		if (mbi.State == MEM_RESERVE || mbi.State == MEM_FREE)
		{
			lpAddress = mbi.RegionSize + (PBYTE)mbi.BaseAddress;
		}
		else
		{
			if (mbi.Type == MEM_IMAGE)
			{
				TCHAR szFileNameBuffer[MAX_PATH];
				GetMappedFileName(hProc, lpAddress, szFileNameBuffer, MAX_PATH);
				TCHAR *pCompare = _tcsrchr(szFileNameBuffer,TCHAR('\\'));
				if (_tcsicmp(pFileNameToCheck, pCompare) == 0)
				{
					return (ULONG_PTR)lpAddress;
				}
			}
			lpAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize;

		}
	}
	//查找失败
	MessageBox(NULL, TEXT("my_ERROR"), TEXT("定位内存Image失败"),0);
	return FALSE;
}

//模拟Detours 注入dll 
//原理，主线程运行前 修改导入表
BOOL DetourCreateProcessWithDllx32(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	LPTSTR lpDllName,
	LPTSTR szExpFunName,
	PDETOUR_CREATE_PROCESS_ROUTINE pfCreateProcess
)
{
	//实例化CImageX32;
	CImageX32 ImageX32;
	//输出信息
	CString szInformation;
	//一般BOOL函数返回值
	BOOL bResult = FALSE;
	CWnd *pWnd = AfxGetMainWnd();

	//以休眠方式创建进程
	DWORD dwNewCreationFlags = dwCreationFlags + CREATE_SUSPENDED;
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = {0};

	si.cb = sizeof(si);

	bResult = CreateProcessA(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwNewCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		&si,
		&pi
	);
	if (!bResult)
	{
		my_ERROR(TEXT("创建进程失败！"));
		return FALSE;
	}
	//进程创建成功，进入休眠
	ImageX32.hProc = pi.hProcess;
	//获取进程在内存中的映像基址
	DWORD ImageBase = FindImageBase(pi.hProcess, lpCommandLine);
	ImageX32.m_ImageBase = ImageBase;
	szInformation.AppendFormat(TEXT("[*]以休眠方式创建进程成功： ImageBase = 0x%p\r\n"),ImageBase);
	//显示在编辑框
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	//将ImageBase之后0x1000读入m_HeaderData
	bResult = ReadProcessMemory(pi.hProcess, (LPCVOID)ImageBase, ImageX32.m_HeaderData, 0x1000, NULL);
	if (!bResult)
	{
		my_ERROR(TEXT("读取进程pe数据失败！"));
		return FALSE;
	}
	//解析pe头数据
	ImageX32.AnalysisPEHeader();
	//显示刚才解析的原始导入表RVA以及Size
	szInformation.AppendFormat(TEXT("[*]原始导入表VirtualAddress：0x%p Size = 0x%X\r\n"), 
		ImageX32.m_pImpDataDir->VirtualAddress,ImageX32.m_pImpDataDir->Size);
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	//首先在内存中新开一个区块，用来放最新的导入表和数据
	//所需要的大小为：ThunkData + 新的IID数组大小，别忘了最后一项是0
	DWORD dwNeedSize = ImageX32.m_pImpDataDir->Size + 0x14 * 2
		+ _tcslen(lpDllName) + 1 + 2 + _tcslen(szExpFunName) + 1 + 8;
	//对齐一下dwNeedSize
	dwNeedSize = SIZE_UP(dwNeedSize, 4);
	//调用MallocNewSection
	DWORD lpNewMemVA = ImageX32.MallocNewSection(dwNeedSize);

	szInformation.AppendFormat(TEXT("[*]新开区块VA = 0x%p\r\n"), lpNewMemVA);
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	//接下来填充IID和排列ThunkData
	//首先读旧IID
	//整个缓冲区保存数据
	BYTE* szBuff = (BYTE*)malloc(dwNeedSize);
	ZeroMemory(szBuff, dwNeedSize);
	
	bResult = ReadProcessMemory(pi.hProcess, (LPVOID)(ImageBase + ImageX32.m_pImpDataDir->VirtualAddress),
		szBuff, ImageX32.m_pImpDataDir->Size -0x14, NULL);
	if (!bResult)
	{
		my_ERROR(TEXT("读取旧IID失败!"));
		return FALSE;
	}
	szInformation.AppendFormat(TEXT("[*]向缓冲区写入旧导入表成功\r\n"), lpNewMemVA);
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	PIMAGE_IMPORT_DESCRIPTOR pNewIIDBuffer = (PIMAGE_IMPORT_DESCRIPTOR)szBuff+ImageX32.m_pImpDataDir->Size - 0x14;
	//向缓冲区写入新的ThunkData
	int IndexNewIID = ImageX32.m_pImpDataDir->Size - 0x14;//缓冲区内下标，此时指向新的IID
	int IndexIIBN = IndexNewIID + 0x28;
	int IndexDLLName = IndexIIBN + 2 + _tcslen(szExpFunName) + 1;
	int IndexINT = IndexDLLName + _tcslen(lpDllName) + 1;
	
	//填充IID结构内的RVA lpNewMemVA: 0x00410000 
	//INT RVA
	DWORD RVA_INT = lpNewMemVA - ImageBase + IndexINT;
	memcpy(&szBuff[IndexNewIID], &RVA_INT, 4);
	//DLLNAME RVA
	DWORD RVA_DLLNAME = lpNewMemVA - ImageBase + IndexDLLName;
	memcpy(&szBuff[IndexNewIID + 0xc], &RVA_DLLNAME, 4);
	//IAT RVA
	memcpy(&szBuff[IndexNewIID + 0x10], &RVA_INT, 4);
	//填充ThunkData内的数据
	_tcsncpy((TCHAR*)&szBuff[IndexIIBN + 2], szExpFunName, _tcslen(szExpFunName));
	_tcsncpy((TCHAR*)&szBuff[IndexDLLName], lpDllName, _tcslen(lpDllName));
	DWORD RVA_IIBN = lpNewMemVA - ImageBase + IndexIIBN;
	memcpy(&szBuff[IndexINT], &RVA_IIBN, 4);
	//之后直接把szBuffer 写到lpNewMemVA处
	bResult = WriteProcessMemory(pi.hProcess, (LPVOID)lpNewMemVA, szBuff, dwNeedSize, NULL);
	if (!bResult)
	{
		my_ERROR(TEXT("写导入表数据失败!"));
		return FALSE;
	}
	
	szInformation.AppendFormat(TEXT("[*]感染导入表完成\r\n"), lpNewMemVA);
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	//接下来只需要将pe头以及导入数据目录修正即可
	//更改目标进程的pe头页属性 可写
	DWORD flOldProtect = 0;
	bResult = VirtualProtectEx(pi.hProcess, (LPVOID)ImageBase, 0x1000, PAGE_READWRITE, &flOldProtect);
	if (!bResult)
	{
		my_ERROR(TEXT("修改pe头内存属性失败！"));
		return FALSE;
	}
	//先修改ImageX32中的m_HeaderData ， 然后调用WriteProcessMemory写入原进程 pe头
	//IMAGE_OPTIONAL_HEADER a;14*4  14 DWORD->SizeOfImage SIZE_UP(SectionAlignment)
	ImageX32.m_pOptHeader->SizeOfImage += SIZE_UP(dwNeedSize, ImageX32.m_pOptHeader->SectionAlignment);
	ImageX32.m_pImpDataDir->Size += 0x14;
	ImageX32.m_pImpDataDir->VirtualAddress = lpNewMemVA - ImageBase;
	bResult = WriteProcessMemory(pi.hProcess, (LPVOID)ImageBase, ImageX32.m_HeaderData, 0x1000, NULL);
	if (!bResult)
	{
		my_ERROR(TEXT("写入傀儡进程pe头失败！"));
		return FALSE;
	}
	szInformation.AppendFormat(TEXT("[*]写入傀儡进程pe头成功\r\n"));
	szInformation.AppendFormat(TEXT("[*]正在唤醒傀儡进程......\r\n"));
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	UpdateWindow((HWND)pWnd);
	Sleep(3000);

	ResumeThread(pi.hThread);
	return TRUE;
}

