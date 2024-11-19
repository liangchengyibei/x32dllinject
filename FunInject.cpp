//��һ��ע�뷽ʽ��ģ��΢��DetourCreateProcessWithDll ע��dll
//ԭ�����ڽ��̴������ڣ��޸ĵ���������ǵ�dll�����ȥ��
#include "CImageX32.h"
#include "framework.h"
#include "DLLInjectTool.h"
#include "DLLInjectToolDlg.h"
#include "afxdialogex.h"
#include<psapi.h>
#include<tchar.h>
#include "FunInject.h"
//CreateProcessA ����ָ��
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

//����DetourCreateProcessWithDll ԭ��
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
	//ԭ��ͨ���Ƚ��ڴ�ҳ����һ��ҳ����ΪMEM_IMAGE��ΪEXEʵ�ʼ��ػ�ַ
	//��ȡҳ��С dwPageSize
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	DWORD dwPageSize = sysinfo.dwPageSize;
	MEMORY_BASIC_INFORMATION mbi;
	TCHAR* pFileNameToCheck = _tcsrchr((TCHAR*)lpCommandLine, TCHAR('\\'));

	//���ҵ�һ������MEM_IMAGE���Ե�ҳ
	PBYTE lpAddress = (PBYTE)sysinfo.lpMinimumApplicationAddress;
	while (lpAddress < (PBYTE)sysinfo.lpMaximumApplicationAddress)
	{
		ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
		DWORD dwSize = VirtualQueryEx(hProc, lpAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		//���dwSize = 0������ʧ�ܣ�������´�ѭ��
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
	//����ʧ��
	MessageBox(NULL, TEXT("my_ERROR"), TEXT("��λ�ڴ�Imageʧ��"),0);
	return FALSE;
}

//ģ��Detours ע��dll 
//ԭ�����߳�����ǰ �޸ĵ����
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
	//ʵ����CImageX32;
	CImageX32 ImageX32;
	//�����Ϣ
	CString szInformation;
	//һ��BOOL��������ֵ
	BOOL bResult = FALSE;
	CWnd *pWnd = AfxGetMainWnd();

	//�����߷�ʽ��������
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
		my_ERROR(TEXT("��������ʧ�ܣ�"));
		return FALSE;
	}
	//���̴����ɹ�����������
	ImageX32.hProc = pi.hProcess;
	//��ȡ�������ڴ��е�ӳ���ַ
	DWORD ImageBase = FindImageBase(pi.hProcess, lpCommandLine);
	ImageX32.m_ImageBase = ImageBase;
	szInformation.AppendFormat(TEXT("[*]�����߷�ʽ�������̳ɹ��� ImageBase = 0x%p\r\n"),ImageBase);
	//��ʾ�ڱ༭��
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	//��ImageBase֮��0x1000����m_HeaderData
	bResult = ReadProcessMemory(pi.hProcess, (LPCVOID)ImageBase, ImageX32.m_HeaderData, 0x1000, NULL);
	if (!bResult)
	{
		my_ERROR(TEXT("��ȡ����pe����ʧ�ܣ�"));
		return FALSE;
	}
	//����peͷ����
	ImageX32.AnalysisPEHeader();
	//��ʾ�ղŽ�����ԭʼ�����RVA�Լ�Size
	szInformation.AppendFormat(TEXT("[*]ԭʼ�����VirtualAddress��0x%p Size = 0x%X\r\n"), 
		ImageX32.m_pImpDataDir->VirtualAddress,ImageX32.m_pImpDataDir->Size);
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	//�������ڴ����¿�һ�����飬���������µĵ���������
	//����Ҫ�Ĵ�СΪ��ThunkData + �µ�IID�����С�����������һ����0
	DWORD dwNeedSize = ImageX32.m_pImpDataDir->Size + 0x14 * 2
		+ _tcslen(lpDllName) + 1 + 2 + _tcslen(szExpFunName) + 1 + 8;
	//����һ��dwNeedSize
	dwNeedSize = SIZE_UP(dwNeedSize, 4);
	//����MallocNewSection
	DWORD lpNewMemVA = ImageX32.MallocNewSection(dwNeedSize);

	szInformation.AppendFormat(TEXT("[*]�¿�����VA = 0x%p\r\n"), lpNewMemVA);
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	//���������IID������ThunkData
	//���ȶ���IID
	//������������������
	BYTE* szBuff = (BYTE*)malloc(dwNeedSize);
	ZeroMemory(szBuff, dwNeedSize);
	
	bResult = ReadProcessMemory(pi.hProcess, (LPVOID)(ImageBase + ImageX32.m_pImpDataDir->VirtualAddress),
		szBuff, ImageX32.m_pImpDataDir->Size -0x14, NULL);
	if (!bResult)
	{
		my_ERROR(TEXT("��ȡ��IIDʧ��!"));
		return FALSE;
	}
	szInformation.AppendFormat(TEXT("[*]�򻺳���д��ɵ����ɹ�\r\n"), lpNewMemVA);
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	PIMAGE_IMPORT_DESCRIPTOR pNewIIDBuffer = (PIMAGE_IMPORT_DESCRIPTOR)szBuff+ImageX32.m_pImpDataDir->Size - 0x14;
	//�򻺳���д���µ�ThunkData
	int IndexNewIID = ImageX32.m_pImpDataDir->Size - 0x14;//���������±꣬��ʱָ���µ�IID
	int IndexIIBN = IndexNewIID + 0x28;
	int IndexDLLName = IndexIIBN + 2 + _tcslen(szExpFunName) + 1;
	int IndexINT = IndexDLLName + _tcslen(lpDllName) + 1;
	
	//���IID�ṹ�ڵ�RVA lpNewMemVA: 0x00410000 
	//INT RVA
	DWORD RVA_INT = lpNewMemVA - ImageBase + IndexINT;
	memcpy(&szBuff[IndexNewIID], &RVA_INT, 4);
	//DLLNAME RVA
	DWORD RVA_DLLNAME = lpNewMemVA - ImageBase + IndexDLLName;
	memcpy(&szBuff[IndexNewIID + 0xc], &RVA_DLLNAME, 4);
	//IAT RVA
	memcpy(&szBuff[IndexNewIID + 0x10], &RVA_INT, 4);
	//���ThunkData�ڵ�����
	_tcsncpy((TCHAR*)&szBuff[IndexIIBN + 2], szExpFunName, _tcslen(szExpFunName));
	_tcsncpy((TCHAR*)&szBuff[IndexDLLName], lpDllName, _tcslen(lpDllName));
	DWORD RVA_IIBN = lpNewMemVA - ImageBase + IndexIIBN;
	memcpy(&szBuff[IndexINT], &RVA_IIBN, 4);
	//֮��ֱ�Ӱ�szBuffer д��lpNewMemVA��
	bResult = WriteProcessMemory(pi.hProcess, (LPVOID)lpNewMemVA, szBuff, dwNeedSize, NULL);
	if (!bResult)
	{
		my_ERROR(TEXT("д���������ʧ��!"));
		return FALSE;
	}
	
	szInformation.AppendFormat(TEXT("[*]��Ⱦ��������\r\n"), lpNewMemVA);
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	//������ֻ��Ҫ��peͷ�Լ���������Ŀ¼��������
	//����Ŀ����̵�peͷҳ���� ��д
	DWORD flOldProtect = 0;
	bResult = VirtualProtectEx(pi.hProcess, (LPVOID)ImageBase, 0x1000, PAGE_READWRITE, &flOldProtect);
	if (!bResult)
	{
		my_ERROR(TEXT("�޸�peͷ�ڴ�����ʧ�ܣ�"));
		return FALSE;
	}
	//���޸�ImageX32�е�m_HeaderData �� Ȼ�����WriteProcessMemoryд��ԭ���� peͷ
	//IMAGE_OPTIONAL_HEADER a;14*4  14 DWORD->SizeOfImage SIZE_UP(SectionAlignment)
	ImageX32.m_pOptHeader->SizeOfImage += SIZE_UP(dwNeedSize, ImageX32.m_pOptHeader->SectionAlignment);
	ImageX32.m_pImpDataDir->Size += 0x14;
	ImageX32.m_pImpDataDir->VirtualAddress = lpNewMemVA - ImageBase;
	bResult = WriteProcessMemory(pi.hProcess, (LPVOID)ImageBase, ImageX32.m_HeaderData, 0x1000, NULL);
	if (!bResult)
	{
		my_ERROR(TEXT("д����ܽ���peͷʧ�ܣ�"));
		return FALSE;
	}
	szInformation.AppendFormat(TEXT("[*]д����ܽ���peͷ�ɹ�\r\n"));
	szInformation.AppendFormat(TEXT("[*]���ڻ��ѿ��ܽ���......\r\n"));
	pWnd->GetDlgItem(IDC_INFO)->SetWindowText(szInformation);
	pWnd->GetDlgItem(IDC_INFO)->UpdateWindow();
	Sleep(1000);
	UpdateWindow((HWND)pWnd);
	Sleep(3000);

	ResumeThread(pi.hThread);
	return TRUE;
}

