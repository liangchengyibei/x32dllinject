#include "CImageX32.h"
//向上对齐宏: 将size向上对齐为alignment的整数倍


CImageX32::CImageX32()
{
	//初始化成员变量
	GetSystemInfo(&info);
	hProc = NULL;
	m_ImageBase = NULL;
	m_pDosHeader = NULL;
	m_pNtHeaders = NULL;
	m_pFileHeader = NULL;
	m_pOptHeader = NULL;
	m_pImpDataDir = NULL;
	m_pSecHeader = NULL;
}

void CImageX32::AnalysisPEHeader()
{
	PBYTE pBase = (PBYTE)m_HeaderData;
	m_pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	m_pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + m_pDosHeader->e_lfanew);
	m_pFileHeader = &m_pNtHeaders->FileHeader;
	m_pOptHeader = &m_pNtHeaders->OptionalHeader;
	m_pImpDataDir = &m_pOptHeader->DataDirectory[0x1];
	m_pSecHeader = (PIMAGE_SECTION_HEADER)((BYTE*)m_pOptHeader + m_pFileHeader->SizeOfOptionalHeader);

}

DWORD CImageX32::MallocNewSection(DWORD size)
{

	size = SIZE_UP(size, m_pOptHeader->SectionAlignment);
	//对齐后调用VirtualAllocEx 分配地址
	//起始为最后一个节区后：
	PIMAGE_SECTION_HEADER pLastSection = (m_pFileHeader->NumberOfSections + m_pSecHeader -1 );
	DWORD pNewSectionVA = m_ImageBase +
		pLastSection->VirtualAddress + SIZE_UP(pLastSection->Misc.VirtualSize,m_pOptHeader->SectionAlignment);

	for (DWORD i = SIZE_UP(pNewSectionVA,info.dwAllocationGranularity);
		i < (DWORD)info.lpMaximumApplicationAddress; i += info.dwAllocationGranularity)
	{
		PBYTE x = (PBYTE)VirtualAllocEx(hProc, (PVOID)i, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (x)
		{
			pNewSectionVA = (DWORD)x;
			break;
		}
	}

	return pNewSectionVA;
}

//64位Image映像类构造函数
CImageX64::CImageX64()
{
	//进行类成员变量初始化工作
	GetSystemInfo(&info);
	hProc = NULL;
	m_ImageBase = NULL;
	ZeroMemory(m_HeaderData, 0x1000);
	m_pDosHeader = NULL;
	m_pFileHeader = NULL;
	m_pOptHeader = NULL;
	m_ImpDataDir = NULL;
	m_pSecHeader = NULL;
}

void CImageX64::AnalysisPEHeaderX64()
{
	PBYTE pBase = (PBYTE)m_HeaderData;
	m_pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	m_pNtHeaders = (PIMAGE_NT_HEADERS64)(pBase + m_pDosHeader->e_lfanew);
	m_pFileHeader = &m_pNtHeaders->FileHeader;
	m_pOptHeader = &m_pNtHeaders->OptionalHeader;
	m_ImpDataDir = &m_pOptHeader->DataDirectory[0x1];
	m_pSecHeader = (PIMAGE_SECTION_HEADER)((BYTE*)m_pOptHeader + m_pFileHeader->SizeOfOptionalHeader);
}

QWORD CImageX64::MallocNewSectionX64(size_t size)
{
	size = SIZE_UP(size, m_pOptHeader->SectionAlignment);
	//对齐后调用VirtualAllocEx 分配地址
	//起始为最后一个节区后：
	PIMAGE_SECTION_HEADER pLastSection = (m_pFileHeader->NumberOfSections + m_pSecHeader - 1);
	QWORD pNewSectionVA = m_ImageBase +
		pLastSection->VirtualAddress + SIZE_UP64(pLastSection->Misc.VirtualSize, m_pOptHeader->SectionAlignment);

	for (QWORD i = SIZE_UP64(pNewSectionVA, info.dwAllocationGranularity);
		i < (QWORD)info.lpMaximumApplicationAddress; i += info.dwAllocationGranularity)
	{
		PBYTE x = (PBYTE)VirtualAllocEx(hProc, (PVOID)i, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (x)
		{
			pNewSectionVA = (QWORD)x;
			break;
		}
	}

	return pNewSectionVA;
}
