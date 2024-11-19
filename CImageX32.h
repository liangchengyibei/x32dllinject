#pragma once
//����pe
#include "framework.h"
#define SIZE_UP(size,alignment) (((DWORD)size + alignment -1)&~(alignment -1))
#define SIZE_UP64(size,alignment) (((QWORD)size + (QWORD)alignment -1)&~((QWORD)alignment -1))
class CImageX32
{
public:
	SYSTEM_INFO info;
	HANDLE hProc;
	DWORD m_ImageBase;
	BYTE m_HeaderData[0x1000];
	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_NT_HEADERS m_pNtHeaders;
	PIMAGE_FILE_HEADER m_pFileHeader;
	PIMAGE_OPTIONAL_HEADER m_pOptHeader;
	PIMAGE_DATA_DIRECTORY m_pImpDataDir;
	PIMAGE_SECTION_HEADER m_pSecHeader;
public:
	CImageX32();
	void AnalysisPEHeader();
	//ֱ�������һ�������������һ���µ�����,��СΪsize���϶����ĳߴ�
	//����ֵΪ���һ�����������뵽�� RVA
	DWORD MallocNewSection(DWORD size);


};

class CImageX64 {
public:
	SYSTEM_INFO info;
	HANDLE hProc;
	QWORD m_ImageBase;
	BYTE m_HeaderData[0x1000];
	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_NT_HEADERS64 m_pNtHeaders;
	PIMAGE_FILE_HEADER m_pFileHeader;
	PIMAGE_OPTIONAL_HEADER64 m_pOptHeader;
	PIMAGE_DATA_DIRECTORY m_ImpDataDir;
	PIMAGE_SECTION_HEADER m_pSecHeader;
public:
	CImageX64();
	void AnalysisPEHeaderX64();
	//64λָ��
	QWORD MallocNewSectionX64(size_t size);

};

