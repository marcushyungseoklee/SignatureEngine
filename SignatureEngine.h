//
// Copyright (C) 2019 Marcushslee
//

#include "signature.h"

#ifdef EXPORTDLL

#define DLL_EXPORTING_API extern "C" __declspec(dllexport)

#define MAX_FILE_SIZE	0x7fff
#define FILE_NOT_EXIST	-2
#define EXT_NOT_EXIST	-1
#define NORMAL_FILE		1
#define	MISMATCH		0
#define	CAN_NOT_OPEN_FILE -3

DLL_EXPORTING_API INT	sigengine(CString strFile);
BOOL	findExtension(IN CString strfilePath,OUT CString &ext);
INT		findFileFormat(IN CString strfilePath,OUT FILE_SIGNATURE &signature);
INT		compareSignature(IN FILE_SIGNATURE signature,IN CString strfilePath);
VOID	myOutputDebugString(LPCTSTR pszStr,...);

#else
__declspec(dllimport) bool SignatureCheck(CString strFile);

typedef int (*fpSignatureCheck)(CString);

class CRFEngineSignature
{
	HMODULE m_hModule;
public:
	CRFEngineSignature()
	{
		m_hModule = LoadLibraryW(L"SignatureEngine.dll");
	}

	bool SignatureCheck(CString strFile)
	{
		int nRet = FALSE;
		if (m_hModule != NULL)
		{
			fpSignatureCheck func = (fpSignatureCheck)GetProcAddress(m_hModule, "sigengine");
			if(func != NULL)
			{
				_tprintf(_T("SignatureCheck(CString) load dll success, file path : %s\n"),strFile);
				nRet = func(strFile);
			}
		}

		return nRet;

	}
};
#endif
