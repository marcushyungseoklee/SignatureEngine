//
// Copyright (C) 2019 Marcushslee
//

#include "SignatureEngine.h"

#pragma comment(lib,"shlwapi")

BOOL APIENTRY DllMain( HMODULE hModule,
					   DWORD uI_reason_for_call,
					   LPVOID lpReserved
					 )
{
	switch(uI_reason_for_call)
	{

	case DLL_PROCESS_ATTACH:
		_tprintf(_T("dll process attach - signature\n"));
		_tsetlocale(LC_ALL,_T("korean"));

	case DLL_THREAD_ATTACH:
		_tprintf(_T("dll thread attach\n"));

	case DLL_THREAD_DETACH:
		_tprintf(_T("dll thread detach\n"));

	case DLL_PROCESS_DETACH:
		_tprintf(_T("dll process detach\n"));
		break;
	}
	return TRUE;
}


DLL_EXPORTING_API INT	sigengine(CString strFile)
{
	FILE_SIGNATURE	signature;
	INT		result;

	_tprintf(_T("sigengine = %s\n"),strFile);
	myOutputDebugString(_T("sigengine = %s\n"),strFile);
	result = findFileFormat(strFile,signature);

	switch(result)
	{
	case FILE_NOT_EXIST:
		_tprintf(_T("file not exist\n"));
		myOutputDebugString(_T("file not exist\n"));
		break;
	case EXT_NOT_EXIST:
		_tprintf(_T("ext not exist\n"));
		myOutputDebugString(_T("ext not exist in signature header\n"));
		break;
	case NORMAL_FILE:
		_tprintf(_T("normal\n"));
		myOutputDebugString(_T("normal\n"));
		break;
	case MISMATCH:
		_tprintf(_T("mismatch\n"));
		myOutputDebugString(_T("mismatch(encrypted)\n"));
		break;
	case CAN_NOT_OPEN_FILE:
		_tprintf(_T("CAN_NOT_OPEN_FILE\n"));
		myOutputDebugString(_T("CAN_NOT_OPEN_FILE\n"));
		break;
	default:
		myOutputDebugString(_T("error\n"));
		break;
	}

	if((result == MISMATCH)
		|| (result == EXT_NOT_EXIST))
		result = FALSE;
	else
		result = TRUE;

	return result;
}

INT		findFileFormat(IN CString strfilePath,OUT FILE_SIGNATURE &signature)
{
	CString ext;
	CString exit = _T("Unicode XML File");
	INT i = 0;
	INT result = EXT_NOT_EXIST;

	if( FALSE == findExtension(strfilePath, ext) )
	{
		return FILE_NOT_EXIST;
	}

	do
	{
		if( 0 == ext.CompareNoCase(g_FileSignatures[i].strExt) )
		{
			signature = g_FileSignatures[i];
			result = compareSignature(signature,strfilePath);
			if( result == (INT)TRUE )
			{
				break;
			}
		}
		i++;
	}while( 0 != exit.CompareNoCase(g_FileSignatures[i].strInfo) );

	return result;
}

BOOL	findExtension(IN CString strfilePath, OUT CString &ext)
{
	if( FALSE == PathFileExists(strfilePath) )
	{
		_tprintf(_T("not exist file, file path = %s\n"),(LPCSTR)(LPCTSTR)strfilePath);
		myOutputDebugString(_T("not exist file, file path = %s\n"),(LPCSTR)(LPCTSTR)strfilePath);
		return FALSE;
	}

	ext = PathFindExtension(strfilePath);
	ext = ext.Right(ext.GetLength() -1);

	return TRUE;
}

INT		compareSignature(IN FILE_SIGNATURE signature,IN CString strfilePath)
{
	INT		byte_count = signature.iSize;
	BYTE*	byte = new BYTE[byte_count];
	FILE*	file;
	BOOL	result;

	//_tfopen_s(&file,strfilePath.GetBuffer(0),_T("rb"));
	file = _tfopen(strfilePath.GetBuffer(0),_T("rb"));

	if(file == NULL)
	{
		_tprintf(_T("[compareSignature]can not open file\n"));
		myOutputDebugString(_T("[compareSignature]can not open file\n"));
		return CAN_NOT_OPEN_FILE;
	}
	else
	{
		rewind(file);
		fread(byte,sizeof(BYTE),byte_count,file);
	}

	result = memcmp(byte,signature.Signature,byte_count);

	/* log */
	_tprintf(_T("byte: "));
	myOutputDebugString(_T("byte: "));
	for(int i=0;i<byte_count;i++)
	{
		_tprintf(_T("%02X,"),byte[i]);
		myOutputDebugString(_T("%02X,"),byte[i]);
	}
	_tprintf(_T("\n"));
	myOutputDebugString(_T("\n"));

	fclose(file);

	if( result != 0 )
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}
VOID	myOutputDebugString(LPCTSTR pszStr,...)
{
	TCHAR szMsg[MAX_FILE_SIZE];
	va_list args;
	va_start(args,pszStr);
	_vstprintf_s(szMsg,MAX_FILE_SIZE,pszStr,args);
	OutputDebugString(szMsg);
}
