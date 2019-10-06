#include <windows.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <algorithm>
#include <time.h>

#include "../include/write_dump.h"
#include "make_name.h"


typedef std::basic_string<TCHAR> tstring;

#define MIN_FREE_SPACE 200

const MINIDUMP_TYPE MiniDumpMini = 
	MINIDUMP_TYPE(MiniDumpWithDataSegs
				  | MiniDumpWithUnloadedModules
				  | MiniDumpWithProcessThreadData
				  | MiniDumpWithThreadInfo
				  );

const MINIDUMP_TYPE MiniDumpFull = 
	MINIDUMP_TYPE(MiniDumpWithFullMemory
				  | MiniDumpWithUnloadedModules
				  | MiniDumpWithProcessThreadData
				  | MiniDumpWithFullMemoryInfo
				  | MiniDumpWithThreadInfo
				  | MiniDumpWithHandleData
				  | MiniDumpWithTokenInformation
				  );

extern TCHAR *g_suffix;


class LogFile
{	HANDLE m_hFile;
public:
	LogFile();
	LogFile(LPCTSTR folder);
	~LogFile();
	void Write( const TCHAR* msg, ... );
};

LogFile::LogFile() : m_hFile(INVALID_HANDLE_VALUE) {}

LogFile::LogFile(LPCTSTR folder)
{
	tstring log = folder;
	log += _T("\\write_dump.log");
	m_hFile = CreateFile( log.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_FLAG_WRITE_THROUGH | FILE_ATTRIBUTE_HIDDEN, NULL );
	TCHAR timeBuffer[128];
	time_t now = time(NULL);
	_tctime_s(timeBuffer, _countof(timeBuffer), &now);
	Write(_T("------------------------------------------------------------------\r\n%s\r\n"), timeBuffer);
}

LogFile::~LogFile() { if(INVALID_HANDLE_VALUE != m_hFile) CloseHandle(m_hFile); }

void LogFile::Write( const TCHAR* msg, ... ) 
{
	if( INVALID_HANDLE_VALUE == m_hFile )
		return;

	va_list ap;
	va_start(ap, msg);
	TCHAR text[512];
	_vsntprintf_s(text, _countof(text), _TRUNCATE, msg, ap);
	va_end(ap);

	const DWORD sizeInBytes = 
		static_cast< DWORD >( _tcslen(text) * sizeof(TCHAR) );
	SetFilePointer(m_hFile, 0, NULL, FILE_END);
	DWORD written = 0;
	WriteFile(m_hFile, text, sizeInBytes, &written, NULL); 
	OutputDebugString(text);
}

namespace {
	struct FileObj
	{
		friend bool operator< (const FileObj& left, const FileObj& right);
		FILETIME m_time;
		tstring  m_name;
		FileObj( const WIN32_FIND_DATA& fd ) : m_time( fd.ftLastWriteTime ), m_name( fd.cFileName ) {}
	};
	bool operator< (const FileObj& left, const FileObj& right) { return CompareFileTime(&left.m_time, &right.m_time) == 1; }

	typedef std::vector< FileObj > Files;
	const unsigned int MAX_FILES_ALLOWED = 15;

	class Cleaner
	{
		tstring  m_sFolder;
		Files&   m_files; 
		LONGLONG m_required;
		LogFile& m_logFile;

		void deleteNextFile()
		{
			tstring sFn = m_sFolder; sFn += m_files.back().m_name;
			if( ::DeleteFile( sFn.c_str() ) )
				m_logFile.Write(_T("File %s has been deleted. \r\n"), sFn.c_str() );
			else
				m_logFile.Write(_T("Could not delete %s, system error: %d\r\n"), sFn.c_str(), GetLastError() );
			m_files.pop_back();
		}

		bool getFreeSpace( ULARGE_INTEGER& free ) const
		{
			if( 0 != GetDiskFreeSpaceEx( m_sFolder.c_str(), &free, NULL, NULL ) )
				return true;

			m_logFile.Write(_T("GetDiskFreeSpaceEx failed, system error %d\r\n"), GetLastError() );
			return false;
		}

		bool isEnoughSpace() const 
		{ 
			ULARGE_INTEGER	free;
			if( !getFreeSpace(free) || ( static_cast<LONGLONG>(free.QuadPart) < m_required ) )
				return false;

			m_logFile.Write(_T("== Successfull ==\r\n"));
			return true;
		}
	public:
		Cleaner( const tstring& sFolder, Files& files, LONGLONG required, LogFile& logFile ) 
			: m_sFolder( sFolder ), m_files(files), m_required(required), m_logFile(logFile) {}

		bool operator () ()
		{ 
			while( !m_files.empty() && ( m_files.size() > MAX_FILES_ALLOWED ) )
				deleteNextFile();
			if( isEnoughSpace() ) 	
				return true;
			while( !m_files.empty() )
			{
				deleteNextFile();
				if( isEnoughSpace() )
					return true;
			}
			m_logFile.Write(_T("== ERROR: could not free enough space ==\r\n"));
			return false;
		}
	};
}


struct DumpRequest
{
	MINIDUMP_TYPE DumpType;
	PCTSTR pszDumpPath;
	HRESULT result;
};

////////////////////////////////////////////////////////////////////////////////////////
// DbgHelp
class DbgHelp
{
public:
	explicit DbgHelp(LogFile& logFile);
	~DbgHelp();

	BOOL MiniDumpWriteDump(
		IN HANDLE hProcess,
		IN DWORD ProcessId,
		IN HANDLE hFile,
		IN MINIDUMP_TYPE DumpType,
		IN CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, OPTIONAL
		IN CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, OPTIONAL
		IN CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam OPTIONAL,
		LogFile& logFile
		);

private:
	typedef BOOL (WINAPI *fnMiniDumpWriteDump) (
		IN HANDLE hProcess,
		IN DWORD ProcessId,
		IN HANDLE hFile,
		IN MINIDUMP_TYPE DumpType,
		IN CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, OPTIONAL
		IN CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, OPTIONAL
		IN CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam OPTIONAL
		);

	HMODULE m_hDbgHelp;
	fnMiniDumpWriteDump MiniDumpWriteDumpOrig;
};

DbgHelp::DbgHelp(LogFile& logFile)
	: m_hDbgHelp(NULL)
	, MiniDumpWriteDumpOrig(NULL)
{
	m_hDbgHelp = ::LoadLibrary(_T("dbghelp.dll"));
	if (m_hDbgHelp)
		logFile.Write(_T("Load of dbghelp.dll succeeded\r\n"));
	else
		logFile.Write(_T("Load of dbghelp.dll failed (err %d)\r\n"), GetLastError());
	if( m_hDbgHelp )
	{
		MiniDumpWriteDumpOrig = (fnMiniDumpWriteDump)::GetProcAddress(m_hDbgHelp, "MiniDumpWriteDump");
		if (!MiniDumpWriteDumpOrig)
			logFile.Write(_T("Failed to get MiniDumpWriteDump (err %d)\r\n"), GetLastError());
	}
}

DbgHelp::~DbgHelp()
{
	if( m_hDbgHelp )
	{
		::FreeLibrary(m_hDbgHelp);
	}
}

BOOL DbgHelp::MiniDumpWriteDump(
	IN HANDLE hProcess,
	IN DWORD ProcessId,
	IN HANDLE hFile,
	IN MINIDUMP_TYPE DumpType,
	IN CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, OPTIONAL
	IN CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, OPTIONAL
	IN CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam OPTIONAL,
	LogFile& logFile
	)
{
	if (!MiniDumpWriteDumpOrig)
	{
		logFile.Write(_T("No dbgHelp.MiniDumpWriteDump\r\n"));
		return false;
	}

	static const DWORD dbgHelp51pTypeMask = 0xc01f;
	static const DWORD dbgHelp60DumpTypeMask = 0xc2ff;
	static const DWORD dbgHelp61DumpTypeMask = 0x1fc2ff;
	static const DWORD dumpTypeMasks[] = {
		dbgHelp51pTypeMask,
		dbgHelp60DumpTypeMask,
		dbgHelp61DumpTypeMask,
		MiniDumpValidTypeFlags
	};

	BOOL result = false;
	DWORD dumpType = static_cast<DWORD>(DumpType);
	for (int i = _countof(dumpTypeMasks) - 1; i >= 0; --i)
	{
		dumpType &= dumpTypeMasks[i];
		logFile.Write(_T("[MiniDumpWriteDump] Use '0x%x' dump type\r\n"), dumpType);
		result = MiniDumpWriteDumpOrig(hProcess, ProcessId, hFile, static_cast<MINIDUMP_TYPE>(dumpType), ExceptionParam, UserStreamParam, CallbackParam);
		if (!result && E_INVALIDARG == ::GetLastError())
			logFile.Write(_T("[MiniDumpWriteDump] Failed to write mini dump with '0x%x' dump type, error = '0x%x' \r\n"), dumpType, E_INVALIDARG);
		else
			break;
	}

	return result;
}

class CUseSelfAccount
{
	HANDLE hToken;
public:
	CUseSelfAccount(): hToken(NULL)
	{
		OpenThreadToken (GetCurrentThread (), TOKEN_IMPERSONATE, TRUE, &hToken);
		RevertToSelf ();
	}
	~CUseSelfAccount()
	{
		if (hToken)
		{
			SetThreadToken (NULL, hToken);
			CloseHandle (hToken);
		}
	}
};


static bool WriteDumpWorker (LogFile& logFile, DbgHelp& dbgHelp, PCWSTR pszDumpPath, MINIDUMP_TYPE DumpType, HANDLE hProcess, DWORD dwProcessId,
	DWORD dwThreadId, EXCEPTION_POINTERS* pExceptionPointers, BOOL bClientPointers)
{
	logFile.Write(_T("Writing %ls...\r\n"), pszDumpPath);

	bool result = false;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	do
	{
		hFile = CreateFileW(pszDumpPath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			logFile.Write(_T("Failed to CreateFile(\"%ls\"). 0x%.08lX\r\n"), pszDumpPath, ::GetLastError());
			break;
		}

		MINIDUMP_EXCEPTION_INFORMATION mexi;
		mexi.ThreadId = dwThreadId;
		mexi.ExceptionPointers = pExceptionPointers;
		mexi.ClientPointers = bClientPointers;

		BOOL ok = dbgHelp.MiniDumpWriteDump (
			hProcess,
			dwProcessId,
			hFile,
			DumpType,
			pExceptionPointers ? &mexi : NULL,
			NULL,
			NULL,
			logFile);
		if( !ok )
		{
			logFile.Write(_T("MiniDumpWriteDump failed (err 0x%X)\r\n"), GetLastError());
			break;
		}

		DWORD size = GetFileSize(hFile, NULL);
		if( size == INVALID_FILE_SIZE )
		{
			logFile.Write(_T("GetFileSize failed (err %d)\r\n"), GetLastError());
			break;
		}

		result = true;
		logFile.Write(_T("Writing %ls succeeded (%d bytes).\r\n"), pszDumpPath, size);
	}
	while( false );

	return result;
}

static bool WriteSingleDump(EXCEPTION_POINTERS *ExceptionPointers, MINIDUMP_TYPE DumpType)
{
	TCHAR pszSuffix[16];

	static DWORD id = 0;
	_ultot_s(id++, pszSuffix, _countof(pszSuffix), 10);

	std::wstring dumpPath;
	try
	{
		switch (DumpType)
		{
		case MiniDumpNormal:
			dumpPath = MakeSpecialName(pszSuffix, _T("tiny.dmp"));
			break;
		case MiniDumpMini:
			dumpPath = MakeSpecialName(pszSuffix, _T("mini.dmp"));
			break;
		case MiniDumpFull:
			dumpPath = MakeSpecialName(pszSuffix, _T("full.dmp"));
			break;
		default:
			dumpPath = MakeSpecialName(pszSuffix, _T("unkn.dmp"));
			break;
		}
	}
	catch (const std::exception&)
	{ }


	LogFile logFile;
	return WriteDumpWorker(logFile, DbgHelp(logFile), dumpPath.c_str(), DumpType,
		GetCurrentProcess(), GetCurrentProcessId(), GetCurrentThreadId(), ExceptionPointers, FALSE);
}

bool CleanUpFolder(LogFile& logFile, LONGLONG nRequiredFreeSpace, LPCTSTR folder)
{
	if (!folder || !folder[0])
	{
		logFile.Write(_T("Folder name not specified\r\n"));
		return false;
	}

	tstring sFolder(folder);
	size_t nLen = sFolder.size();
	if ( sFolder.c_str()[nLen-1] != _T('\\'))
		sFolder += _T('\\');

	tstring sFileMask = sFolder; sFileMask+= _T("*.dmp");
	logFile.Write(_T("Search file mask: '%s'\r\n"), sFileMask.c_str() );

	Files files;
	const DWORD dwSkipMask = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_READONLY;
	WIN32_FIND_DATA fd;
	HANDLE h = ::FindFirstFile( sFileMask.c_str(), &fd);
	if ( INVALID_HANDLE_VALUE != h )
	{
		do
		{ 
			if (!(fd.dwFileAttributes & dwSkipMask))
				files.push_back(FileObj(fd));
		} 
		while (::FindNextFile(h,&fd));
		::FindClose(h);
	}
	else 
		logFile.Write(_T("no dump files were found\r\n"));
	if( !files.empty() ) 
		std::sort( files.begin(), files.end() );

	return Cleaner( sFolder, files, nRequiredFreeSpace, logFile)();
}


extern "C" {
	void * _ReturnAddress(void);
#pragma intrinsic(_ReturnAddress)

#ifdef _X86_
	void * _AddressOfReturnAddress(void);
#pragma intrinsic(_AddressOfReturnAddress)
#endif  /* _X86_ */
}

static bool WriteSingleDump(MINIDUMP_TYPE minidump_type)
{
	EXCEPTION_RECORD ExceptionRecord;
	CONTEXT ContextRecord;
	EXCEPTION_POINTERS ExceptionPointers;

#ifdef _X86_

	__asm {
		mov dword ptr [ContextRecord.Eax], eax
			mov dword ptr [ContextRecord.Ecx], ecx
			mov dword ptr [ContextRecord.Edx], edx
			mov dword ptr [ContextRecord.Ebx], ebx
			mov dword ptr [ContextRecord.Esi], esi
			mov dword ptr [ContextRecord.Edi], edi
			mov word ptr [ContextRecord.SegSs], ss
			mov word ptr [ContextRecord.SegCs], cs
			mov word ptr [ContextRecord.SegDs], ds
			mov word ptr [ContextRecord.SegEs], es
			mov word ptr [ContextRecord.SegFs], fs
			mov word ptr [ContextRecord.SegGs], gs
			pushfd
			pop [ContextRecord.EFlags]
	}

	ContextRecord.ContextFlags = CONTEXT_CONTROL;
#pragma warning(push)
#pragma warning(disable:4311)
	ContextRecord.Eip = (ULONG)_ReturnAddress();
	ContextRecord.Esp = (ULONG)_AddressOfReturnAddress();
#pragma warning(pop)
	ContextRecord.Ebp = *((ULONG *)_AddressOfReturnAddress()-1);

#elif defined (_IA64_) || defined (_AMD64_)

	/* Need to fill up the Context in IA64 and AMD64. */
	RtlCaptureContext(&ContextRecord);

#else  /* defined (_IA64_) || defined (_AMD64_) */

	ZeroMemory(&ContextRecord, sizeof(ContextRecord));

#endif  /* defined (_IA64_) || defined (_AMD64_) */

	ZeroMemory(&ExceptionRecord, sizeof(ExceptionRecord));

	ExceptionRecord.ExceptionCode = EXCEPTION_FATAL_MINI;
	ExceptionRecord.ExceptionAddress = _ReturnAddress();

	ExceptionPointers.ExceptionRecord = &ExceptionRecord;
	ExceptionPointers.ContextRecord = &ContextRecord;

	return WriteSingleDump(&ExceptionPointers, minidump_type);
}

bool WriteAllDumpsImpl(EXCEPTION_POINTERS *ExceptionPointers)
try
{
	const wchar_t* DumpsPath = GetSpecialDir().c_str();

	LogFile logFile(DumpsPath);

	CUseSelfAccount self;

	const std::wstring tinyPath = MakeSpecialName(_T(""), _T("tiny.dmp"));
	const std::wstring miniPath = MakeSpecialName(_T(""), _T("mini.dmp"));
	const std::wstring fullPath = MakeSpecialName(_T(""), _T("full.dmp"));

	DumpRequest requests[] = 
	{
		{ MiniDumpNormal, tinyPath.c_str(), E_FAIL },
		{ MiniDumpMini, miniPath.c_str(), E_FAIL },
		{ MiniDumpFull, fullPath.c_str(), E_FAIL },
	};

	DWORD dwRequestCount = _countof(requests);

	bool bSpaceEnough = CleanUpFolder(logFile, MIN_FREE_SPACE, DumpsPath);

	if ( !bSpaceEnough ) dwRequestCount = 1;

	DbgHelp dbgHelp(logFile);
	for( DWORD i = 0; i < dwRequestCount; ++i )
	{
		DumpRequest& Request = requests[i];
		if( WriteDumpWorker (
			logFile,
			dbgHelp,
			Request.pszDumpPath,
			Request.DumpType,
			GetCurrentProcess(),
			GetCurrentProcessId(),
			GetCurrentThreadId(),
			ExceptionPointers,
			FALSE
			) )
		{
			Request.result = S_OK;
		}
	}

	for( DWORD i = 0; i < dwRequestCount; ++i )
	{
		if( SUCCEEDED(requests[i].result) )
		{
			return true;
		}
	}

	return false;
}
catch (const std::exception&)
{
	return false;
}

extern "C" __declspec( dllexport )
bool WriteFullDump()
{
	return WriteSingleDump(MiniDumpFull);
}

extern "C" __declspec(dllexport)
bool WriteMiniDump()
{
	return WriteSingleDump(MiniDumpMini);
}

extern "C" __declspec(dllexport)
bool WriteTinyDump()
{
	return WriteSingleDump(MiniDumpNormal);
}

extern "C" __declspec( dllexport )
bool WriteFullDumpEx(EXCEPTION_POINTERS *ExceptionPointers)
{
	return WriteSingleDump(ExceptionPointers, MiniDumpFull);
}

extern "C" __declspec(dllexport)
bool WriteMiniDumpEx(EXCEPTION_POINTERS *ExceptionPointers)
{
	return WriteSingleDump(ExceptionPointers, MiniDumpMini);
}

extern "C" __declspec(dllexport)
bool WriteTinyDumpEx(EXCEPTION_POINTERS *ExceptionPointers)
{
	return WriteSingleDump(ExceptionPointers, MiniDumpNormal);
}

extern "C" __declspec( dllexport )
bool WriteAllDumpsEx(EXCEPTION_POINTERS *ExceptionPointers)
{
	return WriteAllDumpsImpl(ExceptionPointers);
}
