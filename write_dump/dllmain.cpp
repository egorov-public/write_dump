#ifndef _WIN32_WINNT
# define _WIN32_WINNT 0x0501
#endif

#include <windows.h>
#include <tchar.h>
#include <string>
#include <queue>
#include "../include/write_dump.h"
#include "make_name.h"
#include <signal.h>

static LPTOP_LEVEL_EXCEPTION_FILTER g_pPrevExceptionFilter = NULL;
static UINT g_TerminateAfterExceptionCode = 0;

// parameters
extern std::wstring g_dumpFolder;
extern std::wstring g_prefix;
extern std::wstring g_suffix;
extern DWORD g_dwVersion[4];

#define NOACTIVEUNHANDLEDEXCEPTION	-1

namespace
{
static LONG UnhandledExceptionInThreadId = NOACTIVEUNHANDLEDEXCEPTION;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		break;
	}
	return TRUE;
}

static bool CheckInPageError(EXCEPTION_POINTERS *ExceptionPointers)
{
#define INPAGEERROR_EXCEPT_ONE_SLEEP_DELAY	100
#define INPAGEERROR_EXCEPT_CONTINUE_DELAY	20000

	static PVOID LastExceptionAddress = 0;
	static UINT ExceptionCount = 0;

	if(!ExceptionPointers || !ExceptionPointers->ExceptionRecord)
		return false;

	if (ExceptionPointers->ExceptionRecord->ExceptionCode == EXCEPTION_IN_PAGE_ERROR)
	{
		if (LastExceptionAddress != ExceptionPointers->ExceptionRecord->ExceptionAddress)
		{
			// new exception
			ExceptionCount = 0;
			LastExceptionAddress = ExceptionPointers->ExceptionRecord->ExceptionAddress;
		}
		if (ExceptionCount < (INPAGEERROR_EXCEPT_CONTINUE_DELAY / INPAGEERROR_EXCEPT_ONE_SLEEP_DELAY))
		{
			ExceptionCount++;
			Sleep (INPAGEERROR_EXCEPT_ONE_SLEEP_DELAY);
			return true;
		}
	}
	return false;
}

static DWORD WINAPI WriteMiniDumpThread(LPVOID lpParameter)
{
	return WriteAllDumpsEx((EXCEPTION_POINTERS*)lpParameter) ? TRUE : FALSE;
}

static LONG WINAPI TopLevelExceptionFilter(EXCEPTION_POINTERS *ExceptionPointers)
{
	if(CheckInPageError(ExceptionPointers))
		return EXCEPTION_CONTINUE_EXECUTION;

	{// only first crash will be written
		const DWORD currentThreadId = GetCurrentThreadId();
		const LONG currentProcessedThreadId = InterlockedCompareExchange(&UnhandledExceptionInThreadId, currentThreadId, NOACTIVEUNHANDLEDEXCEPTION);
		if ((currentProcessedThreadId != NOACTIVEUNHANDLEDEXCEPTION) && (currentProcessedThreadId != currentThreadId))
		{
			Sleep(120000);
			return EXCEPTION_CONTINUE_SEARCH;
		}
	}

	static DWORD bWriteMiniDumpRes = FALSE;
	static DWORD dummy;
	static HANDLE hThread;

	if (ExceptionPointers != NULL
		&& ExceptionPointers->ExceptionRecord != NULL
		&& ExceptionPointers->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW
		&& (hThread = CreateThread(NULL, 0, WriteMiniDumpThread, ExceptionPointers, 0, &dummy)) != NULL)
	{// stack overflow should be written in another thread
		WaitForSingleObject(hThread, INFINITE);
		GetExitCodeThread(hThread, &bWriteMiniDumpRes);
	}
	else
	{
		bWriteMiniDumpRes = WriteAllDumpsEx(ExceptionPointers) ? TRUE : FALSE;
	}

	InterlockedExchange(&UnhandledExceptionInThreadId, NOACTIVEUNHANDLEDEXCEPTION);
	return EXCEPTION_EXECUTE_HANDLER;
}

static void FreezeException()
{
	SuspendThread(GetCurrentThread());
}

static bool ProcessSpecialException(DWORD type, PEXCEPTION_POINTERS pExceptionInfo)
{
	if (UnhandledExceptionInThreadId != NOACTIVEUNHANDLEDEXCEPTION)
	{
		FreezeException(); // we already have unhandled exception
		return false;
	}

	switch (type)
	{
	case EXCEPTION_ASSERT_TINY:
	case EXCEPTION_FATAL_TINY:
		return WriteTinyDumpEx(pExceptionInfo);

	case EXCEPTION_ASSERT_MINI:
	case EXCEPTION_FATAL_MINI:
		return WriteMiniDumpEx(pExceptionInfo);

	case EXCEPTION_ASSERT_FULL:
	case EXCEPTION_FATAL_FULL:
		return WriteFullDumpEx(pExceptionInfo);

	default:
		return false;
	}
}

LONG CALLBACK VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
#ifdef _WIN64
# define IP_REG_NAME Rip
#else
# define IP_REG_NAME Eip
#endif

	bool exceptionContinueSearch = true;

	const DWORD type = pExceptionInfo->ExceptionRecord->ExceptionCode;
	switch (type)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		// when library is unloaded while code is executing
		// it leads to uncaught exception in TopLevelExceptionFilter
		// (Windows tries to call catch in unloaded module and fall again
		//  and again till stack is over and then terminates process)
		if (IsBadCodePtr((FARPROC)static_cast<DWORD_PTR>(pExceptionInfo->ContextRecord->IP_REG_NAME)))
		{
			// If during writing a dump we crash again in bad EIP it can lead to recursive dump writing
			// and then stack overflow.
			// The case in bug was when we has finished writing a dump we call WMI and it is crashed with bad EIP.
			// __except(EXCEPTION_EXECUTE_HANDLER) in DumpWriter!TopLevelExceptionFilter doesn't
			// help in this case because VectoredExceptionHandler is working before it.
			static bool writingVectoredException = false;
			if (writingVectoredException)
				return EXCEPTION_CONTINUE_SEARCH;
			writingVectoredException = true;
			TopLevelExceptionFilter(pExceptionInfo);
			TerminateProcess(GetCurrentProcess(), g_TerminateAfterExceptionCode);
		}
		break;


	case EXCEPTION_ASSERT_TINY:
	case EXCEPTION_ASSERT_MINI:
	case EXCEPTION_ASSERT_FULL:
		exceptionContinueSearch = false;
	case EXCEPTION_FATAL_TINY:
	case EXCEPTION_FATAL_MINI:
	case EXCEPTION_FATAL_FULL:
		ProcessSpecialException(type, pExceptionInfo);
		break;
	}

	return exceptionContinueSearch ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_CONTINUE_EXECUTION;
}

void __cdecl AbortHandler(int)
{
	RaiseException(STATUS_NONCONTINUABLE_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
	exit(0);
}

void PurecallHandler()
{
	RaiseException(STATUS_NONCONTINUABLE_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
	exit(0);
}

extern "C" __declspec( dllexport )
DWORD InitializeDump(const WCHAR *dumpFolder, const WCHAR *prefix, const WCHAR *suffix, const DWORD Version[4], UINT terminatingReturnCode)
try
{
	g_TerminateAfterExceptionCode = terminatingReturnCode;

	// copy params
	g_dumpFolder = dumpFolder ? dumpFolder : L"c:\\";

	if (prefix)
		g_prefix = prefix;
	else
		g_prefix.clear();

	if (suffix)
		g_suffix = suffix;
	else
		g_suffix.clear();

	if (Version)
		memcpy(g_dwVersion, Version, sizeof(g_dwVersion));

	g_pPrevExceptionFilter = SetUnhandledExceptionFilter(TopLevelExceptionFilter);
	AddVectoredExceptionHandler(0, VectoredExceptionHandler);
	LPCTSTR crt[] = {
		_T("msvcr80"), _T("msvcr80d"),
		_T("msvcr100"), _T("msvcr100d"),
		_T("ucrtbase"), _T("ucrtbased")
	};
	HMODULE hCrt = NULL;
	for (size_t i = 0; !hCrt && i < _countof(crt); ++i)
		hCrt = GetModuleHandle(crt[i]);
	if (hCrt)
	{
		typedef void (__cdecl *pfn_signal)(int _SigNum, void (__cdecl *_Func)(int));
		pfn_signal fn_signal = (pfn_signal) GetProcAddress(hCrt, "signal");
		if (fn_signal)			
			fn_signal(SIGABRT, AbortHandler);

		typedef _purecall_handler (__cdecl *pfn_set_purecall_handler)(_purecall_handler);
		pfn_set_purecall_handler fn_set_purecall_handler = (pfn_set_purecall_handler) GetProcAddress(hCrt, "_set_purecall_handler");
		if (fn_set_purecall_handler)
			fn_set_purecall_handler(PurecallHandler);
	}
	if (g_pPrevExceptionFilter)
		return ERROR_SUCCESS;
	else
		return ERROR_INVALID_FUNCTION;

	return ERROR_SUCCESS;
}
catch (const std::exception&)
{
	return ERROR_NOT_ENOUGH_MEMORY;
}
