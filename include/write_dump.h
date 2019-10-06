#pragma once
#pragma warning(push)
#pragma warning(disable:4091)
#include <dbghelp.h>
#pragma warning(pop)

extern "C"
{

__declspec( dllexport )
DWORD InitializeDump(const WCHAR *dumpFolder, const WCHAR *prefix, const WCHAR *suffix, const DWORD Version[4], UINT terminatingReturnCode);

__declspec( dllexport ) bool WriteFullDump();
__declspec( dllexport ) bool WriteMiniDump();
__declspec( dllexport ) bool WriteTinyDump();

__declspec( dllexport ) bool WriteFullDumpEx(EXCEPTION_POINTERS *ExceptionPointers);
__declspec( dllexport ) bool WriteMiniDumpEx(EXCEPTION_POINTERS *ExceptionPointers);
__declspec( dllexport ) bool WriteTinyDumpEx(EXCEPTION_POINTERS *ExceptionPointers);
__declspec( dllexport ) bool WriteAllDumpsEx(EXCEPTION_POINTERS *ExceptionPointers);
//////////////////////////////////////////////////////////////////////////////////////

typedef DWORD (*PFN_InitializeDump)(const WCHAR *dumpFolder, const WCHAR *prefix, const WCHAR *suffix, const DWORD Version[4], UINT terminatingReturnCode);
typedef bool (*PFN_WriteFullDump)();
typedef bool (*PFN_WriteMiniDump)();
typedef bool (*PFN_WriteTinyDump)();

typedef bool (*PFN_WriteFullDumpEx)(EXCEPTION_POINTERS *ExceptionPointers);
typedef bool (*PFN_WriteMiniDumpEx)(EXCEPTION_POINTERS *ExceptionPointers);
typedef bool (*PFN_WriteTinyDumpEx)(EXCEPTION_POINTERS *ExceptionPointers);
typedef bool (*PFN_WriteAllDumpsEx)(EXCEPTION_POINTERS *ExceptionPointers);


// special exception codes for asserts
#define EXCEPTION_ASSERT_FULL 0xacce0001
#define EXCEPTION_ASSERT_MINI 0xacce0002
#define EXCEPTION_ASSERT_TINY 0xacce0003

// special exception codes for fatal errors
#define EXCEPTION_FATAL_FULL 0xdead0001
#define EXCEPTION_FATAL_MINI 0xdead0002
#define EXCEPTION_FATAL_TINY 0xdead0003

// for example to write tiny dump and continue execution
//	__try
//	{
//		RaiseException(EXCEPTION_DUMPWRITER_WRITE_TINY_DUMP, 0, 0, NULL);
//	}
//	__except(EXCEPTION_CONTINUE_EXECUTION)
//	{
//	}

}
