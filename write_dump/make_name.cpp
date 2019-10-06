#include "make_name.h"

#include <iomanip>
#include <sstream>
#include <windows.h>

// parameters
std::wstring g_dumpFolder;
std::wstring g_prefix;
std::wstring g_suffix;
DWORD g_dwVersion[4] = {0,0,0,0};

namespace
{
struct fw // fill and width
{
	fw(const wchar_t fill, const std::streamsize width) : fill(fill), width(width)
	{ }

	const wchar_t fill;
	const std::streamsize width;
};

std::wostream& operator << (std::wostream& stream, const fw& format)
{
	stream.fill(format.fill);
	stream.width(format.width);
	return stream;
}
}

const std::wstring& GetSpecialDir(void)
{
	return g_dumpFolder;
}

// <prefix>.<version>_[month.day_hour.minute_]PID.[suffix.]extension
std::wstring MakeSpecialName(const std::wstring& suffix, const std::wstring& extension)
{
	std::wstring name;

	const wchar_t dot = L'.';

	//1. Prefix & version
	{
		std::wstringstream prefix; // %s.%i.%i.%i.%i
		prefix << g_prefix << dot << g_dwVersion[0] << dot << g_dwVersion[1] << dot << g_dwVersion[2] << dot << g_dwVersion[3];
		name = prefix.str();
	}

	const wchar_t underscore = L'_';
	name += underscore;

	const wchar_t zero = L'0';

	//3. Date
	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		std::wstringstream date; // %02d.%02d_%02d.%02d_
		const fw z2(zero, 2);
		date << z2 << st.wMonth << dot << z2 << st.wDay << underscore << z2 << st.wHour << dot << z2 << st.wMinute << underscore;
		name += date.str();
	}

	//4. Process
	{
		std::wstringstream pid; // %03d.
		pid << std::setfill(zero) << std::setw(3) << ::GetCurrentProcessId() << dot;
		name += pid.str();
	}

	// 5. Suffix
	if (!g_suffix.empty())
	{
		name += g_suffix;
		name += suffix;
		name += dot;
	}

	//6. Extension
	name += extension;

	std::wstring directory = GetSpecialDir();
	if (!directory.empty() && directory[directory.size() - 1] != L'\\')
		directory += L'\\';
	directory += name;
	return directory;
}
