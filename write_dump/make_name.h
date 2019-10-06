#ifndef __MAKE_NAME_H__
#define __MAKE_NAME_H__

#if defined (_WIN32)

#include <string>

const std::wstring& GetSpecialDir(void);
std::wstring MakeSpecialName(const std::wstring& suffix, const std::wstring& extension);

#endif //_WIN32

#endif // __MAKE_NAME_H__
