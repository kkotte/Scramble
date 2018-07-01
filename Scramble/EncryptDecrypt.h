#pragma once
#include "windows.h"
#include <string>

HRESULT EnumerateProviders();
HRESULT Encrypt(int version, const std::wstring &filename, const std::wstring &password, const std::wstring &outputFilename);
HRESULT Decrypt(int version, const std::wstring &filename, const std::wstring &password, const std::wstring &outputFilename);
