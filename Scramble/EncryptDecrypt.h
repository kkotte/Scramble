#pragma once
#include "windows.h"
#include <string>

HRESULT EnumerateProviders();
HRESULT GetSymmetricKey(int version, PCWSTR password, PBYTE symmetricKey, int symmetricKeyLen);
HRESULT Encrypt(int version, PCWSTR filename, PCWSTR password);
HRESULT Decrypt(int version, PCWSTR filename, PCWSTR password);
std::wstring GetEncryptedFilename(std::wstring inputFilename);
