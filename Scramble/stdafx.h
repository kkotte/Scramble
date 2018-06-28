// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <iostream>
#include <algorithm>
#include <string>
#include <functional>
#include <memory>
#include <fstream>
#include <cstdio>

#include <stdio.h>
#include <tchar.h>

#define RETURN_IF_NT_FAILED(x) \
    { \
        NTSTATUS __ntstatus = (x); \
		if (!NT_SUCCESS(__ntstatus)) \
		{                           \
			wcout << "[" << #x << "]" << L" failed with " << __ntstatus << endl; \
            return HRESULT_FROM_WIN32(__ntstatus); \
		} \
    } \

#define RETURN_IF_NULL_ALLOC(x) \
    { \
		if (x == nullptr) \
		{                           \
            return E_OUTOFMEMORY; \
		} \
    } \

