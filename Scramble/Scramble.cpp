#include "stdafx.h"
#include "EncryptDecrypt.h"
#include <iostream>
#include <algorithm>
#include <string>

using namespace std;

enum RequestedOp
{
	OP_UNDEFINED = 0,
	OP_ENCRYPT,
	OP_DECRYPT
};

struct CommandLineOptions
{
	RequestedOp operation = RequestedOp::OP_UNDEFINED;
	bool processFolders = false;
	wstring targetPath;
	wstring password;
};

bool ParseCommandLineArgs(int argc, PWSTR argv[], CommandLineOptions &options)
{
	for (int i = 1; i < argc; i++)
	{
		wstring arg(argv[i]);
		transform(arg.begin(), arg.end(), arg.begin(), ::tolower);

		if (arg == L"enc")
		{
			if (options.operation == RequestedOp::OP_UNDEFINED)
			{
				options.operation = RequestedOp::OP_ENCRYPT;
			}
			else
			{
				wcout << L"Only one of ENC|DEC supported." << endl;
				return false;
			}
		}
		else if (arg == L"dec")
		{
			if (options.operation == RequestedOp::OP_UNDEFINED)
			{
				options.operation = RequestedOp::OP_DECRYPT;
			}
			else
			{
				wcout << L"Only one of ENC|DEC supported." << endl;
				return false;
			}
		}
		else if (arg == L"-f")
		{
			if (options.targetPath.empty())
			{
				if (i + 1 < argc)
				{
					options.targetPath = argv[++i];
					options.processFolders = false;
				}
				else
				{
					wcout << L"Missing argument for switch " << arg << endl;
					return false;
				}
			}
			else
			{
				wcout << L"Path already specified (" << options.targetPath << ")" << endl;
				return false;
			}
		}
		else if (arg == L"-p")
		{
			if (options.targetPath.empty())
			{
				if (i + 1 < argc)
				{
					options.targetPath = argv[++i];
					options.processFolders = true;
				}
				else
				{
					wcout << L"Missing argument for switch " << arg << endl;
					return false;
				}
			}
			else
			{
				wcout << L"Path already specified (" << options.targetPath << ")" << endl;
				return false;
			}
		}
		else if (arg == L"-pw")
		{
			if (options.password.empty())
			{
				if (i + 1 < argc)
				{
					options.password = argv[++i];
				}
				else
				{
					wcout << L"Missing argument for switch " << arg << endl;
					return false;
				}
			}
			else
			{
				wcout << L"Password specified more than once" << endl;
				return false;
			}
		}
	}

	// Validate all parameters have been specified
	if (options.operation == RequestedOp::OP_UNDEFINED ||
		options.targetPath.empty() ||
		options.password.empty())
	{
		wcout << L"One or more required parameters has not been specified." << endl;
		return false;
	}

	return true;
}

void PrintUsage(PCWSTR exeName)
{
	wcout << exeName << L" [ENC|DEC] [-f <filename> | -p <path>] -pw <password>";
}

int wmain(int argc, PWSTR argv[])
{
	// EnumerateProviders();
	CommandLineOptions options;
	if (!ParseCommandLineArgs(argc, argv, options))
	{
		PrintUsage(argv[0]);
		return 100;
	}

	wcout << L"Enter your password again: ";
	wstring passwordConfirmation;
	getline(wcin, passwordConfirmation);

	if (options.password != passwordConfirmation)
	{
		wcout << L"Password mismatch!" << endl;
		return 200;
	}

	const int CURRENT_VERSION = 1;

	if (options.operation == RequestedOp::OP_ENCRYPT)
	{
		Encrypt(CURRENT_VERSION, options.targetPath.c_str(), options.password.c_str());
	}


	Decrypt(CURRENT_VERSION, GetEncryptedFilename(argv[1]).c_str(), L"Blah" /* argv[1] */);
	return 0;
}

