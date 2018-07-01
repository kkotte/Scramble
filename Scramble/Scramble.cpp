#include "stdafx.h"
#include "EncryptDecrypt.h"
#include <filesystem>

using namespace std;
namespace fs = experimental::filesystem::v1;

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
	bool processSubfolders = false;
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
		else if (arg == L"-r")
		{
			options.processSubfolders = true;
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
	wcout << exeName << L" [ENC|DEC] [-f <filename> | -p <path>] [-r] -pw <password>";
}

#if 0
bool ForEachFileInFolder(fs::path foldername, bool processSubfolders, std::function<bool(PCWSTR filename)> pred)
{
	std::unique_ptr<void, decltype(&::FindClose)> findHandle{ nullptr, ::FindClose };
	WIN32_FIND_DATA fileData;

	findHandle.reset(FindFirstFile(foldername, &fileData));

	if (findHandle.get() == INVALID_HANDLE_VALUE)
	{
		wcout << L"Could not open folder [" << foldername << L"]" << endl;
		return false;
	}

	// Iterate through all file and subfolders
	do
	{
		if ((fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && processSubfolders)
		{
			// Recurse into this subfolder
			ForEachFileInFolder(fileData.cFileName, processSubfolders, pred);
		}
		else
		{
			if (!pred(fileData.cFileName))
			{
				return false;
			}
		}
	} while (FindNextFile(findHandle.get(), &fileData) != 0);

	if (GetLastError() != ERROR_NO_MORE_FILES)
	{
		wcout << L"Error enumerating files." << endl;
		return false;
	}
	return true;
}
#endif

bool ForEachTargetFile(CommandLineOptions &options, std::function<bool(const wstring &filename)> &&pred)
{
	if (!options.processFolders)
	{
		// Processing just a single file
		return pred(options.targetPath);
	}
	else // Processing folders
	{
		if (options.processSubfolders)
		{
			for (auto &p : fs::directory_iterator(options.targetPath))
			{
				if (fs::status(p.path()).type() == fs::file_type::regular)
				{
					if (!pred(p.path()))
					{
						return false;
					}
				}
			}
		}
		else
		{
			for (auto &p : fs::recursive_directory_iterator(options.targetPath))
			{
				if (fs::status(p.path()).type() == fs::file_type::regular)
				{
					if (!pred(p.path()))
					{
						return false;
					}
				}
			}
		}
	}

	return true;
}

bool FilesAreIdentical(const std::wstring &file1, const std::wstring &file2)
{
	std::ifstream inputFile1(file1, std::ios::binary);
	if (!inputFile1.is_open())
	{
		wcout << L"Error opening file: " << file1 << endl;
		return false;
	}

	std::ifstream inputFile2(file2, std::ios::binary);
	if (!inputFile2.is_open())
	{
		wcout << L"Error opening file: " << file2 << endl;
		return false;
	}

	// Work in units of about a page
	char buffer1[4096];
	char buffer2[sizeof(buffer1)];

	std::streamsize bytesRead1 = 0, bytesRead2 = 0;
	DWORD dwFlags = 0;
	do
	{
		bytesRead1 = inputFile1.read(buffer1, sizeof(buffer1)).gcount();
		bytesRead2 = inputFile2.read(buffer2, sizeof(buffer2)).gcount();

		if (bytesRead1 != bytesRead2)
		{
			return false;
		}

		if (memcmp(buffer1, buffer2, (size_t)bytesRead1) != 0)
		{
			return false;
		}

	} while (bytesRead1 > 0);

	return true;
}

const wstring EncryptExtension = L".enc";
wstring GetEncryptedFilename(wstring inputFilename)
{
	wstring temp = inputFilename;
	std::size_t found = temp.find_last_of(L".");

	return (found == string::npos) ? temp + EncryptExtension
		: temp.substr(0, found) + EncryptExtension + temp.substr(found);
}

bool IsEncryptedFilename(wstring inputFilename)
{
	return (inputFilename.find(EncryptExtension) != string::npos);
}

wstring GetDecryptedFilename(wstring inputFilename)
{
	return inputFilename.replace(inputFilename.find(EncryptExtension), EncryptExtension.length(), L"");
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

	const int CURRENT_VERSION = 1;

	if (options.operation == RequestedOp::OP_ENCRYPT)
	{
		wcout << L"Enter your password again: ";
		wstring passwordConfirmation;
		getline(wcin, passwordConfirmation);

		if (options.password != passwordConfirmation)
		{
			wcout << L"Password mismatch!" << endl;
			return 200;
		}

	}

	bool succeeded = ForEachTargetFile(options, [&](const wstring &filename)
	{
		switch (options.operation)
		{
		case OP_ENCRYPT:
			{
				wcout << L"Encypting [" << filename << L"]...";
				const wstring encryptedFilename = GetEncryptedFilename(filename);
				Encrypt(CURRENT_VERSION, filename, options.password, encryptedFilename);
				wcout << L"Verifying...";
				const wstring tempDecryptedFilename = encryptedFilename + L"dec.temp";
				Decrypt(CURRENT_VERSION, encryptedFilename, options.password, tempDecryptedFilename);

				// File compare source and original
				if (!FilesAreIdentical(filename, tempDecryptedFilename))
				{
					wcout << L"**ERROR** Encrypting and decrypting [" << filename << L"] does not give back the same file!!" << endl;
					return false;
				}
				else
				{
					wcout << L"Done." << endl;
					fs::remove(tempDecryptedFilename);
				}
			}
			break;
		
		case OP_DECRYPT:
			{
				wcout << L"Decypting [" << filename << L"]...";
				if (IsEncryptedFilename(filename))
				{
					Decrypt(CURRENT_VERSION, filename, options.password, GetDecryptedFilename(filename));
					wcout << L"Done." << endl;
				}
				else
				{
					wcout << L"Does not appear to be an encypted file. Skipping..." << endl;
				}
			}
			break;
		}
		return true;
	});

	if (!succeeded)
	{
		wcout << L"Error !!" << endl;
		return 300;
	}

	return 0;
}

