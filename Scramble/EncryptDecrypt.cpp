#include <stdafx.h>
#include <windows.h>

using namespace std;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define KeyLenPair(x) \
    ARRAYSIZE(x), ##x \


UCHAR SymmetricKeyDerivationSalt_V1[] = { 12, 34, 31, 4, 65, 53, 43, 1, 12, 43 };
UCHAR iv_V1[] = {12, 32, 12 ,65, 23, 133, 43, 133, 168, 32, 131, 12, 32, 12 ,65, 23, 133, 43, 133, 168, 32, 131 };

const struct 
{
	int SymmetricKeyDerivationSaltLen;
	PUCHAR SymmetricKeyDerivationSalt;
	int SymmetricKeyDerivationIterationCount;
	int ivLength;
	PUCHAR iv;

} EncryptionParams[] = 
{
	// Version 1
	{
		KeyLenPair(SymmetricKeyDerivationSalt_V1),
		200,  // IterationCount
		KeyLenPair(iv_V1),
	}
};


template<typename T>
struct out_param_t
{
	typedef typename T::pointer PointerType;
	out_param_t(T& sp)
	: _sp(sp)
	, _raw(nullptr)
	{}

	out_param_t(out_param_t&& other)
	: _sp(other._sp)
	, _raw(other._raw)
	{
		other._replace = false;
	}

	operator PointerType *()
	{
		return &_raw;
	}

	~out_param_t()
	{
		if (_replace)
		{
			_sp.reset(_raw);
		}
	}

	T& _sp;
	PointerType _raw;
	bool _replace = true;

	out_param_t(out_param_t const &other) = delete;
	out_param_t &operator=(out_param_t const &other) = delete;
};

template<typename T>
out_param_t<T> out_param(T& sp)
{
	return out_param_t<T>(sp);
}

void PrintByteBlob(PBYTE blob, int len)
{
	wcout << "{";
	for (int i = 0; i < len; i++)
	{
		wcout << hex << blob[i];
	}

	wcout << "}" << dec << endl;
}

void BCryptAlgorithmCloser(BCRYPT_ALG_HANDLE hAlgortithm)
{
	BCryptCloseAlgorithmProvider(hAlgortithm, 0);
}
using unique_bcrypt_alg_handle = std::unique_ptr<void, decltype(&::BCryptAlgorithmCloser)>;
using unique_bcrypt_key_handle = std::unique_ptr<void, decltype(&::BCryptDestroyKey)>;

HRESULT EnumerateProviders()
{
	ULONG cbBuffer = 0;
	std::unique_ptr<CRYPT_PROVIDERS, decltype(&::BCryptFreeBuffer)> buffer{nullptr, ::BCryptFreeBuffer};
	RETURN_IF_NT_FAILED(BCryptEnumRegisteredProviders(&cbBuffer, out_param(buffer)));

	if (buffer)
	{
		// Enumerate the providers.
		for (ULONG i = 0; i < buffer->cProviders; i++)
		{
			wcout << buffer->rgpszProviders[i] << endl;
		}
	}

	std::unique_ptr<CRYPT_PROVIDER_REG, decltype(&::BCryptFreeBuffer)> providerReg{ nullptr, ::BCryptFreeBuffer };
	RETURN_IF_NT_FAILED(BCryptQueryProviderRegistration(MS_PRIMITIVE_PROVIDER, CRYPT_UM, BCRYPT_CIPHER_INTERFACE, &cbBuffer, out_param(providerReg)));

	for (unsigned i = 0; i < providerReg->pUM->rgpInterfaces[0]->cFunctions; i++)
	{
		wcout << providerReg->pUM->rgpInterfaces[0]->rgpszFunctions[i] << endl;
	}

	return S_OK;
}

HRESULT GetSymmetricKey(int version, PCWSTR password, PBYTE symmetricKey, int symmetricKeyLen)
{
	// Select the hash algorithm
	unique_bcrypt_alg_handle hashAlgorithm{ nullptr, ::BCryptAlgorithmCloser };
	RETURN_IF_NT_FAILED(BCryptOpenAlgorithmProvider(out_param(hashAlgorithm), BCRYPT_SHA512_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG));

	RETURN_IF_NT_FAILED(BCryptDeriveKeyPBKDF2(hashAlgorithm.get(), reinterpret_cast<PUCHAR>(const_cast<PWSTR>(password)), (ULONG)(wcslen(password)) * sizeof(WCHAR),
						EncryptionParams[version - 1].SymmetricKeyDerivationSalt, EncryptionParams[version - 1].SymmetricKeyDerivationSaltLen, EncryptionParams[version - 1].SymmetricKeyDerivationIterationCount,
		                symmetricKey, symmetricKeyLen, 0));

	return S_OK;
}

HRESULT Encrypt(int version, const std::wstring &filename, const std::wstring &password, const std::wstring &outputFilename)
{
	// Open the algorithm handle
	unique_bcrypt_alg_handle encryptAlgorithm{ nullptr, ::BCryptAlgorithmCloser };
	RETURN_IF_NT_FAILED(BCryptOpenAlgorithmProvider(out_param(encryptAlgorithm), BCRYPT_AES_ALGORITHM, nullptr, 0));

	// Get the block length for this algorithm
	DWORD blockLength;
	DWORD ignore;
	RETURN_IF_NT_FAILED(BCryptGetProperty(encryptAlgorithm.get(), BCRYPT_BLOCK_LENGTH, (PBYTE)&blockLength, sizeof(blockLength), &ignore, 0));
	// wcout << "Block length is " << blockLength << endl;

	// Get the symmetric key
	unique_ptr<BYTE[]> symmetricKey = make_unique<BYTE[]>(blockLength);
	RETURN_IF_NULL_ALLOC(symmetricKey);
	GetSymmetricKey(1, password.c_str(), symmetricKey.get(), blockLength);
	// PrintByteBlob(symmetricKey.get(), blockLength);

	// Allocate a buffer for the IV. This buffer is consumed during the encrypt process
	unique_ptr<BYTE[]> iv = make_unique<BYTE[]>(blockLength);
	RETURN_IF_NULL_ALLOC(iv);

	memcpy(iv.get(), EncryptionParams[version - 1].iv, blockLength);

	RETURN_IF_NT_FAILED(BCryptSetProperty(encryptAlgorithm.get(), BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));

	// Generate the key from the password
	unique_bcrypt_key_handle keyHandle{ nullptr, ::BCryptDestroyKey };
	RETURN_IF_NT_FAILED(BCryptGenerateSymmetricKey(encryptAlgorithm.get(), out_param(keyHandle), nullptr, 0, symmetricKey.get(), blockLength, 0));
		
	std::ifstream inputFile(filename, std::ios::binary);
	if (!inputFile.is_open())
	{
		wcout << L"Error opening file: " << filename << endl;
		return E_UNEXPECTED;
	}

	std::ofstream outputFile(outputFilename, std::ios::binary);
	if (!outputFile.is_open())
	{
		wcout << L"Error opening file: " << outputFilename << endl;
		return E_UNEXPECTED;
	}

	// Work in units of about a page
	int work_block_size = ((4096 + blockLength -1 ) / blockLength) * blockLength;
	ULONG work_buffer_size = work_block_size * 3 / 2;
	std::unique_ptr<char[]> workBuffer = make_unique<char[]>(work_buffer_size); // Enough for in-place operation
	RETURN_IF_NULL_ALLOC(workBuffer);

	std::streamsize bytesRead = 0;
	DWORD dwFlags = 0;
	do
	{
		bytesRead = inputFile.read(workBuffer.get(), work_block_size).gcount();

		ULONG bytesEncrypted;
		dwFlags = (bytesRead == 0 || (bytesRead % blockLength)) ? BCRYPT_BLOCK_PADDING : 0;
		RETURN_IF_NT_FAILED(BCryptEncrypt(keyHandle.get(), reinterpret_cast<PUCHAR>(workBuffer.get()), (ULONG)bytesRead, nullptr, reinterpret_cast<PUCHAR>(iv.get()), blockLength,
			                reinterpret_cast<PUCHAR>(workBuffer.get()), work_buffer_size, &bytesEncrypted, dwFlags));
		outputFile.write(workBuffer.get(), bytesEncrypted);

	} while (dwFlags == 0);

#if 0
	std::streamsize bytesRead = inputFile.read(workBuffer.get(), work_block_size).gcount();
	while (bytesRead > 0)
	{
		ULONG bytesEncrypted;
		RETURN_IF_NT_FAILED(BCryptEncrypt(keyHandle.get(), reinterpret_cast<PUCHAR>(workBuffer.get()), (ULONG)bytesRead, nullptr, reinterpret_cast<PUCHAR>(iv.get()), blockLength,
			                              reinterpret_cast<PUCHAR>(workBuffer.get()), work_buffer_size, &bytesEncrypted, BCRYPT_BLOCK_PADDING /* bytesRead % blockLength ? BCRYPT_BLOCK_PADDING : 0 */));
		outputFile.write(workBuffer.get(), bytesEncrypted);

		bytesRead = inputFile.read(workBuffer.get(), work_block_size).gcount();
	}
#endif

	inputFile.close();
	outputFile.close();
	return S_OK;
}

HRESULT Decrypt(int version, const std::wstring &filename, const std::wstring &password, const std::wstring &outputFilename)
{
	// Open the algorithm handle
	unique_bcrypt_alg_handle decryptAlgorithm{ nullptr, ::BCryptAlgorithmCloser };
	RETURN_IF_NT_FAILED(BCryptOpenAlgorithmProvider(out_param(decryptAlgorithm), BCRYPT_AES_ALGORITHM, nullptr, 0));

	// Get the block length for this algorithm
	DWORD blockLength;
	DWORD ignore;
	RETURN_IF_NT_FAILED(BCryptGetProperty(decryptAlgorithm.get(), BCRYPT_BLOCK_LENGTH, (PBYTE)&blockLength, sizeof(blockLength), &ignore, 0));
	// wcout << "Block length is " << blockLength << endl;

	// Get the symmetric key
	unique_ptr<BYTE[]> symmetricKey = make_unique<BYTE[]>(blockLength);
	RETURN_IF_NULL_ALLOC(symmetricKey);
	GetSymmetricKey(1, password.c_str(), symmetricKey.get(), blockLength);
	// PrintByteBlob(symmetricKey.get(), blockLength);

	// Allocate a buffer for the IV. This buffer is consumed during the encrypt process
	unique_ptr<BYTE[]> iv = make_unique<BYTE[]>(blockLength);
	RETURN_IF_NULL_ALLOC(iv);

	memcpy(iv.get(), EncryptionParams[version - 1].iv, blockLength);

	RETURN_IF_NT_FAILED(BCryptSetProperty(decryptAlgorithm.get(), BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));

	// Generate the key from the password
	unique_bcrypt_key_handle keyHandle{ nullptr, ::BCryptDestroyKey };
	RETURN_IF_NT_FAILED(BCryptGenerateSymmetricKey(decryptAlgorithm.get(), out_param(keyHandle), nullptr, 0, symmetricKey.get(), blockLength, 0));

	std::ifstream inputFile(filename, std::ios::binary);
	if (!inputFile.is_open())
	{
		wcout << L"Error opening file: " << filename << L".";
		return E_UNEXPECTED;
	}

	std::ofstream outputFile(outputFilename, std::ios::binary);
	if (!outputFile.is_open())
	{
		wcout << L"Error opening file: " << outputFilename << L".";
		return E_UNEXPECTED;
	}

	// Work in units of about a page
	int work_block_size = ((4096 + blockLength - 1) / blockLength) * blockLength;
	ULONG work_buffer_size = work_block_size * 3 / 2;
	std::unique_ptr<char[]> workBuffer = make_unique<char[]>(work_buffer_size); // Enough for in-place operation
	RETURN_IF_NULL_ALLOC(workBuffer);

#if 1
	std::streamsize bytesRead = 0;
	DWORD dwFlags = 0;
	do
	{
		bytesRead = inputFile.read(workBuffer.get(), work_block_size).gcount();

		ULONG bytesDecrypted;
		dwFlags = (inputFile.eof()) ? BCRYPT_BLOCK_PADDING : 0;

		RETURN_IF_NT_FAILED(BCryptDecrypt(keyHandle.get(), reinterpret_cast<PUCHAR>(workBuffer.get()), (ULONG)bytesRead, nullptr, reinterpret_cast<PUCHAR>(iv.get()), blockLength,
			                              reinterpret_cast<PUCHAR>(workBuffer.get()), work_buffer_size, &bytesDecrypted, dwFlags));
		outputFile.write(workBuffer.get(), bytesDecrypted);

	} while (dwFlags == 0);
#else
	std::streamsize bytesRead = inputFile.read(workBuffer.get(), work_block_size).gcount();
	while (bytesRead > 0)
	{
		ULONG bytesDecrypted;

		RETURN_IF_NT_FAILED(BCryptDecrypt(keyHandle.get(), reinterpret_cast<PUCHAR>(workBuffer.get()), (ULONG)bytesRead, nullptr, reinterpret_cast<PUCHAR>(iv.get()), blockLength,
			nullptr, work_buffer_size, &bytesDecrypted, BCRYPT_BLOCK_PADDING/* bytesRead % blockLength ? BCRYPT_BLOCK_PADDING : 0 */));
		wcout << L"Bytyes: " << bytesDecrypted << endl;


		RETURN_IF_NT_FAILED(BCryptDecrypt(keyHandle.get(), reinterpret_cast<PUCHAR>(workBuffer.get()), (ULONG)bytesRead, nullptr, reinterpret_cast<PUCHAR>(iv.get()), blockLength,
			reinterpret_cast<PUCHAR>(workBuffer.get()), work_buffer_size, &bytesDecrypted, BCRYPT_BLOCK_PADDING/* bytesRead % blockLength ? BCRYPT_BLOCK_PADDING : 0 */));
		outputFile.write(workBuffer.get(), bytesDecrypted);

		bytesRead = inputFile.read(workBuffer.get(), work_block_size).gcount();
	}
#endif

	inputFile.close();
	outputFile.close();
	return S_OK;
}