#ifndef XAESCryptH
#define XAESCryptH

//#include <bcrypt.h>
//#include <vector>

#include "XBuffTool.h"

// Lier la bibliothèque BCrypt
#pragma comment(lib, "bcrypt.lib")

// Définition du macro NT_SUCCESS s'il n'est pas déjà défini
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

class XAESCrypt {
	private:
	DWORD KeyIterations; // Nombre d'itérations pour la dérivation de clé
	BCRYPT_ALG_HANDLE AESAlgorithm;
	BCRYPT_KEY_HANDLE AESKey;
	std::vector<BYTE> AESBlob;
	std::vector<BYTE> SaltBlob;

	bool              __fastcall NewRandomIV(std::vector<BYTE>& iv);
	bool 			  __fastcall DeriveKey(const UnicodeString& password, std::vector<BYTE>& salt, std::vector<BYTE>& derivedKey, DWORD iterations);

	public:
    DWORD             IVSIZE;

				  XAESCrypt(void);
				  ~XAESCrypt(void);

	UnicodeString     __fastcall EncryptString(const UnicodeString& str);
	UnicodeString     __fastcall DecryptString(const UnicodeString& str);

	bool 		      __fastcall EncryptFile(const UnicodeString& infile, const UnicodeString& outfile);
	bool 		      __fastcall DecryptFile(const UnicodeString& infile, const UnicodeString& outfile);

	bool 			  __fastcall EncryptBuffer(const std::vector<BYTE>& uncrypt, std::vector<BYTE>& crypt);
	bool			  __fastcall DecryptBuffer(const std::vector<BYTE>& crypt, std::vector<BYTE>& uncrypt);

	bool 			  __fastcall NewSecureKey(const UnicodeString& password, const std::vector<BYTE>& salt, const DWORD iterations);
	bool 			  __fastcall NewSecureKey(const UnicodeString& password, const DWORD iterations);
	void 		      __fastcall ClearKey(void);

//	bool              __fastcall ImportAesBlob(BCRYPT_ALG_HANDLE &hAlg, BCRYPT_KEY_HANDLE &hKey, const std::vector<BYTE>& keyBlob);
	bool			  __fastcall ExportBlob(const BCRYPT_KEY_HANDLE hKey, std::vector<BYTE>& aesBlob);

	// Méthodes pour sauvegarder et charger une clé AES
	bool              __fastcall SaveKey(const UnicodeString& filename);
	bool              __fastcall LoadKey(const UnicodeString& filename);

	// Méthodes pour accéder et définir le sel
	std::vector<BYTE>  __fastcall GetSalt(void);
	bool               __fastcall SetSalt(const std::vector<BYTE>& salt);
};

#endif

