#ifndef XAESPwdH
#define XAESPwdH

//#include <bcrypt.h>
//#include <vector>

#include "XAESCrypt.h"

// Lier la bibliothèque BCrypt
#pragma comment(lib, "bcrypt.lib")

// Définition du macro NT_SUCCESS s'il n'est pas déjà défini
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

class XAESPwd {
	private:
	XAESCrypt        *AESCrypt;
	UnicodeString     PPassword;
	bool              PReady;
	DWORD             KeyIterations; // Nombre d'itérations pour la dérivation de clé


	public:
				  XAESPwd(void);
				  ~XAESPwd(void);

	bool 		  __fastcall NewSecureKey(const UnicodeString& password);
	bool 		  __fastcall SetPassword(const UnicodeString& password);

	UnicodeString __fastcall EncryptString(const UnicodeString& str);
	UnicodeString __fastcall DecryptString(const UnicodeString& str);

	bool          __fastcall EncryptFile(const UnicodeString& infile, const UnicodeString& outfile);
	bool          __fastcall DecryptFile(const UnicodeString& infile, const UnicodeString& outfile);

	// Méthodes pour sauvegarder et charger une clé AES
	bool              __fastcall SaveKey(const UnicodeString& filename);
	bool              __fastcall LoadKey(const UnicodeString& filename);
};

#endif

