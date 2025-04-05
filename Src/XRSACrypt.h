#ifndef XRSACryptH
#define XRSACryptH

//#include <vector>
//#include <bcrypt.h>
//#include <ncrypt.h>

#include "XAESCrypt.h"

// Définition de macro NT_SUCCESS s'il n'est pas déjà défini
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

class XRSACrypt {
	private:
	XAESCrypt         *AESCrypt;
	BCRYPT_ALG_HANDLE  hAlgProvider;
	BCRYPT_KEY_HANDLE  hkey;
	NCRYPT_PROV_HANDLE hProvider;
	NCRYPT_KEY_HANDLE  hPrivateKey;
	BCRYPT_KEY_HANDLE  hPublicKey;

	// Blobs des clés
	std::vector<BYTE>  privateblob;
	std::vector<BYTE>  publicblob;

	bool 		  __fastcall GetPrivateReady(void);
	bool 		  __fastcall GetPublicReady(void);

//	bool          __fastcall SaveKey(const std::string &filename, const std::vector<BYTE> &data);
//	bool 		  __fastcall LoadKey(const std::string &filename, std::vector<BYTE> &buffer);
	bool          __fastcall IsValid(const std::vector<BYTE> &buffer);
	bool          __fastcall ExtractPrivateBlob(void);
	bool          __fastcall ExtractPublicBlob(void);

	public:
				  XRSACrypt(void);
				  ~XRSACrypt(void);

	void 		  __fastcall ClearContext(void);
	bool          __fastcall NewKeyPair(void);
	bool 		  __fastcall IsPrivateBlob(const std::vector<BYTE> &buffer);
	bool 		  __fastcall IsPublicBlob(const std::vector<BYTE> &buffer);

	bool 		  __fastcall LoadBlob(const UnicodeString& filename);
	bool 		  __fastcall SaveBlobPrivate(const std::string &filename);
	bool 		  __fastcall SaveBlobPublic(const std::string &filename);

	UnicodeString __fastcall EncryptString(const UnicodeString& str);
	UnicodeString __fastcall DecryptString(const UnicodeString& hexstr);

	bool 		  __fastcall EncryptFile(const UnicodeString& infile, const UnicodeString& outfile);
	bool 		  __fastcall DecryptFile(const UnicodeString& infile, const UnicodeString& outfile);

	bool 		  __fastcall EncryptBuffer(const std::vector<BYTE>& data, std::vector<BYTE>& cryptdata);
	bool		  __fastcall DecryptBuffer(const std::vector<BYTE>& encrypteddata, std::vector<BYTE>& uncrypt);

	// Méthodes d'accès aux blobs de clés
	const std::vector<BYTE>& __fastcall GetPublicBlob(void) const { return publicblob; }
	const std::vector<BYTE>& __fastcall GetPrivateBlob(void) const { return privateblob; }
	bool                     __fastcall SetPublicBlob(const std::vector<BYTE>& blob);
	bool                     __fastcall SetPrivateBlob(const std::vector<BYTE>& blob);

	__property NCRYPT_PROV_HANDLE Provider     = { read = hProvider       };
	__property NCRYPT_KEY_HANDLE  PrivateKey   = { read = hPrivateKey     };
	__property BCRYPT_KEY_HANDLE  PublicKey    = { read = hPublicKey      };
	__property bool               PrivateReady = { read = GetPrivateReady };
	__property bool               PublicReady  = { read = GetPublicReady  };
};

#endif

