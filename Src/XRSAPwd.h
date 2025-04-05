#ifndef XRSAPwdH
#define XRSAPwdH

//#include <vector>

#include "XAESCrypt.h"
#include "XRSACrypt.h"
#include "XBuffTool.h"

class XRSAPwd {
	private:
	HCRYPTPROV        hProv;
	HCRYPTKEY         hKey;
	HCRYPTHASH        hHash;
	std::vector<BYTE> buffer;
	UnicodeString     PPassword;
	bool              PReady;

	// Blobs des clés
	std::vector<BYTE>  privateblob;
	std::vector<BYTE>  publicblob;

	public:
	XAESCrypt     *AESCrypt;
	XRSACrypt     *RSACrypt;

				  XRSAPwd(void);
				  ~XRSAPwd(void);

	bool 		  __fastcall SetPassword(UnicodeString password);
	void 		  __fastcall ClearKey(void);

	UnicodeString __fastcall EncryptString(UnicodeString str);
	UnicodeString __fastcall DecryptString(UnicodeString str);

	bool          __fastcall EncryptFile(UnicodeString infile, UnicodeString outfile);
	bool          __fastcall DecryptFile(UnicodeString infile, UnicodeString outfile);

	bool 		  __fastcall EncryptBuffer(const std::vector<BYTE>& uncrypt, std::vector<BYTE>& crypt);
	bool		  __fastcall DecryptBuffer(const std::vector<BYTE>& crypt, std::vector<BYTE>& uncrypt);

//	bool          __fastcall SaveKey(const UnicodeString& filename);
//	bool          __fastcall LoadKey(const UnicodeString& filename);
	bool          __fastcall SaveBlobPrivate(const UnicodeString& filename);
	bool          __fastcall SaveBlobPublic(const UnicodeString& filename);
	bool          __fastcall LoadBlobPrivate(const UnicodeString& filename);
	bool          __fastcall LoadBlobPublic(const UnicodeString& filename);
	bool          __fastcall NewKeyPair(const UnicodeString& password);

};

#endif

