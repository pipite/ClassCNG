#ifndef XBuffToolH
#define XBuffToolH

	bool              __fastcall UnicodeToBuffer(const UnicodeString& str, std::vector<BYTE>& outbuffer);
	UnicodeString     __fastcall BufferToUnicode(const std::vector<BYTE>& buffer);

	UnicodeString     __fastcall BufferToHex(const std::vector<BYTE>& buffer);
	bool              __fastcall HexToBuffer(const UnicodeString& hexStr, std::vector<BYTE>& buffer);

	bool              __fastcall BufferToFile(const std::vector<BYTE>& buffer, UnicodeString outfile);
	bool              __fastcall FileToBuffer(const UnicodeString& infile, std::vector<BYTE>& buffer);

	bool			  __fastcall ExtractAESBlob(std::vector<BYTE>& buffer, std::vector<BYTE>& aesblob);
	bool              __fastcall CombineAESBlobWithData(std::vector<BYTE> &data, const std::vector<BYTE> &keyBuffer);

	std::string       __fastcall UnicodeToString(const UnicodeString& ustr);

#endif

