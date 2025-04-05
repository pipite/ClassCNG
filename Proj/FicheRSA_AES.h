//---------------------------------------------------------------------------

#ifndef FicheRSA_AESH
#define FicheRSA_AESH
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.Forms.hpp>
//---------------------------------------------------------------------------
class TRSA_AES : public TForm
{
__published:	// Composants gérés par l'EDI
	TButton *Button4;
	TButton *Button6;
	TButton *Button7;
	TButton *Button8;
	TButton *Button9;
	TButton *Button10;
	TButton *Button11;
	TMemo *LOG;
	TEdit *Edit1;
	TEdit *Edit2;
	void __fastcall Button4Click(TObject *Sender);
	void __fastcall Button6Click(TObject *Sender);
	void __fastcall Button7Click(TObject *Sender);
	void __fastcall Button8Click(TObject *Sender);
	void __fastcall Button9Click(TObject *Sender);
	void __fastcall Button10Click(TObject *Sender);
	void __fastcall Button11Click(TObject *Sender);
private:	// Déclarations utilisateur
	HCRYPTPROV hProv = 0;
	HCRYPTKEY  hAesKey = 0;
	HCRYPTKEY  hRsaKey = 0;
	HCRYPTKEY  hRsaPublicKey = 0;
    HCRYPTHASH hHash = 0;
	BYTE       aesKey[256] = { 0 };
	DWORD      aesKeyLen = sizeof(aesKey);

	UnicodeString __fastcall ToHex(const BYTE* data, DWORD length);

public:		// Déclarations utilisateur
	__fastcall TRSA_AES(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TRSA_AES *RSA_AES;
//---------------------------------------------------------------------------
#endif
