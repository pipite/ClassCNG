//---------------------------------------------------------------------------

#include <vcl.h>
#pragma hdrstop

#include "FicheRSA_AES.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TRSA_AES *RSA_AES;
//---------------------------------------------------------------------------
__fastcall TRSA_AES::TRSA_AES(TComponent* Owner)
	: TForm(Owner)
{
	hProv         = NULL;
	hAesKey       = NULL;
	hRsaKey       = NULL;
	hHash         = NULL;
	hRsaPublicKey = NULL;

}

UnicodeString TRSA_AES::ToHex(const BYTE* data, DWORD length) {
	UnicodeString s;
	for (DWORD i = 0; i < length; i++) {
		wchar_t hex[3];
		swprintf(hex, 3, L"%02X", data[i]);
		s += UnicodeString(hex);
	}
	return s;
}

//---------------------------------------------------------------------------
void __fastcall TRSA_AES::Button4Click(TObject *Sender)
{
	LOG->Lines->Add("1) Initialiser le contexte cryptographique");
	if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		LOG->Lines->Add("    Erreur CryptAcquireContext: " + GetLastError());
		return;
	}
	LOG->Lines->Add("    CryptAcquireContext Ok");
}
//---------------------------------------------------------------------------
void __fastcall TRSA_AES::Button6Click(TObject *Sender)
{
	LOG->Lines->Add("2) Générer une clé RSA (asymétrique)");
	if (!CryptGenKey(hProv, AT_KEYEXCHANGE, RSA1024BIT_KEY | CRYPT_EXPORTABLE, &hRsaKey)) {
		LOG->Lines->Add("    Erreur CryptGenKey (RSA): " + GetLastError());
		return;
    }
	LOG->Lines->Add("    CryptGenKey (RSA) Ok");
}
//---------------------------------------------------------------------------
void __fastcall TRSA_AES::Button7Click(TObject *Sender)
{
	LOG->Lines->Add("3) Générer une clé AES-256 (symetrique) manuellement");
	if (!CryptGenRandom(hProv, sizeof(aesKey), aesKey)) {
		LOG->Lines->Add("    Erreur CryptGenRandom (AES): " + GetLastError() );
		return;
    }
	LOG->Lines->Add("    Clé AES générée: ");
	LOG->Lines->Add(ToHex(aesKey, sizeof(aesKey)));
}
//---------------------------------------------------------------------------
void __fastcall TRSA_AES::Button8Click(TObject *Sender)
{
	LOG->Lines->Add("4) Créer un hash SHA-256 (base pour CryptDeriveKey)");
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		LOG->Lines->Add("Erreur CryptCreateHash: " + GetLastError() );
        return;
    }
	LOG->Lines->Add("    hash SHA-256 créé");
}
//---------------------------------------------------------------------------
void __fastcall TRSA_AES::Button9Click(TObject *Sender)
{
	LOG->Lines->Add("5) Alimenter le hash brut avec la clé AES brute");
	if (!CryptHashData(hHash, aesKey, aesKeyLen, 0)) {
		LOG->Lines->Add("Erreur CryptHashData: " + GetLastError());
		return;
	}
	LOG->Lines->Add("    hash SHA-256 allimenté avec clé brute");
}
//---------------------------------------------------------------------------
void __fastcall TRSA_AES::Button10Click(TObject *Sender)
{
	LOG->Lines->Add("6) Dériver la clé AES-256 depuis le hash");
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hAesKey)) {
		LOG->Lines->Add("Erreur CryptDeriveKey: " + GetLastError());
		return;
	}
	LOG->Lines->Add("    Clé AES dérivée avec succès via CryptDeriveKey");
}
//---------------------------------------------------------------------------
void __fastcall TRSA_AES::Button11Click(TObject *Sender)
{
//	LOG->Lines->Add("Chiffrer un message avec AES");
//	BYTE message[] = Edit1->Text.c_str();
//	DWORD msgLen = sizeof(message);
//	DWORD bufferLen = msgLen + 16;
//	std::vector<BYTE> buffer(bufferLen);
//	memcpy(buffer.data(), message, msgLen);
//
//	if (!CryptEncrypt(hAesKey, 0, TRUE, 0, buffer.data(), &msgLen, bufferLen)) {
//		LOG->Lines->Add("Erreur CryptEncrypt: " + GetLastError() );
//		return;
//	}
//	LOG->Lines->Add(L"🔒 Message chiffré: " + ToHex(buffer.data(), msgLen));
}
//---------------------------------------------------------------------------
