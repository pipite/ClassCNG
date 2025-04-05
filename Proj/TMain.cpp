//---------------------------------------------------------------------------
#include "TestCryptPCH1.h"
#pragma hdrstop

#include "TMain.h"

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TMain *Main;
//---------------------------------------------------------------------------
__fastcall TMain::TMain(TComponent* Owner)
	: TForm(Owner)
{
	GenPassword = new XPassword();
	AESPwd      = new XAESPwd();
	RSACrypt    = new XRSACrypt();
	RSAPwd      = new XRSAPwd();
}

void __fastcall TMain::FormClose(TObject *Sender, TCloseAction &Action)
{
	delete GenPassword;
	delete AESPwd;
	delete RSACrypt;
	delete RSAPwd;
}

//---------------------------------------------------------------------------
//          XPassword
//---------------------------------------------------------------------------
void __fastcall TMain::BtPasswordClick(TObject *Sender)
{
	EdPassword->Text = GenPassword->NewSecurePassword(NumberBox->Text.ToInt());
}

void __fastcall TMain::CBVisibleClick(TObject *Sender)
{
	if ( CBVisible->Checked ) {
		EdPassword->PasswordChar = char(0);
	} else {
		EdPassword->PasswordChar = '*';
	}
}

void __fastcall TMain::Button6Click(TObject *Sender)
{
	AESPwd->NewSecureKey(EdPassword->Text);
}

//---------------------------------------------------------------------------
//          XAESPwd
//---------------------------------------------------------------------------
void __fastcall TMain::Button8Click(TObject *Sender)
{
	AESPwd->SaveKey("AES.blob");
}

void __fastcall TMain::Button7Click(TObject *Sender)
{
	AESPwd->LoadKey("AES.blob");
}

void __fastcall TMain::Button9Click(TObject *Sender)
{
	AESPwd->SetPassword(EdPassword->Text);
}

// String
void __fastcall TMain::WinEncryptClick(TObject *Sender)
{
	if ( AESPwd->EncryptFile(EdFilepath->Text, EdFilepath->Text + ".Crypt") ) {
		LabelWinCrypt->Caption = "Fichier Crypt�.";
	} else {
		LabelWinCrypt->Caption = "Echec du cryptage";
	}
	EdWinEncrypt->Text = AESPwd->EncryptString(EdExemple->Text);
}

void __fastcall TMain::WinDecryptClick(TObject *Sender)
{
	EdWinEncrypt->Text = AESPwd->DecryptString(EdWinEncrypt->Text);
}

// File
void __fastcall TMain::BtWinCryptFileClick(TObject *Sender)
{
	if ( AESPwd->EncryptFile(EdFilepath->Text, EdFilepath->Text + ".Crypt") ) {
		LabelWinCrypt->Caption = "Fichier Crypt�.";
	} else {
		LabelWinCrypt->Caption = "Echec du cryptage";
	}
}

void __fastcall TMain::BtWinDecryptFileClick(TObject *Sender)
{
	if ( AESPwd->DecryptFile(EdFilepath->Text + ".Crypt", EdFilepath->Text + ".Crypt.png") ) {
		LabelWinCrypt->Caption = "Fichier D�crypt�.";
	} else {
		LabelWinCrypt->Caption = "Echec du d�cryptage";
	}
}

//---------------------------------------------------------------------------
//          XRSACrypt  Private Public Key
//---------------------------------------------------------------------------
void __fastcall TMain::BtCreateKeyClick(TObject *Sender)
{
	if ( RSACrypt->NewKeyPair() ) {
		LbRSAKey->Caption = "Paire de cl� RSA g�n�r�.";
	} else {
		LbRSAKey->Caption = "Erreur � la cr�ation de la paire de cl� .RSA";
	}
}

void __fastcall TMain::BtLoadPrivateRsaKeyClick(TObject *Sender)
{
	if ( RSACrypt->LoadBlob("private.blob") ) {
		LbRSAKey->Caption = "Cl� private.blob charg�.";
	} else {
		LbRSAKey->Caption = "Erreur chargement de la cl� private.blob";
	}
}

void __fastcall TMain::BtLoadPublicRsaKeyClick(TObject *Sender)
{
	if ( RSACrypt->LoadBlob("public.blob") ) {
		LbRSAKey->Caption = "Cl� public.blob charg�.";
	} else {
		LbRSAKey->Caption = "Erreur chargement de la cl� publique.blob";
	}
}

void __fastcall TMain::BtSaveRSAPrivateKeyClick(TObject *Sender)
{
	if ( RSACrypt->SaveBlobPrivate("private.blob") ) {
		LbRSAKey->Caption = "Cl� priv� sauvegard�.";
	} else {
		LbRSAKey->Caption = "Erreur � la sauvegarde de la cl� priv�";
	}
}

void __fastcall TMain::BtExportRSAPublicKeyClick(TObject *Sender)
{
	if ( RSACrypt->SaveBlobPublic("public.blob") ) {
		LbRSAKey->Caption = "Cl� public.blob sauvegard�.";
	} else {
		LbRSAKey->Caption = "Erreur � la sauvegarde de la cl� public.blob";
	}
}

//---------------------------------------------------------------------------
void __fastcall TMain::BtRSAPublicKeyEncryptClick(TObject *Sender)
{
	EdRSACrypt->Text = RSACrypt->EncryptString(EdRSAExemple->Text);
}

void __fastcall TMain::BtRSAPrivateKeyDecryptClick(TObject *Sender)
{
	EdRSACrypt->Text = RSACrypt->DecryptString(EdRSACrypt->Text);
}

void __fastcall TMain::BtRSAPublicKeyCryptFileClick(TObject *Sender)
{
	if ( RSACrypt->EncryptFile(EdRSAFile->Text, EdRSAFile->Text + ".Crypt") ) {
		LbRSACrypt->Caption = "Fichier Crypt�.";
	} else {
		LbRSACrypt->Caption = "Echec Cryptage";
	}
}

void __fastcall TMain::BtRSAPrivateKeyDeCryptFileClick(TObject *Sender)
{
	if ( RSACrypt->DecryptFile(EdRSAFile->Text + ".Crypt", EdRSAFile->Text + ".Crypt.png") ) {
		LbRSACrypt->Caption = "Fichier D�crypt�.";
	} else {
		LbRSACrypt->Caption = "Echec D�cryptage";
	}
}

//---------------------------------------------------------------------------
//          XRSAPwd  Private Public Key
//---------------------------------------------------------------------------
void __fastcall TMain::Button10Click(TObject *Sender)
{
	RSAPwd->NewKeyPair(EdPassword->Text);
}

void __fastcall TMain::Button15Click(TObject *Sender)
{
	RSAPwd->SetPassword(EdPassword->Text);
}

void __fastcall TMain::Button2Click(TObject *Sender)
{
	EdRSAPwd->Text = RSAPwd->EncryptString(Edit6->Text);
}

void __fastcall TMain::Button3Click(TObject *Sender)
{
	EdRSAPwd->Text = RSAPwd->DecryptString(EdRSAPwd->Text);
}

void __fastcall TMain::Button14Click(TObject *Sender)
{
	if ( RSAPwd->LoadBlobPrivate("privatepwd.blob") ) {
		LbRsaPwd->Caption = "Cl� private.blob charg�.";
	} else {
		LbRsaPwd->Caption = "Erreur chargement de la cl� private.blob";
	}
}

void __fastcall TMain::Button11Click(TObject *Sender)
{
	if ( RSAPwd->LoadBlobPublic("publicpwd.blob") ) {
		LbRsaPwd->Caption = "Cl� public.blob charg�.";
	} else {
		LbRsaPwd->Caption = "Erreur chargement de la cl� public.blob";
	}
}

void __fastcall TMain::Button12Click(TObject *Sender)
{
	if ( RSAPwd->SaveBlobPrivate("privatepwd.blob") ) {
		LbRsaPwd->Caption = "Cl� private.blob sauvegard�.";
	} else {
		LbRsaPwd->Caption = "Erreur sauvegarde de la cl� private.blob";
	}
}

void __fastcall TMain::Button13Click(TObject *Sender)
{
	if ( RSAPwd->SaveBlobPublic("publicpwd.blob") ) {
		LbRsaPwd->Caption = "Cl� public.blob sauvegard�.";
	} else {
		LbRsaPwd->Caption = "Erreur sauvegarde de la cl� public.blob";
	}
}

void __fastcall TMain::Button5Click(TObject *Sender)
{
	if ( RSAPwd->EncryptFile(Edit5->Text, Edit5->Text + ".Crypt") ) {
		Label7->Caption = "Fichier Crypt�.";
	} else {
		Label7->Caption = "Echec du cryptage";
	}
}

void __fastcall TMain::Button4Click(TObject *Sender)
{
	if ( RSAPwd->DecryptFile(Edit5->Text + ".Crypt", Edit5->Text + ".Crypt.png") ) {
		Label7->Caption = "Fichier D�crypt�.";
	} else {
		Label7->Caption = "Echec du d�cryptage";
	}
}

//---------------------------------------------------------------------
//          Run as User
//---------------------------------------------------------------------------
void __fastcall TMain::Button1Click(TObject *Sender) {
	GenPassword->RunAsUser(Edit2->Text, Edit3->Text, EdPassword->Text, Edit1->Text);
}


