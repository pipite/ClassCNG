#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XPassword.h"

XPassword::XPassword(void) {
	Password = L"";
}

XPassword::~XPassword(void) {
}

//---------------------------------------------------------------------------
// G�n�re un password s�curis�
//---------------------------------------------------------------------------
UnicodeString __fastcall XPassword::Shuffle(UnicodeString str) {
	static std::random_device rd;
	static std::mt19937 gen(rd());

	int len = str.Length();
	for (int i = len; i > 1; --i) {
		std::uniform_int_distribution<int> distrib(1, i);
		int j = distrib(gen);
		std::swap(str[i], str[j]);
	}
	return str;
}

UnicodeString __fastcall XPassword::NewSecurePassword(int length) {
	if (length < 4) {
		throw std::invalid_argument("Le mot de passe doit contenir au moins 4 caract�res.");
	}

	const std::string LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
	const std::string UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const std::string DIGITS = "0123456789";
	const std::string SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?";

	const std::string ALL_CHARS = LOWERCASE + UPPERCASE + DIGITS + SYMBOLS;

	// G�n�rateurs al�atoires
	std::random_device rd;
	std::mt19937 gen(rd());

	// Distributions pour chaque type de caract�re
	std::uniform_int_distribution<int> distLower(0, LOWERCASE.size() - 1);
	std::uniform_int_distribution<int> distUpper(0, UPPERCASE.size() - 1);
	std::uniform_int_distribution<int> distDigit(0, DIGITS.size() - 1);
	std::uniform_int_distribution<int> distSymbol(0, SYMBOLS.size() - 1);
	std::uniform_int_distribution<int> distAll(0, ALL_CHARS.size() - 1);

	UnicodeString password;

	// Ajout d'au moins un caract�re de chaque type
	password += LOWERCASE[distLower(gen)];
	password += UPPERCASE[distUpper(gen)];
    password += DIGITS[distDigit(gen)];
    password += SYMBOLS[distSymbol(gen)];

    // Compl�ter le mot de passe avec des caract�res al�atoires
	for (int i = 4; i < length; ++i) {
		password += ALL_CHARS[distAll(gen)];
    }

	// M�langer les caract�res pour �viter une pr�visibilit�
	Password = Shuffle(password);
	return Password;
}

//---------------------------------------------------------------------------
//          Run as User
//---------------------------------------------------------------------------
void __fastcall XPassword::RunAsUser(UnicodeString username, UnicodeString domain, UnicodeString password, UnicodeString programToRun)
{
	// Structure pour démarrer le processus
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Conversion des chaînes String en tableaux de caractères Unicode (LPCWSTR)
	wchar_t* wUsername = username.c_str();
	wchar_t* wDomain = domain.c_str();
	wchar_t* wPassword = password.c_str();
	wchar_t* wProgramToRun = programToRun.c_str();

	// Utilisation de CreateProcessWithLogonW pour démarrer le processus avec les informations d'identification fournies
	BOOL result = CreateProcessWithLogonW(
		wUsername,            // Nom d'utilisateur
		wDomain,              // Domaine ou machine locale
		wPassword,            // Mot de passe
		LOGON_WITH_PROFILE,    // Crée un profil pour l'utilisateur
		NULL,                 // Application à exécuter (NULL si spécifiée dans wProgramToRun)
		wProgramToRun,        // Ligne de commande de l'application
		CREATE_DEFAULT_ERROR_MODE, // Options de création
		NULL,                 // Variables d'environnement (NULL pour utiliser celles par défaut)
		NULL,                 // Répertoire de travail (NULL pour le répertoire par défaut)
		&si,                  // Informations de démarrage
		&pi                   // Informations sur le processus créé
	);

	if (result)
	{
		// Si le processus a été démarré correctement, afficher un message de succès
		WaitForSingleObject(pi.hProcess, INFINITE);
        ShowMessage("Programme démarré avec succès sous l'autre compte utilisateur.");
		// Attendre que le processus se termine

        // Nettoyage des handles
        CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
    }
    else
    {
		// En cas d'échec, afficher un message d'erreur
        DWORD errorCode = GetLastError();
		ShowMessage("Échec du lancement du programme.");
	}
}

