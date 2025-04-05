#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XAESPwd.h"
#include "XBuffTool.h"

XAESPwd::XAESPwd(void) {
	AESCrypt      = new XAESCrypt();
	PPassword     = L"";
	PReady        = false;
	KeyIterations = 50000; // Valeur par défaut
}

XAESPwd::~XAESPwd(void) {
	delete AESCrypt;
}

//---------------------------------------------------------------------------
// CNG - AES Password - AES Cryptage
//---------------------------------------------------------------------------

bool __fastcall XAESPwd::NewSecureKey(const UnicodeString& password) {
	PPassword = password;
	PReady    = AESCrypt->NewSecureKey(password, KeyIterations);
	return PReady;
}

bool __fastcall XAESPwd::SetPassword(const UnicodeString& password) {
	// Cette méthode est utilisée après LoadKey pour recréer la clé AES avec le mot de passe
	if (AESCrypt == NULL) return false;
	
	// Stocker le mot de passe
	PPassword = password;
	
	// Récupérer le sel chargé précédemment
	std::vector<BYTE> saltBlob = AESCrypt->GetSalt();
	if (saltBlob.empty()) return false;
	
	// Utiliser le sel chargé précédemment pour recréer la clé AES
	// Utiliser le nombre d'itérations récupéré du fichier de clé lors du chargement
	PReady = AESCrypt->NewSecureKey(password, saltBlob, KeyIterations);
	
	return PReady;
}

//---------------------------------------------------------------------------
// Crypte / Encrypte AES (symetrique) - String protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
UnicodeString __fastcall XAESPwd::EncryptString(const UnicodeString& str) {
	return AESCrypt->EncryptString(str);
}

UnicodeString __fastcall XAESPwd::DecryptString(const UnicodeString& str) {
	return AESCrypt->DecryptString(str);
}

//---------------------------------------------------------------------------
// AES Crypte / Decrypte AES (symetrique) - fichier protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
bool __fastcall XAESPwd::EncryptFile(const UnicodeString& infile, const UnicodeString& outfile) {
	return AESCrypt->EncryptFile(infile, outfile);
}

bool __fastcall XAESPwd::DecryptFile(const UnicodeString& infile, const UnicodeString& outfile) {
	return AESCrypt->DecryptFile(infile, outfile);
}

//---------------------------------------------------------------------------
// AES Crypte / Decrypte AES (symetrique) - fichier protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
bool __fastcall XAESPwd::SaveKey(const UnicodeString& filename) {
    // Vérifier que la clé AES est valide
    if (AESCrypt == NULL || !PReady) return false;

    try {
        // Structure pour stocker les données de la clé
        struct KeyData {
            DWORD keyIterations;
            DWORD saltSize;
        };

        // Récupérer le sel (salt) utilisé pour la dérivation de clé
        std::vector<BYTE> saltBlob = AESCrypt->GetSalt();
        if (saltBlob.empty()) return false;

        // Créer un buffer pour stocker les données
        KeyData header;
        header.keyIterations = KeyIterations; // Utiliser le nombre d'itérations stocké dans la classe
        header.saltSize = (DWORD)saltBlob.size();

        // Calculer la taille totale du buffer
        size_t totalSize = sizeof(KeyData) + saltBlob.size();
        std::vector<BYTE> saveBuffer(totalSize);

        // Copier l'en-tête
        memcpy(saveBuffer.data(), &header, sizeof(KeyData));

        // Copier le sel
        memcpy(saveBuffer.data() + sizeof(KeyData), saltBlob.data(), saltBlob.size());

        // Sauvegarder le buffer dans un fichier
        return BufferToFile(saveBuffer, filename);
    }
    catch (const std::exception&) {
        return false;
    }
}

bool __fastcall XAESPwd::LoadKey(const UnicodeString& filename) {
    // Cette méthode charge uniquement le sel et les paramètres, mais pas la clé
    // Le mot de passe devra être fourni séparément via SetPassword
    try {
        // Charger le fichier dans un buffer
        std::vector<BYTE> loadBuffer;
        if (!FileToBuffer(filename, loadBuffer)) return false;

        // Structure pour stocker les données de la clé
        struct KeyData {
            DWORD keyIterations;
            DWORD saltSize;
        };

        // Vérifier que le buffer est assez grand pour contenir l'en-tête
        if (loadBuffer.size() < sizeof(struct KeyData)) return false;

        // Extraire l'en-tête
        KeyData header;
        memcpy(&header, loadBuffer.data(), sizeof(KeyData));

        // Vérifier que les tailles sont cohérentes
        if (loadBuffer.size() != sizeof(KeyData) + header.saltSize)
            return false;

        // Extraire le sel
        std::vector<BYTE> saltBlob(header.saltSize);
        memcpy(saltBlob.data(), loadBuffer.data() + sizeof(KeyData), header.saltSize);

        // Stocker le sel dans l'objet AESCrypt
        if (!AESCrypt->SetSalt(saltBlob)) return false;

        // Stocker le nombre d'itérations pour une utilisation ultérieure
        KeyIterations = header.keyIterations;

        // La clé n'est pas encore prête, le mot de passe doit être fourni
        PReady = false;

        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

