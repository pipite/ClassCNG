#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XRSAPwd.h"

XRSAPwd::XRSAPwd(void) {
	AESCrypt  = new XAESCrypt();
	RSACrypt  = new XRSACrypt();
	PPassword = L"";
	hProv     = NULL;
	hKey      = NULL;
	hHash     = NULL;
	PReady    = false;
}

XRSAPwd::~XRSAPwd(void) {
	delete AESCrypt;
	delete RSACrypt;
	ClearKey();
}

//---------------------------------------------------------------------------
// Crypt - AES SHA - RSA Cryptage + Password
//---------------------------------------------------------------------------

void __fastcall XRSAPwd::ClearKey(void) {
	if (hKey  != NULL) { CryptDestroyKey(hKey);         hKey   = NULL; }
	if (hProv != NULL) { CryptReleaseContext(hProv, 0); hProv  = NULL; }
	if (hHash != NULL) { CryptDestroyHash(hHash);       hHash  = NULL; }
	buffer.clear();

	PPassword = L"";
	PReady = false;
}

bool __fastcall XRSAPwd::SetPassword(UnicodeString password) {
	ClearKey();
	PPassword = password;
	
	// Vérifier que le mot de passe n'est pas vide
	PReady = !PPassword.IsEmpty();
	
	return PReady;
}

//---------------------------------------------------------------------------
// Crypte / Decrypte String - AES SHA - RSA Cryptage + Password
//---------------------------------------------------------------------------
UnicodeString __fastcall XRSAPwd::EncryptString(UnicodeString str) {
	try {
		std::vector<BYTE> buff;
		std::vector<BYTE> encryptedBuffer;

		UnicodeToBuffer(str, buff);
		EncryptBuffer(buff, encryptedBuffer);
		return BufferToHex(encryptedBuffer);
	} catch (const std::exception& e) {
		return UnicodeString(L"Erreur: ") + UnicodeString(e.what());
	}
	return L"Erreur encrypage par AES et Clé publique RSA + Password";
}

UnicodeString __fastcall XRSAPwd::DecryptString(UnicodeString str) {
	try {
		std::vector<BYTE> buff;
		std::vector<BYTE> decryptedBuffer;

		HexToBuffer(str,buff);
		DecryptBuffer(buff, decryptedBuffer);
		return BufferToUnicode(decryptedBuffer);
	} catch (const std::exception& e) {
		return UnicodeString(L"Erreur: ") + UnicodeString(e.what());
	}

	return L"Erreur décrypage par AES et Clé privé RSA + Password";
}

//---------------------------------------------------------------------------
// Crypte / Decrypte file AES (symetrique) - fichier protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
bool __fastcall XRSAPwd::EncryptFile(UnicodeString infile, UnicodeString outfile) {
	try {
		std::vector<BYTE> fileBuffer;
		std::vector<BYTE> encryptedData;

		FileToBuffer(infile,fileBuffer);
		EncryptBuffer(fileBuffer, encryptedData);
		return BufferToFile(encryptedData, outfile);
	} catch (const std::exception& e) {
		return false;
	}

	return false;
}

bool __fastcall XRSAPwd::DecryptFile(UnicodeString infile, UnicodeString outfile) {
	try {
		std::vector<BYTE> fileBuffer;
		std::vector<BYTE> decryptedData;

		FileToBuffer(infile,fileBuffer);
		DecryptBuffer(fileBuffer, decryptedData);
		return BufferToFile(decryptedData, outfile);
	} catch (const std::exception& e) {
		return false;
	}

	return false;
}

//---------------------------------------------------------------------------
// Crypte / Decrypte buffer AES (symetrique) - fichier protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
bool __fastcall XRSAPwd::EncryptBuffer(const std::vector<BYTE>& uncrypt, std::vector<BYTE>& crypt) {
	if (!RSACrypt->PublicReady) return false; // Erreur: Clé publique non initialisée
	if (PPassword.IsEmpty()) return false;    // Erreur: Mot de passe non défini

	try {
		// Générer une clé AES aléatoire pour le chiffrement symétrique
		std::vector<BYTE> aesKeyMaterial(AESCrypt->IVSIZE);

		// Ouvrir le fournisseur d'algorithme RNG
		BCRYPT_ALG_HANDLE hRng = NULL;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return false; // Erreur: Impossible d'ouvrir le fournisseur RNG

		// Générer une clé AES aléatoire
		status = BCryptGenRandom(hRng, aesKeyMaterial.data(), aesKeyMaterial.size(), 0);
		BCryptCloseAlgorithmProvider(hRng, 0);
		if (!NT_SUCCESS(status)) return false; // Erreur: Impossible de générer une clé AES aléatoire

		// Créer un nouvel objet XAESCrypt pour cette opération
		XAESCrypt* tempAESCrypt = new XAESCrypt();

		// Initialiser le nouvel objet AESCrypt avec cette clé aléatoire
		UnicodeString aesPassword = BufferToHex(aesKeyMaterial);
		if (!tempAESCrypt->NewSecureKey(aesPassword, 1)) {
			delete tempAESCrypt;
			return false; // Erreur: Impossible de créer la clé AES
		}

		// Récupérer le sel utilisé pour la dérivation de clé
		std::vector<BYTE> saltUsed = tempAESCrypt->GetSalt();

		// Chiffrer les données avec AES
		std::vector<BYTE> aesEncryptedData;
		if (!tempAESCrypt->EncryptBuffer(uncrypt, aesEncryptedData)) {
			delete tempAESCrypt;
			return false; // Erreur: Échec du chiffrement AES
		}

		// Libérer l'objet AESCrypt temporaire
		delete tempAESCrypt;

		// Maintenant, chiffrer la clé AES avec RSA (clé publique)
		// Ouvrir le fournisseur d'algorithme RSA
		BCRYPT_ALG_HANDLE hRsaAlg = NULL;
		status = BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return false; // Erreur: Impossible d'ouvrir le fournisseur RSA

		// Importer la clé publique
		BCRYPT_KEY_HANDLE hRsaKey = NULL;
		const std::vector<BYTE>& publicBlob = RSACrypt->GetPublicBlob();
		status = BCryptImportKeyPair(hRsaAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hRsaKey, 
			const_cast<BYTE*>(publicBlob.data()), publicBlob.size(), 0);
		if (!NT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false; // Erreur: Impossible d'importer la clé publique RSA
		}

		// Dériver une clé à partir du mot de passe pour mélanger avec la clé AES
		// Créer un hash SHA-256 du mot de passe
		BCRYPT_ALG_HANDLE hHashAlg = NULL;
		BCRYPT_HASH_HANDLE hHash = NULL;
		status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) {
			BCryptDestroyKey(hRsaKey);
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false;
		}

		// Créer l'objet de hachage
		DWORD hashObjectSize = 0;
		DWORD dataSize = 0;
		status = BCryptGetProperty(hHashAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjectSize, sizeof(DWORD), &dataSize, 0);
		if (!NT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hHashAlg, 0);
			BCryptDestroyKey(hRsaKey);
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false;
		}

		std::vector<BYTE> hashObject(hashObjectSize);
		status = BCryptCreateHash(hHashAlg, &hHash, hashObject.data(), hashObjectSize, NULL, 0, 0);
		if (!NT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hHashAlg, 0);
			BCryptDestroyKey(hRsaKey);
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false;
		}

		// Convertir le mot de passe en UTF-8 pour le hachage
		std::vector<BYTE> passwordBytes;
		UnicodeToBuffer(PPassword, passwordBytes);

		// Hacher le mot de passe
		status = BCryptHashData(hHash, passwordBytes.data(), passwordBytes.size(), 0);
		if (!NT_SUCCESS(status)) {
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hHashAlg, 0);
			BCryptDestroyKey(hRsaKey);
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false;
		}

		// Obtenir la taille du hash
		DWORD hashSize = 0;
		dataSize = 0;
		status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashSize, sizeof(DWORD), &dataSize, 0);
		if (!NT_SUCCESS(status)) {
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hHashAlg, 0);
			BCryptDestroyKey(hRsaKey);
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false;
		}

		// Obtenir le hash final
		std::vector<BYTE> passwordHash(hashSize);
		status = BCryptFinishHash(hHash, passwordHash.data(), passwordHash.size(), 0);
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hHashAlg, 0);
		if (!NT_SUCCESS(status)) {
			BCryptDestroyKey(hRsaKey);
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false;
		}

		// Combiner la clé AES avec le hash du mot de passe (XOR)
		std::vector<BYTE> combinedKey = aesKeyMaterial;
		for (size_t i = 0; i < combinedKey.size(); i++) {
			combinedKey[i] ^= passwordHash[i % passwordHash.size()];
		}

		// Chiffrer la clé combinée avec RSA
		DWORD encryptedKeySize = 0;
		status = BCryptEncrypt(hRsaKey, combinedKey.data(), combinedKey.size(), NULL, NULL, 0, 
			NULL, 0, &encryptedKeySize, BCRYPT_PAD_PKCS1);
		if (!NT_SUCCESS(status)) {
			BCryptDestroyKey(hRsaKey);
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false; // Erreur: Impossible de déterminer la taille de la clé AES chiffrée
		}

		std::vector<BYTE> encryptedKey(encryptedKeySize);
		status = BCryptEncrypt(hRsaKey, combinedKey.data(), combinedKey.size(), NULL, NULL, 0, 
			encryptedKey.data(), encryptedKey.size(), &encryptedKeySize, BCRYPT_PAD_PKCS1);

		BCryptDestroyKey(hRsaKey);
		BCryptCloseAlgorithmProvider(hRsaAlg, 0);

		if (!NT_SUCCESS(status)) return false; // Erreur: Impossible de chiffrer la clé AES avec RSA

		// Combiner la clé AES chiffrée, le sel et les données chiffrées
		// Format: [Taille de la clé chiffrée (4 octets)][Clé AES chiffrée][Taille du sel (4 octets)][Sel][Données chiffrées AES]
		DWORD keySize = encryptedKey.size();
		DWORD saltSize = saltUsed.size();
		crypt.resize(4 + keySize + 4 + saltSize + aesEncryptedData.size());

		// Écrire la taille de la clé chiffrée (4 octets)
		memcpy(crypt.data(), &keySize, 4);
		// Écrire la clé chiffrée
		memcpy(crypt.data() + 4, encryptedKey.data(), keySize);
		// Écrire la taille du sel (4 octets)
		memcpy(crypt.data() + 4 + keySize, &saltSize, 4);
		// Écrire le sel
		memcpy(crypt.data() + 4 + keySize + 4, saltUsed.data(), saltSize);
		// Écrire les données chiffrées
		memcpy(crypt.data() + 4 + keySize + 4 + saltSize, aesEncryptedData.data(), aesEncryptedData.size());

		return true;
	} catch (...) {
		return false; // Erreur: Exception inconnue lors du chiffrement
	}
}

bool __fastcall XRSAPwd::DecryptBuffer(const std::vector<BYTE>& crypt, std::vector<BYTE>& uncrypt) {
	if (!RSACrypt->PrivateReady) return false; // Erreur: Clé privée non initialisée
	if (PPassword.IsEmpty()) return false;     // Erreur: Mot de passe non défini

	try {
		// Au moins 4 octets pour la taille + quelques octets pour les données
		if (crypt.size() < 8) return false; // Erreur: Données chiffrées invalides ou corrompues

		// Extraire la taille de la clé chiffrée (4 premiers octets)
		DWORD encryptedKeySize = 0;
		memcpy(&encryptedKeySize, crypt.data(), 4);

		// Vérifier que les données sont cohérentes
		if (crypt.size() < 4 + encryptedKeySize || encryptedKeySize == 0) 
			return false; // Erreur: Données chiffrées invalides ou corrompues

		// Extraire la clé AES chiffrée
		std::vector<BYTE> encryptedKey(encryptedKeySize);
		memcpy(encryptedKey.data(), crypt.data() + 4, encryptedKeySize);

		// Extraire la taille du sel (4 octets après la clé chiffrée)
		DWORD saltSize = 0;
		if (crypt.size() < 4 + encryptedKeySize + 4) 
			return false; // Erreur: Données chiffrées invalides ou corrompues (pas de sel)
		memcpy(&saltSize, crypt.data() + 4 + encryptedKeySize, 4);

		// Vérifier que les données sont cohérentes
		if (crypt.size() < 4 + encryptedKeySize + 4 + saltSize || saltSize == 0) 
			return false; // Erreur: Données chiffrées invalides ou corrompues (sel invalide)

		// Extraire le sel
		std::vector<BYTE> salt(saltSize);
		memcpy(salt.data(), crypt.data() + 4 + encryptedKeySize + 4, saltSize);

		// Extraire les données chiffrées avec AES
		std::vector<BYTE> aesEncryptedData(crypt.size() - 4 - encryptedKeySize - 4 - saltSize);
		memcpy(aesEncryptedData.data(), crypt.data() + 4 + encryptedKeySize + 4 + saltSize, aesEncryptedData.size());

		// Déchiffrer la clé AES avec la clé privée RSA
		const std::vector<BYTE>& privateBlob = RSACrypt->GetPrivateBlob();
		if (privateBlob.empty()) return false; // Erreur: Blob de clé privée non disponible

		NTSTATUS status;

		// Ouvrir le fournisseur d'algorithme RSA
		BCRYPT_ALG_HANDLE hRsaAlg = NULL;
		status = BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return false; // Erreur: Impossible d'ouvrir le fournisseur RSA

		// Importer la clé privée à partir du blob stocké
		BCRYPT_KEY_HANDLE hRsaKey = NULL;
		status = BCryptImportKeyPair(hRsaAlg, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, &hRsaKey,
			const_cast<BYTE*>(privateBlob.data()), privateBlob.size(), 0);
		if (!NT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false; // Erreur: Impossible d'importer la clé privée RSA
		}

		// Déchiffrer la clé AES combinée
		DWORD decryptedKeySize = 0;
		status = BCryptDecrypt(hRsaKey, encryptedKey.data(), encryptedKey.size(), NULL, NULL, 0, 
			NULL, 0, &decryptedKeySize, BCRYPT_PAD_PKCS1);
		if (!NT_SUCCESS(status)) {
			BCryptDestroyKey(hRsaKey);
			BCryptCloseAlgorithmProvider(hRsaAlg, 0);
			return false; // Erreur: Impossible de déterminer la taille de la clé AES déchiffrée
		}

		std::vector<BYTE> combinedKey(decryptedKeySize);
		status = BCryptDecrypt(hRsaKey, encryptedKey.data(), encryptedKey.size(), NULL, NULL, 0, 
			combinedKey.data(), combinedKey.size(), &decryptedKeySize, BCRYPT_PAD_PKCS1);

		BCryptDestroyKey(hRsaKey);
		BCryptCloseAlgorithmProvider(hRsaAlg, 0);

		if (!NT_SUCCESS(status)) return false; // Erreur: Impossible de déchiffrer la clé AES avec RSA

		// Dériver une clé à partir du mot de passe pour extraire la clé AES originale
		// Créer un hash SHA-256 du mot de passe
		BCRYPT_ALG_HANDLE hHashAlg = NULL;
		BCRYPT_HASH_HANDLE hHash = NULL;
		status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) {
			return false;
		}

		// Créer l'objet de hachage
		DWORD hashObjectSize = 0;
		DWORD dataSize = 0;
		status = BCryptGetProperty(hHashAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjectSize, sizeof(DWORD), &dataSize, 0);
		if (!NT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hHashAlg, 0);
			return false;
		}

		std::vector<BYTE> hashObject(hashObjectSize);
		status = BCryptCreateHash(hHashAlg, &hHash, hashObject.data(), hashObjectSize, NULL, 0, 0);
		if (!NT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hHashAlg, 0);
			return false;
		}

		// Convertir le mot de passe en UTF-8 pour le hachage
		std::vector<BYTE> passwordBytes;
		UnicodeToBuffer(PPassword, passwordBytes);

		// Hacher le mot de passe
		status = BCryptHashData(hHash, passwordBytes.data(), passwordBytes.size(), 0);
		if (!NT_SUCCESS(status)) {
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hHashAlg, 0);
			return false;
		}

		// Obtenir la taille du hash
		DWORD hashSize = 0;
		dataSize = 0;
		status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashSize, sizeof(DWORD), &dataSize, 0);
		if (!NT_SUCCESS(status)) {
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hHashAlg, 0);
			return false;
		}

		// Obtenir le hash final
		std::vector<BYTE> passwordHash(hashSize);
		status = BCryptFinishHash(hHash, passwordHash.data(), passwordHash.size(), 0);
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hHashAlg, 0);
		if (!NT_SUCCESS(status)) {
			return false;
		}

		// Extraire la clé AES originale en appliquant XOR avec le hash du mot de passe
		std::vector<BYTE> aesKeyMaterial = combinedKey;
		for (size_t i = 0; i < aesKeyMaterial.size(); i++) {
			aesKeyMaterial[i] ^= passwordHash[i % passwordHash.size()];
		}

		// Créer un nouvel objet XAESCrypt pour cette opération
		XAESCrypt* tempAESCrypt = new XAESCrypt();

		// Initialiser le nouvel objet AESCrypt avec la clé déchiffrée et le sel récupéré
		UnicodeString aesPassword = BufferToHex(aesKeyMaterial);
		if (!tempAESCrypt->NewSecureKey(aesPassword, salt, 1)) {
			delete tempAESCrypt;
			return false; // Erreur: Impossible de créer la clé AES
		}

		// Déchiffrer les données avec AES
		bool decryptResult = tempAESCrypt->DecryptBuffer(aesEncryptedData, uncrypt);

		// Libérer l'objet AESCrypt temporaire
		delete tempAESCrypt;

		if (!decryptResult) return false; // Erreur: Échec du déchiffrement AES

		return true;
	}
	catch (...) {
		return false; // Erreur: Exception inconnue lors du déchiffrement
	}
}

//---------------------------------------------------------------------------
// New, Load, Save RSA + Password (assymetrique)
//---------------------------------------------------------------------------
//bool __fastcall XRSAPwd::SaveKey(const UnicodeString& filename) {
//	if (PPassword.IsEmpty() || !RSACrypt->PrivateReady) return false;
//
//	try {
//		// Nous allons chiffrer le blob de clé privée avec le mot de passe
//		// Créer un nouvel objet XAESCrypt pour cette opération
//		XAESCrypt* tempAESCrypt = new XAESCrypt();
//
//		// Initialiser le nouvel objet AESCrypt avec le mot de passe
//		if (!tempAESCrypt->NewSecureKey(PPassword, 1)) {
//			delete tempAESCrypt;
//			return false; // Erreur: Impossible de créer la clé AES
//		}
//
//		// Récupérer le sel utilisé pour la dérivation de clé
//		std::vector<BYTE> saltUsed = tempAESCrypt->GetSalt();
//
//		// Chiffrer le blob de clé privée avec AES
//		std::vector<BYTE> encryptedPrivateBlob;
//		const std::vector<BYTE>& privateBlob = RSACrypt->GetPrivateBlob();
//		if (!tempAESCrypt->EncryptBuffer(privateBlob, encryptedPrivateBlob)) {
//			delete tempAESCrypt;
//			return false; // Erreur: Échec du chiffrement AES
//		}
//
//		// Libérer l'objet AESCrypt temporaire
//		delete tempAESCrypt;
//
//		// Combiner le sel et le blob chiffré
//		// Format: [Taille du sel (4 octets)][Sel][Blob chiffré]
//		DWORD saltSize = saltUsed.size();
//		std::vector<BYTE> finalData(4 + saltSize + encryptedPrivateBlob.size());
//
//		// Écrire la taille du sel (4 octets)
//		memcpy(finalData.data(), &saltSize, 4);
//		// Écrire le sel
//		memcpy(finalData.data() + 4, saltUsed.data(), saltSize);
//		// Écrire le blob chiffré
//		memcpy(finalData.data() + 4 + saltSize, encryptedPrivateBlob.data(), encryptedPrivateBlob.size());
//
//		// Sauvegarder dans le fichier
//		return BufferToFile(finalData, filename);
//	}
//	catch (...) {
//		return false; // Erreur: Exception inconnue lors de la sauvegarde
//	}
//}

//bool __fastcall XRSAPwd::LoadKey(const UnicodeString& filename) {
//	//if (PPassword.IsEmpty()) return false;
//
//	try {
//		// Charger le fichier
//		std::vector<BYTE> fileData;
//		if (!FileToBuffer(filename, fileData) || fileData.size() < 8) {
//			return false; // Erreur: Fichier invalide ou trop petit
//		}
//
//		// Extraire la taille du sel (4 premiers octets)
//		DWORD saltSize = 0;
//		memcpy(&saltSize, fileData.data(), 4);
//
//		// Vérifier que les données sont cohérentes
//		if (fileData.size() < 4 + saltSize || saltSize == 0) {
//			return false; // Erreur: Données invalides ou corrompues
//		}
//
//		// Extraire le sel
//		std::vector<BYTE> salt(saltSize);
//		memcpy(salt.data(), fileData.data() + 4, saltSize);
//
//		// Extraire le blob chiffré
//		std::vector<BYTE> encryptedBlob(fileData.size() - 4 - saltSize);
//		memcpy(encryptedBlob.data(), fileData.data() + 4 + saltSize, encryptedBlob.size());
//
//		// Créer un nouvel objet XAESCrypt pour cette opération
//		XAESCrypt* tempAESCrypt = new XAESCrypt();
//
//		// Initialiser le nouvel objet AESCrypt avec le mot de passe et le sel
//		if (!tempAESCrypt->NewSecureKey(PPassword, salt, 1)) {
//			delete tempAESCrypt;
//			return false; // Erreur: Impossible de créer la clé AES
//		}
//
//		// Déchiffrer le blob de clé privée
//		std::vector<BYTE> privateBlob;
//		if (!tempAESCrypt->DecryptBuffer(encryptedBlob, privateBlob)) {
//			delete tempAESCrypt;
//			return false; // Erreur: Échec du déchiffrement AES
//		}
//
//		// Libérer l'objet AESCrypt temporaire
//		delete tempAESCrypt;
//
//		// Vérifier que c'est bien un blob de clé privée RSA
//		if (!RSACrypt->IsPrivateBlob(privateBlob)) {
//			return false; // Erreur: Le blob déchiffré n'est pas une clé privée RSA valide
//		}
//
//		// Nettoyer les clés existantes
//		RSACrypt->ClearContext();
//
//		// Importer le blob de clé privée dans RSACrypt
//		if (!RSACrypt->SetPrivateBlob(privateBlob)) {
//			return false; // Erreur: Impossible d'importer la clé privée
//		}
//
//		return true;
//	}
//	catch (...) {
//		return false; // Erreur: Exception inconnue lors du chargement
//	}
//}

bool __fastcall XRSAPwd::LoadBlobPrivate(const UnicodeString& filename) {
	// Vérifier que le mot de passe est défini
	if (PPassword.IsEmpty()) return false;

	try {
		// Charger le fichier
		std::vector<BYTE> fileData;
		if (!FileToBuffer(filename, fileData) || fileData.size() < 8) {
			return false; // Erreur: Fichier invalide ou trop petit
		}

		// Extraire la taille du sel (4 premiers octets)
		DWORD saltSize = 0;
		memcpy(&saltSize, fileData.data(), 4);

		// Vérifier que les données sont cohérentes
		if (fileData.size() < 4 + saltSize || saltSize == 0) {
			return false; // Erreur: Données invalides ou corrompues
		}

		// Extraire le sel
		std::vector<BYTE> salt(saltSize);
		memcpy(salt.data(), fileData.data() + 4, saltSize);

		// Extraire le blob chiffré
		std::vector<BYTE> encryptedBlob(fileData.size() - 4 - saltSize);
		memcpy(encryptedBlob.data(), fileData.data() + 4 + saltSize, encryptedBlob.size());

		// Créer un nouvel objet XAESCrypt pour cette opération
		XAESCrypt* tempAESCrypt = new XAESCrypt();

		// Initialiser le nouvel objet AESCrypt avec le mot de passe et le sel
		if (!tempAESCrypt->NewSecureKey(PPassword, salt, 1)) {
			delete tempAESCrypt;
			return false; // Erreur: Impossible de créer la clé AES
		}

		// Déchiffrer le blob de clé privée
		std::vector<BYTE> privateBlob;
		if (!tempAESCrypt->DecryptBuffer(encryptedBlob, privateBlob)) {
			delete tempAESCrypt;
			return false; // Erreur: Échec du déchiffrement AES
		}

		// Libérer l'objet AESCrypt temporaire
		delete tempAESCrypt;

		// Vérifier que c'est bien un blob de clé privée RSA
		if (!RSACrypt->IsPrivateBlob(privateBlob)) {
			return false; // Erreur: Le blob déchiffré n'est pas une clé privée RSA valide
		}

		// Nettoyer les clés existantes
		RSACrypt->ClearContext();

		// Importer le blob de clé privée dans RSACrypt
		if (!RSACrypt->SetPrivateBlob(privateBlob)) {
			return false; // Erreur: Impossible d'importer la clé privée
		}

		return true;
	}
	catch (...) {
		return false; // Erreur: Exception inconnue lors du chargement
	}
}

bool __fastcall XRSAPwd::LoadBlobPublic(const UnicodeString& filename) {
	try {
		std::vector<BYTE> blob;
		if (!FileToBuffer(filename, blob) || blob.empty()) return false; // Erreur: Fichier invalide ou vide
		RSACrypt->ClearContext();
		if (!RSACrypt->IsPublicBlob(blob)) return false; // Erreur: Le fichier ne contient pas une clé publique RSA valide
		if (!RSACrypt->SetPublicBlob(blob)) return false; // Erreur: Impossible d'importer la clé publique
		return true;
	}
	catch (...) {
		return false; // Erreur: Exception inconnue lors du chargement
	}
}

//---------------------------------------------------------------------------
// Sauvegarde des blobs de clés RSA
//---------------------------------------------------------------------------
bool __fastcall XRSAPwd::SaveBlobPrivate(const UnicodeString& filename) {
	// Vérifier que la clé privée est disponible et que le mot de passe est défini
	if (PPassword.IsEmpty() || !RSACrypt->PrivateReady) return false;

	try {
		// Nous allons chiffrer le blob de clé privée avec le mot de passe
		// Créer un nouvel objet XAESCrypt pour cette opération
		XAESCrypt* tempAESCrypt = new XAESCrypt();

		// Initialiser le nouvel objet AESCrypt avec le mot de passe
		if (!tempAESCrypt->NewSecureKey(PPassword, 1)) {
			delete tempAESCrypt;
			return false; // Erreur: Impossible de créer la clé AES
		}

		// Récupérer le sel utilisé pour la dérivation de clé
		std::vector<BYTE> saltUsed = tempAESCrypt->GetSalt();

		// Chiffrer le blob de clé privée avec AES
		std::vector<BYTE> encryptedPrivateBlob;
		const std::vector<BYTE>& privateBlob = RSACrypt->GetPrivateBlob();
		if (!tempAESCrypt->EncryptBuffer(privateBlob, encryptedPrivateBlob)) {
			delete tempAESCrypt;
			return false; // Erreur: Échec du chiffrement AES
		}

		// Libérer l'objet AESCrypt temporaire
		delete tempAESCrypt;

		// Combiner le sel et le blob chiffré
		// Format: [Taille du sel (4 octets)][Sel][Blob chiffré]
		DWORD saltSize = saltUsed.size();
		std::vector<BYTE> finalData(4 + saltSize + encryptedPrivateBlob.size());

		// Écrire la taille du sel (4 octets)
		memcpy(finalData.data(), &saltSize, 4);
		// Écrire le sel
		memcpy(finalData.data() + 4, saltUsed.data(), saltSize);
		// Écrire le blob chiffré
		memcpy(finalData.data() + 4 + saltSize, encryptedPrivateBlob.data(), encryptedPrivateBlob.size());

		// Sauvegarder dans le fichier
		return BufferToFile(finalData, filename);
	}
	catch (...) {
		return false; // Erreur: Exception inconnue lors de la sauvegarde
	}
}

bool __fastcall XRSAPwd::SaveBlobPublic(const UnicodeString& filename) {
	// Vérifier que la clé publique est disponible
	if (!RSACrypt->PublicReady) return false;

	try {
		// Récupérer le blob de clé publique
		const std::vector<BYTE>& publicBlob = RSACrypt->GetPublicBlob();
		
		// Sauvegarder directement le blob dans le fichier (sans chiffrement)
		return BufferToFile(publicBlob, filename);
	}
	catch (...) {
		return false; // Erreur: Exception inconnue lors de la sauvegarde
	}
}

//---------------------------------------------------------------------------
// Génération d'une nouvelle paire de clés RSA protégée par mot de passe
//---------------------------------------------------------------------------
bool __fastcall XRSAPwd::NewKeyPair(const UnicodeString& password) {
	// Vérifier que le mot de passe n'est pas vide
	if (password.IsEmpty()) return false;

	try {
		// Nettoyer les clés existantes
		ClearKey();
		RSACrypt->ClearContext();

		// Définir le mot de passe
		if (!SetPassword(password)) return false;

		// Générer une nouvelle paire de clés RSA
		if (!RSACrypt->NewKeyPair()) {
			ClearKey();
			return false; // Erreur: Impossible de générer la paire de clés RSA
		}

		// Vérifier que les clés ont été générées correctement
		if (!RSACrypt->PrivateReady || !RSACrypt->PublicReady) {
			ClearKey();
			RSACrypt->ClearContext();
			return false; // Erreur: Les clés n'ont pas été générées correctement
		}

		return true;
	}
	catch (...) {
		ClearKey();
		RSACrypt->ClearContext();
		return false; // Erreur: Exception inconnue lors de la génération de la paire de clés
	}
}