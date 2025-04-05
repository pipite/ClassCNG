#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XAESCrypt.h"

XAESCrypt::XAESCrypt(void) {
	// Initialisation des membres
	AESKey        = NULL;
	AESAlgorithm  = NULL;
	KeyIterations = 0;
	IVSIZE        = 32; // 256 bits pour AES-256
	AESBlob.clear();
	SaltBlob.clear();
}

XAESCrypt::~XAESCrypt(void) {
// Aucun nettoyage nécessaire
}

//---------------------------------------------------------------------------
// Cryptage / Decryptage String - AES
//---------------------------------------------------------------------------
UnicodeString __fastcall XAESCrypt::EncryptString(const UnicodeString& str) {
	if (AESKey == NULL) return "Erreur: Pas clé de chiffrement AES disponible";
	try {
		std::vector<BYTE> buff;
		std::vector<BYTE> encryptedBuffer;

		UnicodeToBuffer(str, buff);
		EncryptBuffer(buff, encryptedBuffer);
		return BufferToHex(encryptedBuffer);
	} catch (const std::exception& e) {
		return UnicodeString(L"Erreur: ") + UnicodeString(e.what());
	}
}

UnicodeString __fastcall XAESCrypt::DecryptString(const UnicodeString& str) {
	if (AESKey == NULL) return "Erreur: Pas clé de chiffrement AES disponible";
	try {
		std::vector<BYTE> buff;
		std::vector<BYTE> decryptedBuffer;

		HexToBuffer(str,buff);
		DecryptBuffer(buff, decryptedBuffer);
		return BufferToUnicode(decryptedBuffer);
	} catch (const std::exception& e) {
		return UnicodeString(L"Erreur: ") + UnicodeString(e.what());
	}
}

//---------------------------------------------------------------------------
// Cryptage / Decryptage fichier - AES
//---------------------------------------------------------------------------
bool __fastcall XAESCrypt::EncryptFile(const UnicodeString& infile, const UnicodeString& outfile) {
	if (AESKey == NULL) return false;
	try {
		std::vector<BYTE> fileBuffer;
		std::vector<BYTE> encryptedData;

		FileToBuffer(infile,fileBuffer);
		EncryptBuffer(fileBuffer, encryptedData);
		return BufferToFile(encryptedData, outfile);
	} catch (const std::exception& e) {
		return false;
	}
}

bool __fastcall XAESCrypt::DecryptFile(const UnicodeString& infile, const UnicodeString& outfile) {
	if (AESKey == NULL) return false;
	try {
		std::vector<BYTE> fileBuffer;
		std::vector<BYTE> decryptedData;

		FileToBuffer(infile,fileBuffer);
		DecryptBuffer(fileBuffer, decryptedData);
		return BufferToFile(decryptedData, outfile);
	} catch (const std::exception& e) {
		return false;
	}
}

//---------------------------------------------------------------------------
// Cryptage / Decryptage Buffer
//---------------------------------------------------------------------------
bool __fastcall XAESCrypt::EncryptBuffer(const std::vector<BYTE>& uncrypt, std::vector<BYTE>& crypt) {
	//if (AESKey == NULL) return false; // Erreur: Pas clé de déchiffrement disponible

	// Obtenir la taille du bloc
	DWORD blocklen = 0;
	DWORD resultlen = 0;
	NTSTATUS status = BCryptGetProperty(AESKey,BCRYPT_BLOCK_LENGTH,(PBYTE)&blocklen,sizeof(blocklen),&resultlen,0);
	if (!NT_SUCCESS(status)) return false; // Erreur lors de l'obtention de la taille du bloc

    // Appliquer le padding PKCS#7
	DWORD padsize = blocklen - (uncrypt.size() % blocklen);
	if (padsize == 0) padsize = blocklen; // Si la taille est déjà un multiple du bloc, ajouter un bloc complet

    // Créer un buffer pour les données avec padding
	std::vector<BYTE> paddata = uncrypt;
	paddata.resize(uncrypt.size() + padsize);

    // Remplir le padding avec la valeur du padding (PKCS#7)
	for (DWORD i = uncrypt.size(); i < paddata.size(); i++) {
		paddata[i] = static_cast<BYTE>(padsize);
    }

	// Générer un vecteur d'initialisation aléatoire
	std::vector<BYTE> iv(IVSIZE);
	BCRYPT_ALG_HANDLE hRndAlg = NULL;
	status = BCryptOpenAlgorithmProvider(&hRndAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) return false; // Impossible d'ouvrir un fournisseur d'algorithme BCRYPT_RNG_ALGORITHM
	status = BCryptGenRandom(hRndAlg, iv.data(), IVSIZE, 0);
	if (!NT_SUCCESS(status)) return false; // Impossible de générer un vecteur IV aléatoire
	BCryptCloseAlgorithmProvider(hRndAlg, 0);

	// Créer une copie du IV pour le chiffrement
	std::vector<BYTE> cryptIV = iv;

	// Calculer la taille du buffer chiffré
	DWORD cryptsize = 0;
	status = BCryptEncrypt(AESKey,const_cast<BYTE*>(paddata.data()),paddata.size(),NULL,cryptIV.data(),IVSIZE,NULL,0,&cryptsize,0);
	if (!NT_SUCCESS(status)) return false; // Erreur lors du calcul de la taille du buffer chiffré

    // Allouer un buffer pour les données chiffrées
	crypt.resize(cryptsize);

   // Réinitialiser IV pour le chiffrement réel
	cryptIV = iv;  // Réinitialiser avec une copie fraîche

    // Chiffrer les données
	status = BCryptEncrypt(AESKey,const_cast<BYTE*>(paddata.data()),paddata.size(),NULL,cryptIV.data(),IVSIZE,crypt.data(),crypt.size(),&cryptsize,0);

	if (!NT_SUCCESS(status)) return false; // Erreur lors du chiffrement

    // Ajuster la taille du buffer chiffré
	crypt.resize(cryptsize);

    // Ajouter le vecteur d'initialisation original au début des données chiffrées
	std::vector<BYTE> result(IVSIZE + crypt.size());
	memcpy(result.data(), iv.data(), IVSIZE);
	memcpy(result.data() + IVSIZE, crypt.data(), crypt.size());
	
	// Assigner le résultat final à crypt
	crypt = result;

	return true;
}

bool __fastcall XAESCrypt::DecryptBuffer(const std::vector<BYTE>& crypt, std::vector<BYTE>& uncrypt) {
	if (AESKey == NULL) return false; // Erreur: Pas clé de déchiffrement disponible

	// Verify that the encrypted data contains at least an initialization vector
//	const size_t IV_SIZE = IVSIZE; // Standard size for AES
	if (crypt.size() <= IVSIZE) return false; // Invalid or corrupted encrypted data

	// Get the block size
    DWORD blocklen = 0;
    DWORD resultlen = 0;
	NTSTATUS status = BCryptGetProperty(AESKey, BCRYPT_BLOCK_LENGTH, (PBYTE)&blocklen, sizeof(blocklen), &resultlen, 0);
    if (!NT_SUCCESS(status)) return false;

    // Extract the initialization vector
	std::vector<BYTE> iv(IVSIZE);
	memcpy(iv.data(), crypt.data(), IVSIZE);

    // Extract the encrypted data (everything except the IV)
	const size_t ciphertextSize = crypt.size() - IVSIZE;
    std::vector<BYTE> ciphertext(ciphertextSize);
	memcpy(ciphertext.data(), crypt.data() + IVSIZE, ciphertextSize);

    // Calculate the size of the decrypted buffer
    DWORD uncryptlen = 0;
    // Create a copy of the IV for the size calculation
	std::vector<BYTE> tempIV = iv;
	status = BCryptDecrypt(AESKey, const_cast<BYTE*>(ciphertext.data()), ciphertext.size(), NULL, tempIV.data(), IVSIZE, NULL, 0, &uncryptlen, 0);
    if (!NT_SUCCESS(status)) return false;

    // Allocate a buffer for the decrypted data
    uncrypt.resize(uncryptlen);

    // Decrypt the data using the original IV
	status = BCryptDecrypt(AESKey, const_cast<BYTE*>(ciphertext.data()), ciphertext.size(), NULL, iv.data(), IVSIZE, uncrypt.data(), uncrypt.size(), &uncryptlen, 0);
    if (!NT_SUCCESS(status)) return false;

    // Adjust the size of the decrypted buffer
    uncrypt.resize(uncryptlen);

    // Remove PKCS#7 padding
    if (!uncrypt.empty()) {
        BYTE padval = uncrypt.back();

        // Verify that the padding value is valid
        if (padval > 0 && padval <= blocklen && padval <= uncrypt.size()) {
            bool validPadding = true;

            // Verify that all padding bytes have the same value
            for (size_t i = uncrypt.size() - padval; i < uncrypt.size(); i++) {
                if (uncrypt[i] != padval) {
                    validPadding = false;
                    break;
                }
            }
            if (validPadding) uncrypt.resize(uncrypt.size() - padval);
        }
    }

    return true;
}

//---------------------------------------------------------------------------
// Génération d'une nouvelle clé AES sécurisée avec dérivation de clé HMAC
//---------------------------------------------------------------------------
bool __fastcall XAESCrypt::NewSecureKey(const UnicodeString& password, const DWORD iterations) {
	std::vector<BYTE> none;
	bool success = NewSecureKey(password, none, iterations);
	std::vector<BYTE>().swap(none);
    return success;
}

bool __fastcall XAESCrypt::NewSecureKey(const UnicodeString& password, const std::vector<BYTE>& salt, const DWORD iterations) {
	// Vérifier que le mot de passe n'est pas vide
	if (password.IsEmpty()) return false;

	ClearKey();

	// Stocker le nombre d'itérations
	KeyIterations = iterations;

	// Ouvrir un fournisseur d'algorithme AES
	NTSTATUS status = BCryptOpenAlgorithmProvider(&AESAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) { ClearKey(); return false; }

	// Configurer le mode de chaînage (CBC)
	status = BCryptSetProperty(AESAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(status)) { ClearKey(); return false; }

	if ( salt.empty() ) {
		// Générer un salt aléatoire
		std::vector<BYTE> saltIV;
		if (!NewRandomIV(saltIV)) { ClearKey(); return false; }
		SaltBlob = saltIV;
	} else {
		SaltBlob = salt;
    }

	// Définir la taille de la clé AES-256 (32 octets = 256 bits)
	const DWORD AES_256_KEY_SIZE = IVSIZE;

	// Dériver une clé à partir du mot de passe et du sel
	std::vector<BYTE> derivedKey;
	if (!DeriveKey(password, SaltBlob, derivedKey, iterations)) {
		ClearKey();
		return false;
	}

	// Obtenir la taille de l'objet clé AES
	DWORD AESKeySize = 0;
	DWORD resultLen = 0;
    status = BCryptGetProperty(AESAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&AESKeySize, sizeof(AESKeySize), &resultLen, 0);
    if (!NT_SUCCESS(status)) { ClearKey(); return false; }

    // Obtenir la taille du bloc AES (pour information)
    DWORD blockLength = 0;
	status = BCryptGetProperty(AESAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&blockLength, sizeof(blockLength), &resultLen, 0);
    if (!NT_SUCCESS(status)) { ClearKey(); return false; }

	// Créer la clé AES à partir de la clé dérivée
    // S'assurer que le buffer AESBlob est correctement dimensionné
	AESBlob.clear();
	AESBlob.resize(AESKeySize, 0);

	// Générer la clé symétrique
    status = BCryptGenerateSymmetricKey(
		AESAlgorithm,                       // Handle de l'algorithme AES
		&AESKey,                            // Handle de la clé générée
        AESBlob.data(),                     // Buffer pour l'objet clé
		AESKeySize,                         // Taille du buffer de l'objet clé
        derivedKey.data(),                  // Matériel de clé (clé dérivée)
        (ULONG)derivedKey.size(),           // Taille du matériel de clé (utiliser la taille réelle)
		0                                   // Flags
	);
	if (AESKey == NULL) {
		AESKeySize = 0;
	}
	if (!NT_SUCCESS(status)) { ClearKey(); return false; }

	// Effacer la clé dérivée et le hash de la mémoire pour des raisons de sécurité
	if (!derivedKey.empty()) {
		SecureZeroMemory(derivedKey.data(), derivedKey.size());
		derivedKey.clear();
		std::vector<BYTE>().swap(derivedKey);
	}

	return true;
}

bool __fastcall XAESCrypt::DeriveKey(const UnicodeString& password, std::vector<BYTE>& salt, std::vector<BYTE>& derivedKey, DWORD iterations) {
    // Créer un hash SHA-256 du mot de passe avec le sel
    BCRYPT_ALG_HANDLE  SHA256Algorithm    = NULL;
    BCRYPT_HASH_HANDLE SHA256Hash         = NULL;
	DWORD              SHA256HashBYTELen  = 0; // (size en BYTE  = 32 pour SHA 256)
    DWORD              SHA256HashDWORDLen = 0; // (size en DWORD =  4 pour SHA 256)

	// Ouvrir l'algorithme de hachage SHA-256
    NTSTATUS status = BCryptOpenAlgorithmProvider(&SHA256Algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) return false;

	// Obtenir la taille du hash SHA256
	status = BCryptGetProperty(SHA256Algorithm, BCRYPT_HASH_LENGTH, (PBYTE)&SHA256HashBYTELen, sizeof(SHA256HashBYTELen), &SHA256HashDWORDLen, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(SHA256Algorithm, 0);
		return false;
    }

    // Créer l'objet de hash SHA256
    status = BCryptCreateHash(SHA256Algorithm, &SHA256Hash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(SHA256Algorithm, 0);
        return false;
    }

    // Ajouter le sel au hash
	status = BCryptHashData(SHA256Hash, salt.data(), (ULONG)salt.size(), 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(SHA256Hash);
        BCryptCloseAlgorithmProvider(SHA256Algorithm, 0);
        return false;
    }

    if (password != L"") {
        // Ajouter le mot de passe au hash SHA256
        std::string pwd = UnicodeToString(password);
        status = BCryptHashData(SHA256Hash, (PBYTE)pwd.c_str(), (ULONG)pwd.length(), 0);
        if (!NT_SUCCESS(status)) {
            BCryptDestroyHash(SHA256Hash);
			BCryptCloseAlgorithmProvider(SHA256Algorithm, 0);
			return false;
        }
    }

    // Redimensionner le vecteur de sortie pour contenir le hash
    derivedKey.resize(SHA256HashBYTELen);

    // Obtenir le blob du hash SHA256
    status = BCryptFinishHash(SHA256Hash, derivedKey.data(), SHA256HashBYTELen, 0);
    BCryptDestroyHash(SHA256Hash);

	// Vérifier que le buffer de clé dérivée contient des données valides
    bool hasNonZero = false;
	for (size_t i = 0; i < derivedKey.size(); i++) {
        if (derivedKey[i] != 0) {
            hasNonZero = true;
			break;
        }
    }

	// Si la clé dérivée est entièrement nulle, c'est probablement une erreur
	if (!hasNonZero) {
		BCryptCloseAlgorithmProvider(SHA256Algorithm, 0);
		return false;
	}

	// Si des itérations supplémentaires sont demandées, appliquer PBKDF2 manuellement
    if (iterations > 1 && NT_SUCCESS(status)) {
        std::vector<BYTE> prevHash = derivedKey;

        for (DWORD i = 1; i < iterations; i++) {
            // Créer un nouveau hash pour chaque itération
            status = BCryptCreateHash(SHA256Algorithm, &SHA256Hash, NULL, 0, NULL, 0, 0);
            if (!NT_SUCCESS(status)) break;

            // Hasher le résultat précédent
            status = BCryptHashData(SHA256Hash, prevHash.data(), (ULONG)prevHash.size(), 0);
            if (!NT_SUCCESS(status)) {
                BCryptDestroyHash(SHA256Hash);
                break;
            }

            // Ajouter le sel à chaque itération pour plus de sécurité
            status = BCryptHashData(SHA256Hash, salt.data(), (ULONG)salt.size(), 0);
            if (!NT_SUCCESS(status)) {
                BCryptDestroyHash(SHA256Hash);
                break;
            }

            // Finaliser le hash
            status = BCryptFinishHash(SHA256Hash, prevHash.data(), SHA256HashBYTELen, 0);
            BCryptDestroyHash(SHA256Hash);
            if (!NT_SUCCESS(status)) break;

            // XOR avec la clé dérivée pour accumuler l'entropie
            for (size_t j = 0; j < derivedKey.size(); j++) {
                derivedKey[j] ^= prevHash[j];
            }
		}
    }

    BCryptCloseAlgorithmProvider(SHA256Algorithm, 0);
    return NT_SUCCESS(status);
}

bool __fastcall XAESCrypt::NewRandomIV(std::vector<BYTE>& iv) {
	BCRYPT_ALG_HANDLE RNGAlgorithm = NULL;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&RNGAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) return false;

	// Redimensionner le vecteur à la taille IVSIZE et initialiser à zéro
	iv.clear();
	iv.resize(IVSIZE, 0);

	// Vérifier que le vecteur a été correctement alloué
	if (iv.size() != IVSIZE || iv.data() == NULL) return false;

	// Générer des données aléatoires
	status = BCryptGenRandom(RNGAlgorithm, iv.data(), (ULONG)iv.size(), 0);
	BCryptCloseAlgorithmProvider(RNGAlgorithm, 0);
	if (!NT_SUCCESS(status)) return false;
	
	// Vérifier que les données ne sont pas toutes nulles (cas rare mais possible)
	bool allZeros = true;
	for (size_t i = 0; i < iv.size(); i++) {
		if (iv[i] != 0) {
			allZeros = false;
			break;
		}
	}
	
	// Si toutes les données sont nulles, considérer cela comme un échec
	if (allZeros) return false;
	
	return true;
}

void __fastcall XAESCrypt::ClearKey(void) {
	if (AESKey  != NULL) {
		BCryptDestroyKey(AESKey);
		AESKey  = NULL;
	}
	if (AESAlgorithm  != NULL) {
		BCryptCloseAlgorithmProvider(AESAlgorithm, 0);
		AESAlgorithm = NULL;
	}
	AESBlob.clear();
}

std::vector<BYTE> __fastcall XAESCrypt::GetSalt(void) {
	return SaltBlob;
};

bool __fastcall XAESCrypt::SetSalt(const std::vector<BYTE>& salt) {
    if (salt.empty()) return false;
	SaltBlob = salt;
    return true;
}

//---------------------------------------------------------------------------
// Méthodes pour la gestion AES Key <> blob
//---------------------------------------------------------------------------
bool __fastcall XAESCrypt::ExportBlob(const BCRYPT_KEY_HANDLE hKey, std::vector<BYTE>& aesblob) {
	if (hKey == NULL) return false; // Clé AES invalide

	// Obtenir la taille du blob de clé
	DWORD bloblen = 0;
	NTSTATUS status = BCryptExportKey(hKey,NULL,BCRYPT_KEY_DATA_BLOB,NULL,0,&bloblen,0);
	if (!NT_SUCCESS(status)) return false; // Impossible d'obtenir la taille du blob de clé AES

	// Allouer un buffer pour le blob de clé
	aesblob.resize(bloblen);

	// Exporter la clé
	status = BCryptExportKey(hKey,NULL,BCRYPT_KEY_DATA_BLOB,aesblob.data(),aesblob.size(),&bloblen,0);
	if (!NT_SUCCESS(status)) return false; // Impossible d'exporter la clé AES

	return true;
}

//---------------------------------------------------------------------------
// Sauvegarde et chargement de clé AES
//---------------------------------------------------------------------------
bool __fastcall XAESCrypt::SaveKey(const UnicodeString& filename) {
    // Vérifier que la clé AES est valide
	if ( AESKey == NULL ) return false;

    try {
        // Structure pour stocker les données de la clé
        struct KeyData {
            DWORD ivSize;
			DWORD keyIterations;
            DWORD saltSize;
			DWORD aesBlobSize;
        };

        // Exporter le blob AES
        std::vector<BYTE> exportedBlob;
		if (!ExportBlob(AESKey, exportedBlob)) return false;

        // Créer un buffer pour stocker toutes les données
        KeyData header;
        header.ivSize = IVSIZE;
        header.keyIterations = KeyIterations;
        header.saltSize = (DWORD)SaltBlob.size();
		header.aesBlobSize = (DWORD)exportedBlob.size();

        // Calculer la taille totale du buffer
		size_t totalSize = sizeof(KeyData) + SaltBlob.size() + exportedBlob.size();
        std::vector<BYTE> saveBuffer(totalSize);

        // Copier l'en-tête
        memcpy(saveBuffer.data(), &header, sizeof(KeyData));

        // Copier le sel
        memcpy(saveBuffer.data() + sizeof(KeyData), SaltBlob.data(), SaltBlob.size());

        // Copier le blob AES
        memcpy(saveBuffer.data() + sizeof(KeyData) + SaltBlob.size(),
			   exportedBlob.data(), exportedBlob.size());

        // Sauvegarder le buffer dans un fichier
        return BufferToFile(saveBuffer, filename);
    }
    catch (const std::exception&) {
        return false;
    }
}

bool __fastcall XAESCrypt::LoadKey(const UnicodeString& filename) {
    try {
        // Charger le fichier dans un buffer
        std::vector<BYTE> loadBuffer;
        if (!FileToBuffer(filename, loadBuffer)) return false;

        // Structure pour stocker les données de la clé
        struct KeyData {
            DWORD ivSize;
            DWORD keyIterations;
            DWORD saltSize;
            DWORD aesBlobSize;
        };

        // Vérifier que le buffer est assez grand pour contenir l'en-tête
		if (loadBuffer.size() < sizeof(struct KeyData)) return false;

		// Extraire l'en-tête
        KeyData header;
        memcpy(&header, loadBuffer.data(), sizeof(KeyData));

        // Vérifier que les tailles sont cohérentes
        if (loadBuffer.size() != sizeof(KeyData) + header.saltSize + header.aesBlobSize)
            return false;

        // Nettoyer les ressources existantes
        ClearKey();

        // Mettre à jour IVSIZE
        IVSIZE = header.ivSize;

        // Mettre à jour KeyIterations
        KeyIterations = header.keyIterations;

        // Extraire le sel
        SaltBlob.resize(header.saltSize);
        memcpy(SaltBlob.data(), loadBuffer.data() + sizeof(KeyData), header.saltSize);

        // Extraire le blob AES
        std::vector<BYTE> aesBlob(header.aesBlobSize);
        memcpy(aesBlob.data(),
               loadBuffer.data() + sizeof(KeyData) + header.saltSize,
               header.aesBlobSize);

        // Ouvrir un fournisseur d'algorithme AES
        NTSTATUS status = BCryptOpenAlgorithmProvider(&AESAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) { ClearKey(); return false; }

        // Configurer le mode de chaînage (CBC)
        status = BCryptSetProperty(AESAlgorithm, BCRYPT_CHAINING_MODE,
                                  (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                                  sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (!NT_SUCCESS(status)) { ClearKey(); return false; }

        // Obtenir la taille de l'objet clé AES
        DWORD AESKeySize = 0;
        DWORD resultLen = 0;
        status = BCryptGetProperty(AESAlgorithm, BCRYPT_OBJECT_LENGTH,
                                  (PBYTE)&AESKeySize, sizeof(AESKeySize), &resultLen, 0);
        if (!NT_SUCCESS(status)) { ClearKey(); return false; }

        // Préparer le buffer pour l'objet clé
        AESBlob.resize(AESKeySize);

        // Importer la clé AES
        status = BCryptImportKey(AESAlgorithm, NULL, BCRYPT_KEY_DATA_BLOB,
                                &AESKey, AESBlob.data(), (ULONG)AESBlob.size(),
                                aesBlob.data(), (ULONG)aesBlob.size(), 0);
        if (!NT_SUCCESS(status)) { ClearKey(); return false; }

        return true;
    }
    catch (const std::exception&) {
        ClearKey();
        return false;
    }
}




