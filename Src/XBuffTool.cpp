#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XBuffTool.h"

//---------------------------------------------------------------------------
// Buffer <> Unicode
//---------------------------------------------------------------------------
bool __fastcall UnicodeToBuffer(const UnicodeString& str, std::vector<BYTE>& outbuffer) {
    // Convertir la chaîne Unicode en UTF-8
    UTF8String utf8Str = UTF8String(str);
    int byteCount = utf8Str.Length();

    // Créer un buffer pour stocker les données UTF-8
    outbuffer.resize(byteCount);

    // Copier les données UTF-8 dans le buffer
    if (byteCount > 0) {
        memcpy(outbuffer.data(), utf8Str.c_str(), byteCount);
    }

    return true;
}

UnicodeString __fastcall BufferToUnicode(const std::vector<BYTE>& buffer) {
    // Vérifier si le buffer est vide
    if (buffer.empty()) {
        return UnicodeString();
    }

    // Traiter le buffer comme des données UTF-8
    // Ajouter un terminateur nul pour la conversion en chaîne
    std::vector<BYTE> tempBuffer = buffer;
    tempBuffer.push_back(0); // Ajouter un terminateur nul

    // Convertir les données UTF-8 en UnicodeString
    return UnicodeString(UTF8String(reinterpret_cast<const char*>(tempBuffer.data())));
}

//---------------------------------------------------------------------------
// Buffer <> File
//---------------------------------------------------------------------------
bool __fastcall BufferToFile(const std::vector<BYTE>& buffer, UnicodeString outfile) {
    std::string outputFile = UnicodeToString(outfile);
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) return false;
    outFile.write((char*)buffer.data(), buffer.size());
    return true;
}

bool __fastcall FileToBuffer(const UnicodeString& infile, std::vector<BYTE>& buffer) {
    std::string inputFile = UnicodeToString(infile);
    std::ifstream inFile(inputFile, std::ios::binary);

	if (!inFile) return false; // throw std::runtime_error("Impossible d'ouvrir le fichier d'entrée");

    inFile.seekg(0, std::ios::end);
	std::streamsize fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

	if (fileSize == 0) return false;

	buffer.resize(fileSize);
    inFile.read(reinterpret_cast<char*>(buffer.data()), fileSize);

	return true;
}

//---------------------------------------------------------------------------
// Buffer <> Hexa Unicode
//---------------------------------------------------------------------------
bool __fastcall HexToBuffer(const UnicodeString& hexStr, std::vector<BYTE>& buffer) {
	int len = hexStr.Length();
	buffer.clear(); // Clear the buffer first to ensure we start fresh

	if (len % 2 != 0) return false; // Invalid hex string length

	for (int i = 1; i <= len; i += 2) {
		// Create a 2-character hex string
		wchar_t hexByte[3] = { hexStr[i], hexStr[i+1], 0 };

		// Convert hex to integer
		unsigned int value;
		if (swscanf(hexByte, L"%x", &value) != 1) {
			// Failed to parse hex value
			buffer.clear();
			return false;
		}

		buffer.push_back((BYTE)value);
	}
	return true;
}

UnicodeString __fastcall BufferToHex(const std::vector<BYTE>& buffer) {
    UnicodeString hexString;
    for (BYTE byte : buffer) {
        wchar_t hex[3];
        swprintf(hex, 3, L"%02X", byte);
        hexString += UnicodeString(hex);
    }
    return hexString;
}

//---------------------------------------------------------------------------
// Extract / Add AES key to Data    (chiffrée ou non)
//---------------------------------------------------------------------------
// Extrait la clé AES du buffer et modifie le buffer pour qu'il ne contienne plus que les données
bool __fastcall ExtractAESBlob(std::vector<BYTE>& buffer, std::vector<BYTE>& aesblob) {
	// Vérifier que le buffer est assez grand pour contenir au moins la taille de la clé
	if (buffer.size() < sizeof(DWORD)) return false; // Format de buffer invalide ou buffer corrompu
	// Extraire la taille de la clé
	DWORD aesblobsize = 0;
	memcpy(&aesblobsize, buffer.data(), sizeof(DWORD));

    // Vérifier que la taille de la clé est valide
	if (aesblobsize == 0 || aesblobsize > 1024 || buffer.size() < sizeof(DWORD) + aesblobsize) return false;

	// Extraire la clé AES
	aesblob.resize(aesblobsize);
	memcpy(aesblob.data(), buffer.data() + sizeof(DWORD), aesblobsize);

    // Calculer la taille du header (taille de la clé + clé)
	size_t headerSize = sizeof(DWORD) + aesblobsize;

    // Modifier le buffer pour qu'il ne contienne plus que les données
	// On déplace les données vers le début du buffer
    size_t dataSize = buffer.size() - headerSize;
	if (dataSize > 0) memmove(buffer.data(), buffer.data() + headerSize, dataSize);

    // Redimensionner le buffer pour qu'il ne contienne plus que les données
	buffer.resize(dataSize);

	return true;
}

// Ajoute une clé AES (sous forme de buffer) aux données en modifiant directement le buffer data
bool __fastcall CombineAESBlobWithData(std::vector<BYTE> &data, const std::vector<BYTE> &keyBuffer) {
    try {
		// Vérifier que le buffer de clé n'est pas vide
        if (keyBuffer.empty()) {
            throw std::runtime_error("Buffer de clé AES vide");
        }

        // Sauvegarder la taille originale des données
        size_t originalDataSize = data.size();

        // Calculer la nouvelle taille du buffer
        size_t newSize = sizeof(DWORD) + keyBuffer.size() + originalDataSize;

        // Redimensionner le buffer de données pour accueillir l'en-tête et la clé
        data.resize(newSize);

        // Déplacer les données originales vers la fin du buffer
        // Commencer par la fin pour éviter d'écraser des données
        for (size_t i = 0; i < originalDataSize; ++i) {
            size_t srcIdx = originalDataSize - 1 - i;
            size_t destIdx = newSize - 1 - i;
            data[destIdx] = data[srcIdx];
        }

        // Ajouter la taille du buffer de clé au début
        DWORD keySize = keyBuffer.size();
        memcpy(data.data(), &keySize, sizeof(DWORD));

        // Ajouter le buffer de clé après la taille
        memcpy(data.data() + sizeof(DWORD), keyBuffer.data(), keyBuffer.size());

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Erreur lors de l'ajout de la clé AES aux données: " << e.what() << std::endl;
        return false;
    }
}

//---------------------------------------------------------------------------
// Conversion Unicode -> String
//---------------------------------------------------------------------------
std::string __fastcall UnicodeToString(const UnicodeString& ustr) {
    // Pour les opérations de fichier, nous utilisons AnsiString
    // car les chemins de fichiers Windows sont généralement en ANSI
    AnsiString ansi(ustr);
    return std::string(ansi.c_str());
}