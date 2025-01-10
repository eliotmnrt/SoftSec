#include "server.h"
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <dirent.h>
#include <openssl/ec.h>


#define MAX_BUFFER 1024

int serverPort = 12345;
int clientPort = 54321;

EVP_PKEY* localKey;
EVP_PKEY* peerKey;
unsigned char secret[32];

// Gérer les erreurs OpenSSL
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Génération d'une paire de clés locale
EVP_PKEY* generate_local_key() {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) handle_openssl_error();

    if (EVP_PKEY_paramgen_init(pctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) handle_openssl_error();

    EVP_PKEY* params = NULL;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) handle_openssl_error();

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx) handle_openssl_error();

    if (EVP_PKEY_keygen_init(kctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) handle_openssl_error();

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);

    return pkey;
}

// Décoder une clé publique distante brute (non compressée)
EVP_PKEY* decode_peer_public_key(const unsigned char* pubkey, size_t pubkey_len) {
    if (!pubkey || pubkey_len != 65) {
        fprintf(stderr, "Erreur : Clé publique invalide ou longueur incorrecte\n");
        return NULL;
    }

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) handle_openssl_error();

    const unsigned char* p = pubkey;
    if (!o2i_ECPublicKey(&ec_key, &p, pubkey_len)) {
        fprintf(stderr, "Erreur : Échec du décodage de la clé publique\n");
        handle_openssl_error();
    }

    EVP_PKEY* peer_pkey = EVP_PKEY_new();
    if (!peer_pkey) handle_openssl_error();

    if (!EVP_PKEY_assign_EC_KEY(peer_pkey, ec_key)) {
        fprintf(stderr, "Erreur : Impossible d'associer la clé EC_KEY à EVP_PKEY\n");
        handle_openssl_error();
    }

    return peer_pkey;
}

// Calcul du secret partagé
size_t derive_shared_secret(EVP_PKEY* local_key, EVP_PKEY* peer_key, unsigned char* secret, size_t secret_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_key, NULL);
    if (!ctx) handle_openssl_error();

    if (EVP_PKEY_derive_init(ctx) <= 0) handle_openssl_error();

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        fprintf(stderr, "Erreur : Impossible de définir la clé publique distante\n");
        handle_openssl_error();
    }

    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) handle_openssl_error();

    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) handle_openssl_error();

    EVP_PKEY_CTX_free(ctx);
    return secret_len;
}

char* base64_encode(const unsigned char* input, int length) {
    BIO* bmem = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Supprime les sauts de ligne
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char* encoded = (char*)malloc(bptr->length + 1);
    memcpy(encoded, bptr->data, bptr->length);
    encoded[bptr->length] = '\0';

    BIO_free_all(b64);
    return encoded;
}

// Fonction pour encoder une clé publique EC en base64
char* encode_public_key(EVP_PKEY* pkey) {
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        fprintf(stderr, "Erreur : Impossible de récupérer la clé EC\n");
        return NULL;
    }

    // Convertir la clé publique EC en format DER
    unsigned char* pubkey_der = NULL;
    int pubkey_der_len = i2o_ECPublicKey(ec_key, &pubkey_der);
    if (pubkey_der_len <= 0) {
        fprintf(stderr, "Erreur : Impossible de convertir la clé publique en DER\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    // Encoder la clé publique en base64
    printf("clé pub : ");
    for (size_t i = 0; i < pubkey_der_len; i++) {
        printf("%02X", pubkey_der[i]);
    }
    printf("\n");
    char* encoded_key = base64_encode(pubkey_der, pubkey_der_len);
    OPENSSL_free(pubkey_der);
    EC_KEY_free(ec_key);

    return encoded_key;
}

void send_message_to_client(const char *message) {
    // Check if the message is NULL
    int clientPort = 54321;

    if (message == NULL) {
        fprintf(stderr, "Error: message is NULL.\n");
        return;
    }

    // Check the message size
    size_t message_length = strlen(message);
    
    // Create a buffer for the message
    char buffer[4096] = {0};
    strncpy(buffer, message, 4096 - 1); // Copy the message into the buffer (with null-termination)

    // Send the message using sndmsg
    int result = sndmsg(buffer, clientPort);

    // Check the result of sndmsg
    if (result == 0) {
        printf("Message sent successfully to port %d.\n", clientPort);
    } else {
        fprintf(stderr, "Error: Failed to send message to port %d. sndmsg returned %d.\n", clientPort, result);
    }
}


int authenticate_user(const char* username, const char* hashed_password, const char * fileName) {

    FILE* file = fopen(fileName, "r");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier utilisateur\n");
        send_message_to_client("ERROR: Erreur lors de l'ouverture du fichier utilisateur");
        return 0; // Impossible de lire le fichier
    }

    char file_username[256], file_hashed_password[256];
    // Lire le fichier ligne par ligne
    while (fscanf(file, "%s %s", file_username, file_hashed_password) == 2) {
        if (strcmp(file_username, username) == 0 && strcmp(file_hashed_password, hashed_password) == 0) {
            fclose(file);
            return 1; // Utilisateur authentifié
        }
    }

    fclose(file);
    return 0; // Échec de l'authentification
}


unsigned char* base64_decode(const char* input, size_t* decodedLen) {
    BIO *bio, *b64;
    size_t input_len = strlen(input);
    unsigned char* buffer = (unsigned char*)malloc(input_len);
    
    bio = BIO_new_mem_buf((void*)input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore les nouvelles lignes dans l'entrée base64
    *decodedLen = BIO_read(bio, buffer, input_len);
    BIO_free_all(bio);

    return buffer;
}


int verify_signature(const char* message, const char* signature, size_t sig_len, const char* public_key_path) {
    // 1. Charger la clé publique
    FILE* key_file = fopen(public_key_path, "r");
    if (!key_file) {
        perror("Erreur d'ouverture de la clé publique");
        return 0;
    }
    EVP_PKEY* pubkey = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!pubkey) {
        fprintf(stderr, "Erreur lors de la lecture de la clé publique.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // 2. Créer un contexte pour la vérification
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Erreur de création du contexte EVP.\n");
        EVP_PKEY_free(pubkey);
        return 0;
    }

    // 3. Initialiser la vérification
    if (!EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey)) {
        fprintf(stderr, "Erreur lors de l'initialisation de la vérification.\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pubkey);
        return 0;
    }

    // 4. Fournir le message à vérifier
    if (!EVP_DigestVerifyUpdate(md_ctx, message, strlen(message))) {
        fprintf(stderr, "Erreur lors de la mise à jour de la vérification.\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pubkey);
        return 0;
    }

    // 5. Vérifier la signature
    int result = EVP_DigestVerifyFinal(md_ctx, (unsigned char*)signature, sig_len);
    if (result == 1) {
        printf("Signature valide.\n");
    } else if (result == 0) {
        printf("Signature invalide.\n");
    } else {
        fprintf(stderr, "Erreur lors de la vérification de la signature.\n");
        ERR_print_errors_fp(stderr);
    }

    // 6. Libérer les ressources
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pubkey);

    return result == 1; // Retourne 1 si la signature est valide
}


int decrypt_message(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len;
    int plaintext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    plaintext[plaintext_len] = '\0'; // Null-terminate plaintext
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


#define MAX_FILE_SIZE (900)


void handle_upload_command(const char* payload) {
    char filename[256], username[256];

    const char* file_content;
    // EXTRACTION DU USERNAME
    const char* first_space = strchr(payload, ' ');
    if (!first_space) {
        printf("ERROR: Format de payload invalide pour UPLOAD\n");
        send_message_to_client("ERROR: Format de payload invalide pour UPLOAD");
        return;
    }
    size_t username_length = first_space - payload;
    strncpy(username, payload, username_length);
    username[username_length] = '\0';
    printf("USERNAME: %s", username);
    
    // Extraction du nom de fichier FILENAME
    const char * second_space = strchr(first_space+1, ' ');
    if (!second_space) {
        printf("ERROR: Format de payload invalide pour UPLOAD\n");
        send_message_to_client("ERROR: Format de payload invalide pour UPLOAD");
        return;
    }
    size_t filename_length = second_space - (first_space + 1);


    if (filename_length >= sizeof(filename)) {
        printf("ERROR: Nom de fichier trop long\n");
        send_message_to_client("ERROR: Nom de fichier trop long");
        return;
    }
    strncpy(filename, first_space + 1, filename_length);
    filename[filename_length] = '\0';

    printf("FILENAME: %s\n", filename);



    // Extraction du contenu du fichier (FILE CONTENT)
    file_content = second_space + 1;
    size_t content_length = strlen(file_content);


    
    if (!file_content) {
        printf("ERROR: Format de payload invalide pour UPLOAD\n");
        send_message_to_client("ERROR: Format de payload invalide pour UPLOAD");
        return;
    }
    if (content_length > MAX_FILE_SIZE) {
        printf("ERROR: Fichier trop volumineux (%zu octets)\n", content_length);
        send_message_to_client("ERROR: Fichier trop volumineux");
        return;
    }
    for (size_t i = 0; i < content_length; i++) {
        if (file_content[i] < 32 && file_content[i] != '\n' && file_content[i] != '\r' && file_content[i] != '\t') {
            printf("ERROR: Contenu du fichier non valide (caractère binaire détecté)\n");
            send_message_to_client("ERROR: Contenu du fichier non valide");
            return;
        }
    }

    printf("file content: %s\n", file_content);

    // Écriture du fichier sur le serveur
    char path[512];
    snprintf(path, sizeof(path), "./files/%s/%s", username, filename);
    FILE* file = fopen(path, "w");
    if (!file) {
        perror("ERROR: Impossible de créer le fichier sur le serveur");
        send_message_to_client("ERROR: Impossible de créer le fichier sur le serveur");
        return;
    }
    fwrite(file_content, 1, content_length, file);
    fclose(file);

    printf("SUCCESS: Fichier '%s' téléchargé avec succès (%zu octets)\n", filename, content_length);
    send_message_to_client("SUCCESS: Fichier téléchargé avec succès");
}


void handle_download_command(const char* payload) {
    char filename[256], username[256];
    // Extract `username` and `filename` from the payload
    if (sscanf(payload, "%s %s", username, filename) != 2) {
        printf("ERROR: Payload format incorrect: %s\n", payload);
        send_message_to_client("ERROR: Format de payload invalide");
        return;
    }

    // Construct the file path with username directory
    char filepath[512] = "./files/";
    strcat(filepath, username);    // Append username
    strcat(filepath, "/");         // Add trailing slash
    strcat(filepath, filename);    // Append the filename

    // Vérification du nom du fichier (évite les attaques par parcours de répertoires)
    if (strstr(filename, "../") || strchr(filename, '/') || strchr(filename, '\\')) {
        printf("ERROR: Nom de fichier invalide : %s\n", filename);
        send_message_to_client("ERROR: Nom de fichier invalide");
        return;
    }

    // Ouvrir le fichier en mode lecture
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        perror("ERROR: Impossible d'ouvrir le fichier");
        send_message_to_client("ERROR: Impossible d'ouvrir le fichier");
        return;
    }

    // Obtenir la taille du fichier
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // Vérifier si le fichier est trop volumineux
    if (file_size > MAX_FILE_SIZE) {
        printf("ERROR: Fichier trop volumineux (%ld octets)\n", file_size);
        send_message_to_client("ERROR: Fichier trop volumineux");
        fclose(file);
        return;
    }

    // Lire le contenu du fichier
    char* file_content = (char*)malloc(file_size + 1);
    if (!file_content) {
        printf("ERROR: Mémoire insuffisante\n");
        send_message_to_client("ERROR: Mémoire insuffisante");

        fclose(file);
        return;
    }

    size_t bytes_read = fread(file_content, 1, file_size, file);
    if (bytes_read != file_size) {
        printf("ERROR: Erreur lors de la lecture du fichier\n");
        send_message_to_client("ERROR: Erreur lors de la lecture du fichier");
        free(file_content);
        fclose(file);
        return;
    }
    file_content[file_size] = '\0'; // Null-terminate le contenu

    fclose(file);

    // Envoyer le contenu au client (simulé ici avec un affichage)
    printf("SUCCESS: Fichier '%s' téléchargé (%ld octets)\n", filename, file_size);
    printf("Contenu du fichier :\n%s\n", file_content);
    send_message_to_client(file_content);

    free(file_content);
}


void handle_login_command(const char* buffer, char * fileNameLogin) {
    char username[256], hashedPassword[256];
    if (sscanf(buffer, "%s %s", username, hashedPassword) != 2) {
        printf("ERROR: Invalid login format\n");
        send_message_to_client("ERROR: Invalid login format\n");

        return;
    }

    if (authenticate_user(username, hashedPassword, fileNameLogin)) {
        printf("SUCCESS: Login successful\n");
        send_message_to_client("SUCCESS: Login successful");

    } else {
        printf("ERROR: Invalid credentials\n");
        send_message_to_client("ERROR: Invalid credentials\n");


    }
}


void handle_register_command(const char* buffer, char * fileNameLogin) {
    char username[256], hashedPassword[256];
    if (sscanf(buffer, "%s %s", username, hashedPassword) != 2) {
        printf("ERREUR: Format du login invalide\n");
        send_message_to_client("ERROR: Format du login invalide\n");
        exit(1);
    }

    FILE* file = fopen(fileNameLogin, "a");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier utilisateur\n");
        send_message_to_client("ERROR: problème avec l'ouverture du fichier utilisateur");
        fclose(file);
        exit(1);
    }
    
    if (fprintf(file, "%s %s\n", username, hashedPassword) < 0) {
        perror("Erreur lors de l'écriture dans le fichier");
        send_message_to_client("ERROR: l'écriture dans le fichier échoué");
        fclose(file);
        exit(1);
    }


    fclose(file);

    //ajout de du repertoire du client
    char dir[512];
    snprintf(dir, sizeof(dir), "./files/%s", username);

    if (mkdir(dir, 0700) == 0) {
        printf("Répertoire client créé avec succès : %s\n", dir);
        send_message_to_client("SUCCESS: Répertoire client crée avec succès");
    } else {
        // Gérer les erreurs
        if (errno == EEXIST) {
            printf("Le répertoire client existe déjà : %s\n", dir);
            send_message_to_client("ERROR: l'utilisateur existe déjà");
        } else {
            perror("Erreur lors de la création du répertoire client");
            send_message_to_client("ERROR: erreur lors de la création du répertoire client");
        }
    }
}

void handle_ecdh_command(const char* buffer){

    char *encodedPubKey = encode_public_key(localKey);
    sndmsg(encodedPubKey, clientPort);

    size_t decoded_len = 0;
    unsigned char* decodedKey = base64_decode(buffer, &decoded_len);

    if (!decodedKey) {
        fprintf(stderr, "Erreur : Décodage Base64 échoué.\n");
        send_message_to_client("Error: Décodage Base64 échoué ");
        exit(1);
    }
    printf("key size %d\n", decoded_len);
    printf("Clé décodée (en hexadécimal) :\n");
    for (size_t i = 0; i < decoded_len; i++) {
        printf("%02X", decodedKey[i]);
    }
    printf("\n");

    peerKey = decode_peer_public_key(decodedKey, decoded_len);

    if (!peerKey) {
        printf("Erreur : Échec du traitement de la clé publique distante\n");
        send_message_to_client("ERROR: Échec du traitement de la clé publique distante");
        exit(1);
    }

    // Calcul du secret partagé
    size_t secret_len = sizeof(secret);
    size_t derived_len = derive_shared_secret(localKey, peerKey, secret, secret_len);

    fprintf(stderr, "Secret partagé calculé avec succès (%zu octets).\n", derived_len);
    for (size_t i = 0; i < derived_len; i++) {
        printf("%02X", secret[i]);
    }
    printf("\n\n\n");
}
void handle_list_command(const char * username) {
    char directory_name[1024];
    snprintf(directory_name, sizeof(directory_name), "files/%s", username);

    printf("directory_name: %s\n", directory_name);

    struct dirent* entry; // Structure pour représenter une entrée de répertoire

    // Ouvre le répertoire
    DIR* dir = opendir(directory_name);
    if (dir == NULL) {
        perror("Erreur lors de l'ouverture du répertoire files");
        send_message_to_client("Erreur lors de l'ouverture du répertoire files");

        return;
    }

    printf("Contenu du répertoire '%s' :\n", directory_name);
    char response[4096] = ""; 
    size_t response_length = 0;
    int is_empty=1;

    // Parcourt chaque entrée du répertoire
    while ((entry = readdir(dir)) != NULL) {
        // Ignore les entrées spéciales "." et ".."
        if (entry->d_name[0] == '.' && 
           (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }
        is_empty=0; // si une entrée est trouvée, le répertoire n'est pas vide

        // Ajoute le nom du fichier ou du dossier au buffer
        response_length += snprintf(response + response_length, 
                                    sizeof(response) - response_length, 
                                    "- %s\n", entry->d_name);

        // Vérifie que le buffer n'est pas plein
        if (response_length >= sizeof(response)) {
            fprintf(stderr, "Buffer overflow: contenu du répertoire trop grand\n");
            break;
        } 
    }
    if(is_empty){
        strncpy(response, "Dossier vide\n", sizeof(response)-1);
        response[sizeof(response)-1] = '\0'; 
    }
    send_message_to_client(response);

    closedir(dir); // Ferme le répertoire

}


void handle_client_command(const char* command, const char* payload) {
    if (strcmp(command, "UPLOAD") == 0) {
        printf("Commande UPLOAD reçue. \n");
        // necessite que le client soit enregistré auparavant
        handle_upload_command(payload);
    } else if (strcmp(command, "LIST") == 0) {
        printf("Commande LIST reçue. Envoi de la liste des fichiers. %s\n", payload);
        handle_list_command(payload);
        // a implémenter 
    } else if (strcmp(command, "DOWNLOAD") == 0) {
        printf("Commande DOWNLOAD reçue. Envoi du fichier %s\n", payload);
        handle_download_command(payload);
    } else if (strcmp(command, "REGISTER") == 0) {
        printf("Commande REGISTER reçue.%s\n", payload);
        handle_register_command(payload, "login.txt");
    } else if (strcmp(command, "LOGIN") == 0) {
        printf("Commande LOGIN reçue. %s\n", payload);
        handle_login_command(payload, "login.txt");
    } else if (strcmp(command, "ECDH") == 0) {
        printf("Commande ECDH reçue. %s\n", payload);
        handle_ecdh_command(payload);
    } else {
        printf("Commande non reconnue : %s\n", command);
    }
}

int main() {
    
    char buffer[MAX_BUFFER];
    
    if (startserver(serverPort) != 0) {
        fprintf(stderr, "Erreur : impossible de démarrer le serveur sur le port %d\n", serverPort);
        return 1;
    }
    printf("Serveur SecTrans démarré sur le port %d\n", serverPort);

    // Initialisation d'OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Génération de la paire de clés locale
    localKey = generate_local_key();
    fprintf(stderr, "Clé locale générée avec succès.\n");

    while (1) {
        memset(buffer, 0, MAX_BUFFER);
        if (getmsg(buffer) == 0) {
            printf("Message reçu : %s\n\n", buffer);

            // Extraire le le contenu de la commande recue
            char command[32], payload[MAX_BUFFER];
            char encoded_signature[512];
            int sig_len = 0;
            char encodedIv[25];

            char* token = strtok(buffer, " "); // Extraire la commande
            if (token) {
                strncpy(command, token, sizeof(command));
                command[sizeof(command) - 1] = '\0'; 
            }

            if (strcmp(command, "ECDH") == 0){
                token = strtok(NULL, "\n"); // Extraire le payload
                if (token) {
                    strncpy(payload, token, sizeof(payload));
                    payload[sizeof(payload) - 1] = '\0';
                }
                printf("payload : %s\n", payload);
                
                handle_ecdh_command(payload);
            }

            token = strtok(NULL, " ");  // Extraire la signature
            if (token) {
                strncpy(encoded_signature, token, sizeof(encoded_signature));
                encoded_signature[sizeof(encoded_signature) - 1] = '\0';
            }
            token = strtok(NULL, " "); // Extraire sig_len
            if (token) {
                sig_len = atoi(token); 
            }
            token = strtok(NULL, " "); // Extraire le payload
            if (token) {
                strncpy(encodedIv, token, sizeof(encodedIv));
                encodedIv[sizeof(encodedIv) - 1] = '\0';
            }
            token = strtok(NULL, "\n"); // Extraire le payload
            if (token) {
                strncpy(payload, token, sizeof(payload));
                payload[sizeof(payload) - 1] = '\0';
            }

            printf("Commande : %s\n", command);
            printf("Signature : %s\n", encoded_signature);
            printf("Taille de la signature : %d\n", sig_len);
            printf("encoded iv : %s\n", encodedIv);
            printf("Payload : %s\n", payload);
            

            if (strcmp(command, "ECDH") != 0){
                
                size_t decoded_payload_len = 0;
                char * decoded_payload = base64_decode(payload, &decoded_payload_len);
                printf("decoded payload : %s\n", decoded_payload);
                size_t decoded_sig_len = 0;
                char* decoded_signature = base64_decode(encoded_signature, &decoded_sig_len);

                size_t decoded_iv_len = 0;
                unsigned char* iv = base64_decode(encodedIv, &decoded_iv_len);

                decrypt_message(decoded_payload, decoded_payload_len, secret, iv, payload);

                if (verify_signature(payload, (const char *) decoded_signature, sig_len, "public_key.pem") != 1)
                {
                    fprintf(stderr, "Erreur lors de la verification de la signature du message.\n");
                    return 1;
                }
                printf("payload : %s\n", payload);
            }
            handle_client_command(command, payload);
        } else {
            printf("Aucun message reçu.\n");
        }
    }

    stopserver();
    return 0;
}