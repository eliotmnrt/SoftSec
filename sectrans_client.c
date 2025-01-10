#include "client.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <regex.h>


#define MAX_BUFFER 1024

EVP_PKEY* localKey;
EVP_PKEY* peerKey;
unsigned char secret[32];
bool is_logged = false;
char current_user[256] = ""; 

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
    if (!ec_key) {
        fprintf(stderr, "Erreur : Impossible de créer EC_KEY\n");
        handle_openssl_error();
        return NULL;
    }

    const unsigned char* p = pubkey;
    if (!o2i_ECPublicKey(&ec_key, &p, pubkey_len)) {
        fprintf(stderr, "Erreur : Échec du décodage de la clé publique\n");
        handle_openssl_error();
        return NULL;
    }

    EVP_PKEY *peer_pkey = EVP_PKEY_new();
    if (!peer_pkey) {
        fprintf(stderr, "Erreur : Impossible de créer EVP_PKEY\n");
        handle_openssl_error();
        return NULL;
    }

    if (!EVP_PKEY_assign_EC_KEY(peer_pkey, ec_key)) {
        fprintf(stderr, "Erreur : Impossible d'associer la clé EC_KEY à EVP_PKEY\n");
        handle_openssl_error();
        return NULL;
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

void generate_rsa_keys(const char* private_key_path, const char* public_key_path) {
    int key_length = 2048; // Taille de la clé (2048 bits)
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;

    // Crée un contexte pour la génération des clés
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Erreur lors de la création du contexte EVP_PKEY.\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    // Initialise le contexte pour la génération de clés
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Erreur lors de l'initialisation du keygen.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Configure la taille des clés RSA
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_length) <= 0) {
        fprintf(stderr, "Erreur lors de la configuration de la taille des clés.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Génère la clé RSA
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Erreur lors de la génération des clés.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    EVP_PKEY_CTX_free(ctx);

    // Sauvegarde de la clé privée
    FILE* private_key_file = fopen(private_key_path, "wb") ;
    if (!private_key_file) {
        perror("Erreur lors de l'ouverture du fichier de clé privée");
        EVP_PKEY_free(pkey);
        return;
    }

    if (!PEM_write_PrivateKey(private_key_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Erreur lors de l'écriture de la clé privée.\n");
        ERR_print_errors_fp(stderr);
    }
    fclose(private_key_file);

    // Sauvegarde de la clé publique
    FILE* public_key_file = fopen(public_key_path, "wb");
    if (!public_key_file) {
        perror("Erreur lors de l'ouverture du fichier de clé publique");
        EVP_PKEY_free(pkey);
        return;
    }

    if (!PEM_write_PUBKEY(public_key_file, pkey)) {
        fprintf(stderr, "Erreur lors de l'écriture de la clé publique.\n");
        ERR_print_errors_fp(stderr);
    }
    fclose(public_key_file);

    // Libération des ressources
    EVP_PKEY_free(pkey);
    printf("Clés RSA générées et sauvegardées avec succès.\n");
}



int sign_message(const char* message, const char* private_key_path, unsigned char* signature, unsigned int* sig_len) {
    FILE* key_file = fopen(private_key_path, "r");
    if (!key_file) {
        perror("Erreur d'ouverture de la clé privée");
        return 0;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey)) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (!EVP_DigestSignUpdate(md_ctx, message, strlen(message))) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    size_t required_len = 0;
    if (!EVP_DigestSignFinal(md_ctx, NULL, &required_len)) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (!EVP_DigestSignFinal(md_ctx, signature, &required_len)) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    *sig_len = (unsigned int)required_len;

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return 1;
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
    // printf("clé pub");
    // for (size_t i = 0; i < pubkey_der_len; i++) {
    //     printf("%02X", pubkey_der[i]);
    // }
    char* encoded_key = base64_encode(pubkey_der, pubkey_der_len);
    OPENSSL_free(pubkey_der);
    EC_KEY_free(ec_key);

    return encoded_key;
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

int encrypt_message(const char* plaintext, const unsigned char* key, unsigned char* iv, unsigned char* ciphertext, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, strlen(plaintext))) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

void hash_password(const char* password, char* hash_output) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, password, strlen(password));
    EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
    EVP_MD_CTX_free(md_ctx);

    // Convertir le hash en chaîne hexadécimale
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&hash_output[i * 2], "%02x", hash[i]);
    }
}

#define MAX_FILE_SIZE (900)

// Fonction pour charger le contenu d'un fichier dans un buffer
char* load_file(const char* filename, size_t* file_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("ERROR: Impossible d'ouvrir le fichier");
        return NULL;
    }

    // Aller à la fin pour déterminer la taille
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    if (size < 0 || size > MAX_FILE_SIZE) {
        printf("ERROR: Taille de fichier invalide (%ld octets)\n", size);
        fclose(file);
        return NULL;
    }

    char* buffer = (char*)malloc(size + 1); // +1 pour le caractère nul
    if (!buffer) {
        perror("ERROR: Allocation mémoire échouée");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, size, file);
    buffer[size] = '\0'; // Null-terminate pour les chaînes
    fclose(file);

    if (file_size) {
        *file_size = (size_t)size;
    }
    
    return buffer;
}


char* prepare_payload(const char *user, char* filename) {
    printf("\nUSER %s\n", user);
    printf("FILENAME %s\n", filename);
    size_t file_size;
    char* file_content = load_file(filename, &file_size);
    if (!file_content) {
        return NULL;
    }

    // Allouer suffisamment d'espace pour le payload
    size_t payload_size = strlen(user) + 2 + strlen(filename) + 1 + file_size + 2;
    char* payload = (char*)malloc(payload_size);
    if (!payload) {
        perror("ERROR: Allocation mémoire échouée pour le payload");
        free(file_content);
        return NULL;
    }

    // Construire le payload : <filename> <file_content>
    snprintf(payload, payload_size, "%s %s %s", user, filename, file_content);
    printf("\n\nfile %s\n", payload);
    free(file_content);

    return payload;
}

bool handle_upload_command(const char* command, char* filename, int port){
    char buffer[MAX_BUFFER];

    unsigned char signature[256];
    unsigned int sig_len;
    printf("\nCURRENT USER DE TA MERE LA PUTE %s", current_user);

    char * payload = prepare_payload(current_user, filename);
    
    if(!payload){
        printf("invalid payload");
        return false;
    }

// Génération d'un IV aléatoire
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Erreur : impossible de générer l'IV.\n");
        return false;
    }
    

    // Signature du message chiffré
    if (!sign_message((char*)payload, "private_key.pem", signature, &sig_len)) {
        fprintf(stderr, "Erreur lors de la signature du message.\n");
        return false;
    }

    // Chiffrement du message (payload)
    unsigned char ciphertext[MAX_BUFFER];
    int ciphertext_len;
    if (!encrypt_message(payload, secret, iv, ciphertext, &ciphertext_len)) {
        fprintf(stderr, "Erreur : échec du chiffrement du message.\n");
        return false;
    }

    
    char* encoded_signature = base64_encode(signature, sig_len);

    // Encoder le message chiffré et l'IV en base64 pour l'envoi
    char* encoded_ciphertext = base64_encode(ciphertext, ciphertext_len);
    char* encoded_iv = base64_encode(iv, AES_BLOCK_SIZE);

    // printf("iv : ");
    // for (int i=0; i<16; i++){
    //     printf("%d", encoded_iv[i]);
    // }
    // printf("\n");
    // printf("Message : %s\n", payload);
    // printf("Message chiffré : %s\n", ciphertext);
    // printf("Message chiffré (base64) : %s\n", encoded_ciphertext);
    // printf("IV (base64) : %s\n", encoded_iv);

    // Création du buffer pour l'envoi
    snprintf(buffer, MAX_BUFFER, "%s %s %d %s %s", command, encoded_signature, sig_len, encoded_iv, encoded_ciphertext);

    // Envoi du message
    if (sndmsg(buffer, port) == 0) {
        // printf("Commande envoyée : %s\n", buffer);
        printf("Commande envoyée avec succès \n");
        return true;
    } else {
        fprintf(stderr, "Erreur : échec de l'envoi de la commande.\n");
        return false;
    }
}



void send_command(const char* command, char* payload, int port) {
    char buffer[MAX_BUFFER];

    unsigned char signature[256];
    unsigned int sig_len;

    // Génération d'un IV aléatoire
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Erreur : impossible de générer l'IV.\n");
        return;
    }
    

    // Signature du message chiffré
    if (!sign_message((char*)payload, "private_key.pem", signature, &sig_len)) {
        fprintf(stderr, "Erreur lors de la signature du message.\n");
        return;
    }

    // Chiffrement du message (payload)
    unsigned char ciphertext[MAX_BUFFER];
    int ciphertext_len;
    if (!encrypt_message(payload, secret, iv, ciphertext, &ciphertext_len)) {
        fprintf(stderr, "Erreur : échec du chiffrement du message.\n");
        return;
    }

    
    char* encoded_signature = base64_encode(signature, sig_len);

    // Encoder le message chiffré et l'IV en base64 pour l'envoi
    char* encoded_ciphertext = base64_encode(ciphertext, ciphertext_len);
    char* encoded_iv = base64_encode(iv, AES_BLOCK_SIZE);

    // printf("iv : ");
    // for (int i=0; i<16; i++){
    //     printf("%d", encoded_iv[i]);
    // }
    // printf("\n");
    // printf("Message : %s\n", payload);
    // printf("Message chiffré : %s\n", ciphertext);
    // printf("Message chiffré (base64) : %s\n", encoded_ciphertext);
    // printf("IV (base64) : %s\n", encoded_iv);

    // Création du buffer pour l'envoi
    snprintf(buffer, MAX_BUFFER, "%s %s %d %s %s", command, encoded_signature, sig_len, encoded_iv, encoded_ciphertext);

    // Envoi du message
    if (sndmsg(buffer, port) == 0) {
        // printf("Commande envoyée : %s\n", buffer);
        printf("Commande envoyée avec succès\n");
    } else {
        fprintf(stderr, "Erreur : échec de l'envoi de la commande.\n");
    }
}

void handle_ecdh_command(const char* buffer){
    size_t decoded_len = 0;
    unsigned char* decodedKey = base64_decode(buffer, &decoded_len);

    if (!decodedKey) {
        fprintf(stderr, "Erreur : Décodage Base64 échoué.\n");
        exit(1);
    }
    // printf("key size %d", decoded_len);
    // printf("Clé décodée (en hexadécimal) :\n");
    // for (size_t i = 0; i < decoded_len; i++) {
    //     printf("%02X", decodedKey[i]);
    // }
    // printf("\n");
    peerKey = decode_peer_public_key(decodedKey, decoded_len);
    if (!peerKey) {
        printf("Erreur : Échec du traitement de la clé publique distante\n");
        exit(1);
    }

    // Calcul du secret partagé
    size_t secret_len = sizeof(secret);
    size_t derived_len = derive_shared_secret(localKey, peerKey, secret, secret_len);

    // fprintf(stderr, "Secret partagé calculé avec succès (%zu octets).\n", derived_len);
    // for (size_t i = 0; i < derived_len; i++) {
    //     printf("%02X", secret[i]);
    // }
    // printf("\n\n\n");
}

void make_ecdh(){
    char bufferECDH[MAX_BUFFER];
    char *encodedPubKey = encode_public_key(localKey);
    // printf("\n\nkeyy %s\n", encodedPubKey);
    snprintf(bufferECDH, MAX_BUFFER, "ECDH %s", encodedPubKey);
    sndmsg(bufferECDH, 12345),

    memset(bufferECDH, 0, MAX_BUFFER);
    if(getmsg(bufferECDH) == 0){
        handle_ecdh_command(bufferECDH);
    }
    getmsg(bufferECDH);

}

void print_usage() {
    printf("Usage: %s -<option> <file>\n");
    printf("Options:\n");
    printf("  -up <file>        Upload a file to the server\n");
    printf("  -list <username>  List files for the given username\n");
    printf("  -down <file>      Download a file from the server\n");
    printf("  -register <user> <password>  Register a new user\n");
    printf("  -login <user> <password>     Login as an existing user\n");
}
bool validate_argument(const char *arg, const char* pattern){
    regex_t regex;
    int ret;
    ret=regcomp(&regex, pattern, REG_EXTENDED);
    if(ret){
        fprintf(stderr, "Erreur lors de la compilation de la regex\n");
        return false;
    }
    // Vérifier si l'arg correspond au pattern
    ret = regexec(&regex, arg, 0, NULL, 0);
    regfree(&regex);
    return ret==0;
}

bool validate_command(const char *command, const char *arg1, const char *arg2){
    const char * userPattern = "^[a-zA-Z0-9_]{3,20}$";
    const char * mdpPattern = "^[a-zA-Z0-9@#$^&+=]{4,20}$";
    if(strcmp(command,"-register")==0 || strcmp(command, "-login")==0){
        //Vérifier si aucun des deux arguments n'est nul
        if(!arg2 || !arg2){
            printf("ERROR: Nom d'utilisateur ou mot de passe manquant.\n");
            return false;
        }
        // pour user: chiffre et lettres entre 3 et 2O char autorisées
        // pour mdp: chiffre et lettrer et quelque char spéciaux entre 5 et 2O autorisées
        

        if (!validate_argument(arg1, userPattern) || !validate_argument(arg2, mdpPattern)){
            printf("ERROR: Format invalide pour le nom d'utilisateur ou le mot de passe.\n");
            return false;

        }
        return true;
    } else if (strcmp(command, "-up") == 0) {
        // Vérifie qu'il y a un argument
        if (!arg1) {
            printf("Erreur : Nom du fichier manquant.\n");
            return false;
        }
        if(arg2){
            printf("invalid number of args");
            return false;
        }

        // Valide le format du chemin de fichier
        // les / ne sont pas autorisés pour pas changer de dossier
        if (!validate_argument(arg1, "^[a-zA-Z0-9._/-]+$")) {
            printf("Erreur : Nom du fichier invalid.\n");
            return false;
        }
        return true;
    } else if (strcmp(command, "-down") == 0) {
        // Vérifie qu'il y a un argument
        if (!arg1) {
            printf("Erreur : Nom du fichier manquant.\n");
            return false;
        }
        if(arg2){
            printf("invalid number of args");
            return false;
        }

        // Valide le format du chemin de fichier
        // les / ne sont pas autorisés pour pas changer de dossier
        if (!validate_argument(arg1, "^[a-zA-Z0-9._-]+$") || (strstr(arg1, ".."))!=NULL) {
            printf("Erreur : Nom du fichier invalid.\n");
            return false;
        }
        return true;
        }
    else if (strcmp(command, "-list")==0){
        if (arg1 || arg2) {
            printf("Erreur: No args for -list.\n");
            return false;
        }
        return true;
    } else if (strcmp(command, "-help")==0){
        // Vérifie qu'il y a un argument
        if (arg1 || arg2) {
            printf("Erreur: No args for help.\n");
            return false;
        }
        return true;
        
    }
    
}
void handle_input(int serverPort) {
    char input[MAX_BUFFER];
    char buffer[MAX_BUFFER];

    while (true) {
        printf("\nEnter a command (-up, -list, -down, -register, -login, -help):\n> ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("Exiting...\n");
            break;
        }

        // Remove newline character
        input[strcspn(input, "\n")] = 0;

        // Parse the input
        char *command = strtok(input, " ");
        char *arg1 = strtok(NULL, " ");
        char *arg2 = strtok(NULL, " ");

        if (command == NULL) {
            printf("Invalid command. -help for usage \n ");
            continue;
        }
        // Vérifier si la commande est valide:
        if(!validate_command(command, arg1, arg2)){
            printf("invalid command, -help for usage \n");
            continue;
        }

        //Gestion des command
        if (strcmp(command, "-help") == 0){
            print_usage();
            continue;
        }

        if (strcmp(command, "-register") == 0 && arg1 && arg2) {
            make_ecdh();
            char hashed_password[65];
            hash_password(arg2, hashed_password);
            char logs[56];
            snprintf(logs, sizeof(logs), "%s %s", arg1, hashed_password);
            send_command("REGISTER", logs, serverPort);
        } else if (strcmp(command, "-login") == 0 && arg1 && arg2) {
            make_ecdh();
            char hashed_password[65];
            hash_password(arg2, hashed_password);
            char logs[56];
            snprintf(logs, sizeof(logs), "%s %s", arg1, hashed_password);
            send_command("LOGIN", logs, serverPort);
        } 
        
        if(!is_logged && strcmp(command, "-login") != 0 && strcmp(command, "-register") != 0){
            printf("Veuillez vous identifier avec -login ou -register avant d'effectuer cette commande");
            continue;
        }
        if (strcmp(command, "-up") == 0 && arg1) {
            printf("ARG1 %s", arg1);

            bool uploaded= handle_upload_command("UPLOAD", arg1, serverPort);
            if (!uploaded) continue;
        } else if (strcmp(command, "-list") == 0 && !arg1) {
            send_command("LIST", current_user , serverPort);
        } else if (strcmp(command, "-down") == 0 && arg1) {
            send_command("DOWNLOAD", arg1, serverPort);
        } else if (strcmp(command, "-login") != 0 && strcmp(command, "-register") != 0) {
            printf("Invalid command.\n");
            printf("Etes-vous log ? utilisez login ou register d'abord");
            continue;
        }

        // Receive server response
        memset(buffer, 0, MAX_BUFFER);
        printf("Waiting for Server response...\n");
        if (getmsg(buffer) == 0) {
            printf("Server response:\n%s\n", buffer);
            if (strcmp(buffer, "SUCCESS: Login successful") == 0 && strcmp(command, "-login") == 0){
                is_logged = true;
                strncpy(current_user, arg1, sizeof(current_user) - 1);
                current_user[sizeof(current_user) - 1] = '\0'; // Null-terminate
            }
        }

    }
}

int main(int argc, char *argv[]) {
    //  Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate local key pair
    localKey = generate_local_key();
    fprintf(stderr, "Local key generated successfully.\n");

    const char *private_key_path = "private_key.pem";
    const char *public_key_path = "public_key.pem";

    generate_rsa_keys(private_key_path, public_key_path);

    int serverPort = 12345;
    int clientPort = 54321;

    if (startserver(clientPort) != 0) {
        fprintf(stderr, "Error: Unable to start the server on port %d\n", clientPort);
        return 1;
    }
    printf("Client SecTrans started on port %d\n", clientPort);

    
    handle_input(serverPort);

    return 0;
}

