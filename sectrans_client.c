#include "client.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#define MAX_BUFFER 1024
#define AUTH_TOKEN "secure_token" // Jeton d'authentification


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


void send_command(const char* command, const char* payload, int port) {
    char buffer[MAX_BUFFER];

    unsigned char signature[256];
    unsigned int sig_len;

    // Signature du message
    if (!sign_message(payload, "private_key.pem", signature, &sig_len)) {
        fprintf(stderr, "Erreur lors de la signature du message.\n");
    }
    char* encoded_signature = base64_encode(signature, sig_len);
    printf("signature %s\n", encoded_signature);
    printf("Message : %s\n", payload);
    snprintf(buffer, MAX_BUFFER, "%s %s %d %s", command, encoded_signature, sig_len, payload);

    if (sndmsg(buffer, port) == 0) {
        printf("Commande envoyée : %s\n", buffer);
    } else {
        fprintf(stderr, "Erreur : échec de l'envoi de la commande.\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage : %s -<option> <file>\n", argv[0]);
        return 1;
    }

    const char* private_key_path = "private_key.pem";
    const char* public_key_path = "public_key.pem";

    generate_rsa_keys(private_key_path, public_key_path);

    int port = 12345;

    if (strcmp(argv[1], "-up") == 0 && argv[2]) {
        send_command("UPLOAD", argv[2], port);
    } else if (strcmp(argv[1], "-list") == 0) {
        send_command("LIST", "", port);
    } else if (strcmp(argv[1], "-down") == 0  && argv[2]) {
        send_command("DOWNLOAD", argv[2], port);
    } else if (strcmp(argv[1], "-register") == 0 && argv[3]) {
        send_command("REGISTER", strcat(argv[2], argv[3]), port);
    } else if (strcmp(argv[1], "-login") == 0 && argv[3]) {
        send_command("LOGIN", strcat(argv[2], argv[3]), port);
    } else {
        fprintf(stderr, "Option invalide : %s\n", argv[1]);
        return 1;
    }

    return 0;
}
