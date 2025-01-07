#include "server.h"
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <dirent.h>

#define MAX_BUFFER 1024
#define AUTH_TOKEN "secure_token" // Jeton d'authentification 

/* int authenticate_client(const char* token) {
    return (strcmp(token, AUTH_TOKEN) == 0);
} */

int authenticate_user(const char* username, const char* hashed_password, const char * fileName) {

    FILE* file = fopen(fileName, "r");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier utilisateur\n");
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


unsigned char* base64_decode(const char* input) {
    BIO *bio, *b64;
    size_t input_len = strlen(input);
    unsigned char* buffer = (unsigned char*)malloc(input_len);
    
    bio = BIO_new_mem_buf((void*)input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore les nouvelles lignes dans l'entrée base64
    BIO_read(bio, buffer, input_len);
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

void handle_login_command(const char* buffer, char * fileNameLogin) {
    char username[256], hashedPassword[256];
    if (sscanf(buffer, "%s %s", username, hashedPassword) != 2) {
        printf("ERROR: Invalid login format\n");
        return;
    }

    if (authenticate_user(username, hashedPassword, fileNameLogin)) {
        printf("SUCCESS: Login successful\n");
    } else {
        printf("ERROR: Invalid credentials\n");
    }
}


void handle_register_command(const char* buffer, char * fileNameLogin) {
    char username[256], hashedPassword[256];
    if (sscanf(buffer, "%s %s", username, hashedPassword) != 2) {
        printf("ERROR: Invalid login format\n");
        exit(1);
    }

    FILE* file = fopen(fileNameLogin, "a");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier utilisateur\n");
        fclose(file);
        exit(1);
    }
    
    if (fprintf(file, "%s %s\n", username, hashedPassword) < 0) {
        perror("Erreur lors de l'écriture dans le fichier");
        fclose(file);
        exit(1);
    }

    fclose(file); // Fermer le fichier
    
}

void handle_list_command() {

    const char* directory_name = "files";
    printf("directory_name %s\n", directory_name);
    struct dirent* entry; // Structure pour représenter une entrée de répertoire

    // Ouvre le répertoire
    DIR* dir = opendir(directory_name);
    if (dir == NULL) {
        perror("Erreur lors de l'ouverture du répertoire files");
        return;
    }

    printf("Contenu du répertoire '%s' :\n", directory_name);

    // Parcourt chaque entrée du répertoire
    while ((entry = readdir(dir)) != NULL) {
        // Ignore les entrées spéciales "." et ".."
        if (entry->d_name[0] == '.' && 
           (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }

        printf("- %s\n", entry->d_name); // Affiche le nom du fichier ou du dossier
    }

    closedir(dir); // Ferme le répertoire

}

void handle_client_command(const char* command, const char* payload) {
    if (strcmp(command, "UPLOAD") == 0) {
        printf("Commande UPLOAD reçue. Traitement du fichier %s\n", payload);
        // a implémenter 
    } else if (strcmp(command, "LIST") == 0) {
        printf("Commande LIST reçue. Envoi de la liste des fichiers.\n");
        handle_list_command();
        // a implémenter 
    } else if (strcmp(command, "DOWNLOAD") == 0) {
        printf("Commande DOWNLOAD reçue. Envoi du fichier %s\n", payload);
        // a implémenter 
    } else if (strcmp(command, "REGISTER") == 0) {
        printf("Commande REGISTER reçue.%s\n", payload);
        handle_register_command(payload, "login.txt");
        // a implémenter 
    } else if (strcmp(command, "LOGIN") == 0) {
        printf("Commande LOGIN reçue. %s\n", payload);
        handle_login_command(payload, "login.txt");
    }else {
        printf("Commande non reconnue : %s\n", command);
    }
}

int main() {
    int port = 12345;
    char buffer[MAX_BUFFER];
    
    if (startserver(port) != 0) {
        fprintf(stderr, "Erreur : impossible de démarrer le serveur sur le port %d\n", port);
        return 1;
    }
    printf("Serveur SecTrans démarré sur le port %d\n", port);

    while (1) {
        memset(buffer, 0, MAX_BUFFER);
        if (getmsg(buffer) == 0) {
            printf("Message reçu : %s\n\n", buffer);

            // Extraire le le contenu de la commande recue
            char command[32], payload[MAX_BUFFER];
            char encoded_signature[512];
            int sig_len = 0;

            char* token = strtok(buffer, " "); // Extraire la commande
            if (token) {
                strncpy(command, token, sizeof(command));
                command[sizeof(command) - 1] = '\0'; 
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
            token = strtok(NULL, "\n"); // Extraire le payload
            if (token) {
                strncpy(payload, token, sizeof(payload));
                payload[sizeof(payload) - 1] = '\0';
            }

            printf("Commande : %s\n", command);
            printf("Signature : %s\n", encoded_signature);
            printf("Taille de la signature : %d\n", sig_len);
            printf("Payload : %s\n", payload);

            /* if (!authenticate_client(token)) {
                printf("Erreur : client non authentifié.\n");
                continue;
            } */
           char* decoded_signature = base64_decode(encoded_signature);
           if (verify_signature(payload, (const char *) decoded_signature, sig_len, "public_key.pem") != 1)
           {
                fprintf(stderr, "Erreur lors de la verification de la signature du message.\n");
                return 1;
           }
            handle_client_command(command, payload);
        } else {
            printf("Aucun message reçu.\n");
        }
    }

    stopserver();
    return 0;
}