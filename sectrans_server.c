#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h> // Pour le chiffrement AES

#define MAX_BUFFER 1024
#define AUTH_TOKEN "secure_token" // Jeton d'authentification 

int authenticate_client(const char* token) {
    return (strcmp(token, AUTH_TOKEN) == 0);
}

void handle_client_command(const char* command, const char* payload) {
    if (strcmp(command, "UPLOAD") == 0) {
        printf("Commande UPLOAD reçue. Traitement du fichier %s\n", payload);
        // a implémenter 
    } else if (strcmp(command, "LIST") == 0) {
        printf("Commande LIST reçue. Envoi de la liste des fichiers.\n");
        // a implémenter 
    } else if (strcmp(command, "DOWNLOAD") == 0) {
        printf("Commande DOWNLOAD reçue. Envoi du fichier %s\n", payload);
        // a implémenter 
    } else {
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
            printf("Message reçu : %s\n", buffer);

            // Extraire le jeton d'authentification et la commande
            char token[MAX_BUFFER], command[MAX_BUFFER], payload[MAX_BUFFER];
            sscanf(buffer, "%s %s %[^\n]", token, command, payload);
            printf("%s\n", token);
            printf("%s\n", command);
            printf("%s\n", payload);
            if (!authenticate_client(token)) {
                printf("Erreur : client non authentifié.\n");
                continue;
            }

            handle_client_command(command, payload);
        } else {
            printf("Aucun message reçu.\n");
        }
    }

    stopserver();
    return 0;
}