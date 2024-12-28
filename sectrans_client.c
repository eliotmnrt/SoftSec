#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>

#define MAX_BUFFER 1024
#define AUTH_TOKEN "secure_token" // Jeton d'authentification

void send_command(const char* command, const char* payload, int port) {
    char buffer[MAX_BUFFER];
    snprintf(buffer, MAX_BUFFER, "%s %s %s", AUTH_TOKEN, command, payload);

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

    int port = 12345;

    if (strcmp(argv[1], "-up") == 0) {
        send_command("UPLOAD", argv[2], port);
    } else if (strcmp(argv[1], "-list") == 0) {
        send_command("LIST", "", port);
    } else if (strcmp(argv[1], "-down") == 0) {
        send_command("DOWNLOAD", argv[2], port);
    } else {
        fprintf(stderr, "Option invalide : %s\n", argv[1]);
        return 1;
    }

    return 0;
}
