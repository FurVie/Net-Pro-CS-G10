#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gtk/gtk.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 12345
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 10
#define RECEIVED_FILES_DIR "received_files"

typedef struct {
    SSL *ssl;
    struct sockaddr_in addr;
    char name[256];
} Client;

typedef struct {
    GtkWidget *window;
    GtkWidget *chat_area;
    GtkWidget *entry;
    GtkWidget *send_button;
    GtkWidget *file_button;
    char name[256];
    Client *clients[MAX_CLIENTS];
    int client_count;
    pthread_mutex_t clients_mutex;
} ServerData;

// Function declarations
void init_ssl(void);
void cleanup_ssl(void);
void *accept_clients(void *arg);
void *handle_client(void *arg);
void broadcast_message(const char *sender, const char *message);
void send_file_to_all(const char *path);
void calculate_checksum(const unsigned char *data, size_t len, char *checksum);
void display_message(const char *sender, const char *message, const char *side);
void on_send_clicked(GtkWidget *widget, gpointer data);
void on_file_clicked(GtkWidget *widget, gpointer data);

// Global variables
SSL_CTX *ctx;
ServerData server_data;

// SSL initialization
void init_ssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// SSL cleanup
void cleanup_ssl(void) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

// Calculate SHA-256 checksum
void calculate_checksum(const unsigned char *data, size_t len, char *checksum) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
    
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(checksum + (i * 2), "%02x", hash[i]);
    }
    checksum[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Display message in chat area
void display_message(const char *sender, const char *message, const char *side) {
    char *markup;
    if (strcmp(side, "right") == 0) {
        markup = g_markup_printf_escaped(
            "<span foreground=\"#00aaff\"><b>%s</b></span>: %s\n",
            sender, message);
    } else {
        markup = g_markup_printf_escaped(
            "<span foreground=\"#ffaa00\"><b>%s</b></span>: %s\n",
            sender, message);
    }
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(server_data.chat_area));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);
    gtk_text_buffer_insert_markup(buffer, &end, markup, -1);
    g_free(markup);
}

// Broadcast message to all clients
void broadcast_message(const char *sender, const char *message) {
    pthread_mutex_lock(&server_data.clients_mutex);
    
    for (int i = 0; i < server_data.client_count; i++) {
        if (server_data.clients[i]) {
            SSL_write(server_data.clients[i]->ssl, "TEXT", 4);
            
            char name_len[5];
            snprintf(name_len, sizeof(name_len), "%04d", (int)strlen(sender));
            SSL_write(server_data.clients[i]->ssl, name_len, 4);
            SSL_write(server_data.clients[i]->ssl, sender, strlen(sender));
            
            SSL_write(server_data.clients[i]->ssl, message, strlen(message));
        }
    }
    
    pthread_mutex_unlock(&server_data.clients_mutex);
}

// Accept new client connections
void *accept_clients(void *arg) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        return NULL;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(server_socket);
        return NULL;
    }

    if (listen(server_socket, 5) == -1) {
        perror("Listen failed");
        close(server_socket);
        return NULL;
    }

    // Get server's IP address
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent *host = gethostbyname(hostname);
    char ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, host->h_addr_list[0], ip_address, sizeof(ip_address));
    
    char startup_msg[512];
    snprintf(startup_msg, sizeof(startup_msg), "Server started on %s:%d", ip_address, PORT);
    display_message("System", startup_msg, "left");
    printf("%s\n", startup_msg);

    while (1) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, (socklen_t *)&client_len);
        
        if (client_socket == -1) {
            perror("Accept failed");
            continue;
        }

        // Create SSL connection
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);
        
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        // Create new client
        Client *client = malloc(sizeof(Client));
        if (!client) {
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        client->ssl = ssl;
        client->addr = client_addr;
        memset(client->name, 0, sizeof(client->name));

        // Add client to list
        pthread_mutex_lock(&server_data.clients_mutex);
        if (server_data.client_count < MAX_CLIENTS) {
            server_data.clients[server_data.client_count++] = client;
            pthread_mutex_unlock(&server_data.clients_mutex);
            
            // Start client handler thread
            pthread_t thread;
            pthread_create(&thread, NULL, handle_client, client);
            pthread_detach(thread);
        } else {
            pthread_mutex_unlock(&server_data.clients_mutex);
            SSL_free(ssl);
            close(client_socket);
            free(client);
        }
    }

    close(server_socket);
    return NULL;
}

// Handle client connection
void *handle_client(void *arg) {
    Client *client = (Client *)arg;
    char buffer[BUFFER_SIZE];
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = SSL_read(client->ssl, buffer, 4);
        if (bytes <= 0) break;
        
        if (strncmp(buffer, "TEXT", 4) == 0) {
            // Handle text message
            char name_len[5] = {0};
            SSL_read(client->ssl, name_len, 4);
            int len = atoi(name_len);
            
            char sender[256] = {0};
            SSL_read(client->ssl, sender, len);
            
            memset(buffer, 0, sizeof(buffer));
            SSL_read(client->ssl, buffer, sizeof(buffer) - 1);
            
            display_message(sender, buffer, "left");
            broadcast_message(sender, buffer);
        }
        else if (strncmp(buffer, "FILE", 4) == 0) {
            // Handle file transfer
            char name_len[5] = {0};
            SSL_read(client->ssl, name_len, 4);
            int len = atoi(name_len);
            
            char sender[256] = {0};
            SSL_read(client->ssl, sender, len);
            
            char filename_len[5] = {0};
            SSL_read(client->ssl, filename_len, 4);
            len = atoi(filename_len);
            
            char filename[256] = {0};
            SSL_read(client->ssl, filename, len);
            
            char filesize_str[17] = {0};
            SSL_read(client->ssl, filesize_str, 16);
            long filesize = atol(filesize_str);
            
            char checksum[65] = {0};
            SSL_read(client->ssl, checksum, 64);
            
            // Create received_files directory if it doesn't exist
            mkdir(RECEIVED_FILES_DIR, 0755);
            
            // Save file
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s", RECEIVED_FILES_DIR, filename);
            
            FILE *file = fopen(filepath, "wb");
            if (!file) {
                display_message("System", "Error saving file", "left");
                continue;
            }
            
            unsigned char *data = malloc(filesize);
            if (!data) {
                fclose(file);
                display_message("System", "Memory allocation failed", "left");
                continue;
            }
            
            size_t total_read = 0;
            while (total_read < filesize) {
                int bytes = SSL_read(client->ssl, data + total_read, filesize - total_read);
                if (bytes <= 0) break;
                total_read += bytes;
            }
            
            fwrite(data, 1, filesize, file);
            fclose(file);
            
            // Verify checksum
            char received_checksum[65];
            calculate_checksum(data, filesize, received_checksum);
            free(data);
            
            char result[512];
            if (strcmp(checksum, received_checksum) == 0) {
                snprintf(result, sizeof(result), "File %s received from %s ✅ Verified", filename, sender);
            } else {
                snprintf(result, sizeof(result), "File %s received from %s ❌ Checksum mismatch", filename, sender);
            }
            display_message("System", result, "left");
            broadcast_message("System", result);
        }
    }
    
    // Cleanup client
    pthread_mutex_lock(&server_data.clients_mutex);
    for (int i = 0; i < server_data.client_count; i++) {
        if (server_data.clients[i] == client) {
            server_data.clients[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&server_data.clients_mutex);
    
    SSL_free(client->ssl);
    free(client);
    return NULL;
}

// Callback functions
void on_send_clicked(GtkWidget *widget, gpointer data) {
    const char *message = gtk_entry_get_text(GTK_ENTRY(server_data.entry));
    if (strlen(message) > 0) {
        broadcast_message(server_data.name, message);
        display_message("You", message, "right");
        gtk_entry_set_text(GTK_ENTRY(server_data.entry), "");
    }
}

void on_file_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select File",
                                                   GTK_WINDOW(server_data.window),
                                                   GTK_FILE_CHOOSER_ACTION_OPEN,
                                                   "Cancel", GTK_RESPONSE_CANCEL,
                                                   "Open", GTK_RESPONSE_ACCEPT,
                                                   NULL);
    
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        send_file_to_all(filename);
        g_free(filename);
    }
    
    gtk_widget_destroy(dialog);
}

// Send file to all clients
void send_file_to_all(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        display_message("System", "Error opening file", "left");
        return;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Read file data
    unsigned char *data = malloc(filesize);
    if (!data) {
        fclose(file);
        display_message("System", "Memory allocation failed", "left");
        return;
    }
    
    fread(data, 1, filesize, file);
    fclose(file);
    
    // Calculate checksum
    char checksum[65];
    calculate_checksum(data, filesize, checksum);
    
    // Get filename
    const char *filename = strrchr(path, '/');
    if (!filename) filename = strrchr(path, '\\');
    if (!filename) filename = path;
    else filename++;
    
    pthread_mutex_lock(&server_data.clients_mutex);
    
    for (int i = 0; i < server_data.client_count; i++) {
        if (server_data.clients[i]) {
            // Send file data
            SSL_write(server_data.clients[i]->ssl, "FILE", 4);
            
            char name_len[5];
            snprintf(name_len, sizeof(name_len), "%04d", (int)strlen(server_data.name));
            SSL_write(server_data.clients[i]->ssl, name_len, 4);
            SSL_write(server_data.clients[i]->ssl, server_data.name, strlen(server_data.name));
            
            char filename_len[5];
            snprintf(filename_len, sizeof(filename_len), "%04d", (int)strlen(filename));
            SSL_write(server_data.clients[i]->ssl, filename_len, 4);
            SSL_write(server_data.clients[i]->ssl, filename, strlen(filename));
            
            char filesize_str[17];
            snprintf(filesize_str, sizeof(filesize_str), "%016ld", filesize);
            SSL_write(server_data.clients[i]->ssl, filesize_str, 16);
            
            SSL_write(server_data.clients[i]->ssl, checksum, 64);
            SSL_write(server_data.clients[i]->ssl, data, filesize);
        }
    }
    
    pthread_mutex_unlock(&server_data.clients_mutex);
    
    free(data);
    display_message("You", "File sent to all clients", "right");
}

// Main server function
int main(int argc, char *argv[]) {
    // Initialize GTK
    gtk_init(&argc, &argv);
    
    // Initialize SSL
    init_ssl();
    
    // Initialize server data
    memset(&server_data, 0, sizeof(server_data));
    pthread_mutex_init(&server_data.clients_mutex, NULL);
    
    // Get server name
    printf("Enter your name: ");
    fgets(server_data.name, sizeof(server_data.name), stdin);
    server_data.name[strcspn(server_data.name, "\n")] = 0;
    
    // Create main window
    server_data.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(server_data.window), "Secure Chat Server");
    gtk_window_set_default_size(GTK_WINDOW(server_data.window), 700, 500);
    g_signal_connect(server_data.window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    
    // Create chat area
    server_data.chat_area = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(server_data.chat_area), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(server_data.chat_area), FALSE);
    
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                 GTK_POLICY_AUTOMATIC,
                                 GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scrolled_window), server_data.chat_area);
    
    // Create input area
    server_data.entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(server_data.entry), "Type your message...");
    
    server_data.send_button = gtk_button_new_with_label("Send");
    server_data.file_button = gtk_button_new_with_label("Send File");
    
    g_signal_connect(server_data.send_button, "clicked", G_CALLBACK(on_send_clicked), NULL);
    g_signal_connect(server_data.file_button, "clicked", G_CALLBACK(on_file_clicked), NULL);
    
    // Create layout
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    
    gtk_box_pack_start(GTK_BOX(hbox), server_data.entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), server_data.send_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), server_data.file_button, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
    
    gtk_container_add(GTK_CONTAINER(server_data.window), vbox);
    
    // Show all widgets
    gtk_widget_show_all(server_data.window);
    
    // Start server thread
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, accept_clients, NULL);
    
    // Start GTK main loop
    gtk_main();
    
    // Cleanup
    cleanup_ssl();
    pthread_mutex_destroy(&server_data.clients_mutex);
    
    return 0;
} 