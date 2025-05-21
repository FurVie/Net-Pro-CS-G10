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
#define RECEIVED_FILES_DIR "received_files"

typedef struct {
    GtkWidget *window;
    GtkWidget *chat_area;
    GtkWidget *entry;
    GtkWidget *send_button;
    GtkWidget *file_button;
    char name[256];
    SSL *ssl;
} ClientData;

// Function declarations
void init_ssl(void);
void cleanup_ssl(void);
void *receive_data(void *arg);
void send_message(const char *message);
void send_file(const char *path);
void calculate_checksum(const unsigned char *data, size_t len, char *checksum);
void display_message(const char *sender, const char *message, const char *side);
void on_send_clicked(GtkWidget *widget, gpointer data);
void on_file_clicked(GtkWidget *widget, gpointer data);

// Global variables
SSL_CTX *ctx;
ClientData client_data;

// SSL initialization
void init_ssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
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
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(client_data.chat_area));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);
    gtk_text_buffer_insert_markup(buffer, &end, markup, -1);
    g_free(markup);
}

// Send message to server
void send_message(const char *message) {
    SSL_write(client_data.ssl, "TEXT", 4);
    
    char name_len[5];
    snprintf(name_len, sizeof(name_len), "%04d", (int)strlen(client_data.name));
    SSL_write(client_data.ssl, name_len, 4);
    SSL_write(client_data.ssl, client_data.name, strlen(client_data.name));
    
    SSL_write(client_data.ssl, message, strlen(message));
    display_message("You", message, "right");
}

// Send file to server
void send_file(const char *path) {
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
    
    // Send file data
    SSL_write(client_data.ssl, "FILE", 4);
    
    char name_len[5];
    snprintf(name_len, sizeof(name_len), "%04d", (int)strlen(client_data.name));
    SSL_write(client_data.ssl, name_len, 4);
    SSL_write(client_data.ssl, client_data.name, strlen(client_data.name));
    
    char filename_len[5];
    snprintf(filename_len, sizeof(filename_len), "%04d", (int)strlen(filename));
    SSL_write(client_data.ssl, filename_len, 4);
    SSL_write(client_data.ssl, filename, strlen(filename));
    
    char filesize_str[17];
    snprintf(filesize_str, sizeof(filesize_str), "%016ld", filesize);
    SSL_write(client_data.ssl, filesize_str, 16);
    
    SSL_write(client_data.ssl, checksum, 64);
    SSL_write(client_data.ssl, data, filesize);
    
    free(data);
    display_message("You", "File sent", "right");
}

// Receive data from server
void *receive_data(void *arg) {
    char buffer[BUFFER_SIZE];
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = SSL_read(client_data.ssl, buffer, 4);
        if (bytes <= 0) break;
        
        if (strncmp(buffer, "TEXT", 4) == 0) {
            // Handle text message
            char name_len[5] = {0};
            SSL_read(client_data.ssl, name_len, 4);
            int len = atoi(name_len);
            
            char sender[256] = {0};
            SSL_read(client_data.ssl, sender, len);
            
            memset(buffer, 0, sizeof(buffer));
            SSL_read(client_data.ssl, buffer, sizeof(buffer) - 1);
            
            if (strcmp(sender, client_data.name) != 0) {
                display_message(sender, buffer, "left");
            }
        }
        else if (strncmp(buffer, "FILE", 4) == 0) {
            // Handle file transfer
            char name_len[5] = {0};
            SSL_read(client_data.ssl, name_len, 4);
            int len = atoi(name_len);
            
            char sender[256] = {0};
            SSL_read(client_data.ssl, sender, len);
            
            char filename_len[5] = {0};
            SSL_read(client_data.ssl, filename_len, 4);
            len = atoi(filename_len);
            
            char filename[256] = {0};
            SSL_read(client_data.ssl, filename, len);
            
            char filesize_str[17] = {0};
            SSL_read(client_data.ssl, filesize_str, 16);
            long filesize = atol(filesize_str);
            
            char checksum[65] = {0};
            SSL_read(client_data.ssl, checksum, 64);
            
            // Show confirmation dialog
            char prompt[512];
            snprintf(prompt, sizeof(prompt),
                "%s wants to send you file '%s' (%.2f MB). Accept?",
                sender, filename, filesize / (1024.0 * 1024.0));

            GtkWidget *dialog = gtk_message_dialog_new(
                GTK_WINDOW(client_data.window),
                GTK_DIALOG_MODAL,
                GTK_MESSAGE_QUESTION,
                GTK_BUTTONS_YES_NO,
                "%s", prompt);

            int response = gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);

            if (response != GTK_RESPONSE_YES) {
                display_message("System", "File transfer rejected.", "left");
                // Discard the file data to keep the stream in sync
                unsigned char discard_buf[4096];
                size_t total_read = 0;
                while (total_read < filesize) {
                    int bytes = SSL_read(client_data.ssl, discard_buf, sizeof(discard_buf));
                    if (bytes <= 0) break;
                    total_read += bytes;
                }
                continue;
            }

            // Create received_files directory if it doesn't exist
            mkdir(RECEIVED_FILES_DIR, 0755);

            // Save file
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s", RECEIVED_FILES_DIR, filename);

            FILE *file = fopen(filepath, "wb");
            if (!file) {
                display_message("System", "Error saving file", "left");
                // Discard the file data
                unsigned char discard_buf[4096];
                size_t total_read = 0;
                while (total_read < filesize) {
                    int bytes = SSL_read(client_data.ssl, discard_buf, sizeof(discard_buf));
                    if (bytes <= 0) break;
                    total_read += bytes;
                }
                continue;
            }

            unsigned char *data = malloc(filesize);
            if (!data) {
                fclose(file);
                display_message("System", "Memory allocation failed", "left");
                // Discard the file data
                unsigned char discard_buf[4096];
                size_t total_read = 0;
                while (total_read < filesize) {
                    int bytes = SSL_read(client_data.ssl, discard_buf, sizeof(discard_buf));
                    if (bytes <= 0) break;
                    total_read += bytes;
                }
                continue;
            }

            size_t total_read = 0;
            while (total_read < filesize) {
                int bytes = SSL_read(client_data.ssl, data + total_read, filesize - total_read);
                if (bytes <= 0) break;
                total_read += bytes;
            }

            fwrite(data, 1, filesize, file);
            fclose(file);

            // Verify checksum
            char received_checksum[65];
            calculate_checksum(data, filesize, received_checksum);
            free(data);

            if (strcmp(checksum, received_checksum) == 0) {
                display_message(sender, "File received and verified", "left");
            } else {
                display_message(sender, "File received but checksum mismatch", "left");
            }
        }
    }
    
    display_message("System", "Connection lost", "left");
    return NULL;
}

// Callback functions
void on_send_clicked(GtkWidget *widget, gpointer data) {
    const char *message = gtk_entry_get_text(GTK_ENTRY(client_data.entry));
    if (strlen(message) > 0) {
        send_message(message);
        gtk_entry_set_text(GTK_ENTRY(client_data.entry), "");
    }
}

void on_file_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select File",
                                                   GTK_WINDOW(client_data.window),
                                                   GTK_FILE_CHOOSER_ACTION_OPEN,
                                                   "Cancel", GTK_RESPONSE_CANCEL,
                                                   "Open", GTK_RESPONSE_ACCEPT,
                                                   NULL);
    
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        send_file(filename);
        g_free(filename);
    }
    
    gtk_widget_destroy(dialog);
}

// Main client function
int main(int argc, char *argv[]) {
    // Initialize GTK
    gtk_init(&argc, &argv);
    
    // Initialize SSL
    init_ssl();
    
    // Initialize client data
    memset(&client_data, 0, sizeof(client_data));
    
    // Get server IP
    char server_ip[256];
    printf("Enter server IP: ");
    fgets(server_ip, sizeof(server_ip), stdin);
    server_ip[strcspn(server_ip, "\n")] = 0;
    
    // Get client name
    printf("Enter your name: ");
    fgets(client_data.name, sizeof(client_data.name), stdin);
    client_data.name[strcspn(client_data.name, "\n")] = 0;
    
    // Connect to server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Socket creation failed\n");
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(server_ip);
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        printf("Connection failed\n");
        close(sock);
        return 1;
    }
    
    // Create SSL connection
    client_data.ssl = SSL_new(ctx);
    SSL_set_fd(client_data.ssl, sock);
    
    if (SSL_connect(client_data.ssl) != 1) {
        ERR_print_errors_fp(stderr);
        close(sock);
        return 1;
    }
    
    // Create main window
    client_data.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(client_data.window), "Secure Chat Client");
    gtk_window_set_default_size(GTK_WINDOW(client_data.window), 600, 500);
    g_signal_connect(client_data.window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    
    // Create chat area
    client_data.chat_area = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(client_data.chat_area), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(client_data.chat_area), FALSE);
    
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                 GTK_POLICY_AUTOMATIC,
                                 GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scrolled_window), client_data.chat_area);
    
    // Create input area
    client_data.entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(client_data.entry), "Type your message...");
    
    client_data.send_button = gtk_button_new_with_label("Send");
    client_data.file_button = gtk_button_new_with_label("Send File");
    
    g_signal_connect(client_data.send_button, "clicked", G_CALLBACK(on_send_clicked), NULL);
    g_signal_connect(client_data.file_button, "clicked", G_CALLBACK(on_file_clicked), NULL);
    
    // Create layout
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    
    gtk_box_pack_start(GTK_BOX(hbox), client_data.entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), client_data.send_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), client_data.file_button, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
    
    gtk_container_add(GTK_CONTAINER(client_data.window), vbox);
    
    // Show all widgets
    gtk_widget_show_all(client_data.window);
    
    // Start receive thread
    pthread_t receive_thread;
    pthread_create(&receive_thread, NULL, receive_data, NULL);
    
    // Start GTK main loop
    gtk_main();
    
    // Cleanup
    SSL_free(client_data.ssl);
    close(sock);
    cleanup_ssl();
    
    return 0;
} 