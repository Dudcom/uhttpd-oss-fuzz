#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

// Mock some system includes that might not be available in fuzzing environment
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#else
// Windows equivalents or stubs
typedef int socklen_t;
#define AF_INET 2
#define AF_INET6 10
struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};
struct in_addr {
    unsigned long s_addr;
};
#endif

#include "uhttpd.h"

// Define missing macros that might be needed
#ifndef __HDR_MAX
#define __HDR_MAX 16
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

// Global configuration needed by uhttpd functions
struct config conf = {
    .docroot = "/tmp",
    .realm = "Test",
    .network_timeout = 30,
    .http_keepalive = 20,
    .max_script_requests = 3,
    .max_connections = 100,
    .cgi_prefix = "/cgi-bin",
    .cgi_path = "/bin:/usr/bin"
};

// Mock ustream functions to avoid crashes
int ustream_printf(struct ustream *s, const char *format, ...) { 
    (void)s; (void)format; // Suppress unused parameter warnings
    return 0;
}
void ustream_consume(struct ustream *s, int len) { 
    (void)s; (void)len; 
}
char *ustream_get_read_buf(struct ustream *s, int *len) { 
    (void)s; 
    *len = 0; 
    return NULL; 
}

// Mock other functions to avoid linking issues
void uh_request_done(struct client *cl) { 
    (void)cl; 
}
void uh_http_header(struct client *cl, int code, const char *summary) { 
    (void)cl; (void)code; (void)summary; 
}
void uh_chunk_printf(struct client *cl, const char *format, ...) { 
    (void)cl; (void)format; 
}
void uh_connection_close(struct client *cl) { 
    (void)cl; 
}
bool uh_use_chunked(struct client *cl) { 
    (void)cl; 
    return false; 
}
struct path_info *uh_path_lookup(struct client *cl, const char *url) { 
    (void)cl; (void)url; 
    return NULL; 
}
bool uh_auth_check(struct client *cl, const char *path, const char *auth, char **uptr, char **pptr) { 
    (void)cl; (void)path; (void)auth; (void)uptr; (void)pptr; 
    return true; 
}
void uh_dispatch_add(struct dispatch_handler *d) { 
    (void)d; 
}
void uh_invoke_handler(struct client *cl, struct dispatch_handler *d, char *url, struct path_info *pi) { 
    (void)cl; (void)d; (void)url; (void)pi; 
}
void uh_file_request(struct client *cl, const char *url, struct path_info *pi, struct blob_attr **tb) { 
    (void)cl; (void)url; (void)pi; (void)tb; 
}

// Helper function to initialize a mock client structure
static void init_client(struct client *cl) {
    memset(cl, 0, sizeof(*cl));
    
    // Initialize blob buffers
    blob_buf_init(&cl->hdr, 0);
    blob_buf_init(&cl->hdr_response, 0);
    
    // Set up basic client state
    cl->state = CLIENT_STATE_HEADER;
    cl->id = 1;
    
    // Initialize HTTP request
    memset(&cl->request, 0, sizeof(cl->request));
    cl->request.version = UH_HTTP_VER_1_1;
    cl->request.method = UH_HTTP_MSG_GET;
}

// Helper function to sanitize header data for client_parse_header
static char* sanitize_header_data(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    
    char *header = malloc(size + 1);
    if (!header) return NULL;
    
    // Copy data and ensure it's printable ASCII for HTTP headers
    for (size_t i = 0; i < size; i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            header[i] = data[i];
        } else if (data[i] == '\t' || data[i] == ' ') {
            header[i] = data[i]; // Allow tabs and spaces
        } else {
            header[i] = '_'; // Replace unprintable chars
        }
    }
    header[size] = '\0';
    
    // Ensure we have a valid header format (name: value)
    char *colon = strchr(header, ':');
    if (!colon && size > 10) {
        // Insert a colon to make it a valid header
        header[size/2] = ':';
    }
    
    return header;
}

// Helper function to sanitize URL data
static char* sanitize_url_data(const uint8_t *data, size_t size) {
    if (size == 0) return strdup("/");
    
    char *url = malloc(size + 2); // +2 for leading slash and null terminator
    if (!url) return NULL;
    
    url[0] = '/'; // URLs should start with /
    
    // Copy data and ensure it's valid URL characters
    size_t url_len = 1;
    for (size_t i = 0; i < size && url_len < size; i++) {
        char c = data[i];
        // Allow valid URL characters
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == '/' || c == '.' || 
            c == '-' || c == '_' || c == '~' || c == '%' || 
            c == '?' || c == '&' || c == '=') {
            url[url_len++] = c;
        }
    }
    url[url_len] = '\0';
    
    return url;
}

// Helper function to sanitize data for URL decoding
static char* sanitize_urldecode_data(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    
    char *input = malloc(size + 1);
    if (!input) return NULL;
    
    // For URL decoding, we want to test various percent-encoded sequences
    for (size_t i = 0; i < size; i++) {
        char c = data[i];
        // Allow printable ASCII and percent signs for encoding
        if ((c >= 32 && c <= 126)) {
            input[i] = c;
        } else {
            input[i] = '%'; // Replace with percent for encoding tests
        }
    }
    input[size] = '\0';
    
    return input;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0; // Need at least 4 bytes for our tests
    
    // Use first byte to determine which function to test
    uint8_t test_selector = data[0] % 4;
    const uint8_t *test_data = data + 1;
    size_t test_size = size - 1;
    
    struct client cl;
    init_client(&cl);
    
    switch (test_selector) {
        case 0: {
            // Test client_parse_header
            char *header_data = sanitize_header_data(test_data, test_size);
            if (header_data) {
                client_parse_header(&cl, header_data);
                free(header_data);
            }
            break;
        }
        
        case 1: {
            // Test __handle_file_request
            char *url_data = sanitize_url_data(test_data, test_size);
            if (url_data) {
                bool is_error_handler = (test_size > 0) ? (test_data[0] & 1) : false;
                __handle_file_request(&cl, url_data, is_error_handler);
                free(url_data);
            }
            break;
        }
        
        case 2: {
            // Test uh_urldecode
            char *input_data = sanitize_urldecode_data(test_data, test_size);
            if (input_data) {
                char output_buf[4096];
                uh_urldecode(output_buf, sizeof(output_buf), input_data, strlen(input_data));
                free(input_data);
            }
            break;
        }
        
        case 3: {
            // Test uh_handle_request
            char *url_data = sanitize_url_data(test_data, test_size);
            if (url_data) {
                // Since blob functions are mocked, just call uh_handle_request directly
                // The function will work with the mocked blob data
                uh_handle_request(&cl);
                free(url_data);
            }
            break;
        }
    }
    
    // Clean up blob buffers
    blob_buf_free(&cl.hdr);
    blob_buf_free(&cl.hdr_response);
    
    return 0;
}