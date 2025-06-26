#!/bin/bash -eu

# Install dependencies
apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev libssl-dev

# Set up dependencies directory
DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

# Clean up any existing builds to avoid conflicts
rm -rf libubox/build ubus/build

# Download and build libubox (required for uhttpd)
if [ ! -d "libubox" ]; then
    echo "Downloading libubox..."
    git clone https://github.com/openwrt/libubox.git
    cd libubox
    rm -rf tests
    # Don't remove examples directory, just ensure it won't be built
    cd ..
fi

cd libubox

# Patch CMakeLists.txt to conditionally add examples directory
if [ -f CMakeLists.txt ]; then
    # Replace unconditional ADD_SUBDIRECTORY with conditional one
    sed -i 's/ADD_SUBDIRECTORY(examples)/IF(BUILD_EXAMPLES)\n  ADD_SUBDIRECTORY(examples)\nENDIF()/g' CMakeLists.txt
fi

mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_STATIC=ON \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

# Download and build libubus (optional but commonly used with uhttpd)
if [ ! -d "ubus" ]; then
    echo "Downloading libubus..."
    git clone https://git.openwrt.org/project/ubus.git
    cd ubus
    rm -rf tests
    # Don't remove examples directory, just ensure it won't be built
    cd ..
fi

cd ubus

# Patch CMakeLists.txt to conditionally add examples directory if needed
if [ -f CMakeLists.txt ]; then
    # Replace unconditional ADD_SUBDIRECTORY with conditional one
    sed -i 's/ADD_SUBDIRECTORY(examples)/IF(BUILD_EXAMPLES)\n  ADD_SUBDIRECTORY(examples)\nENDIF()/g' CMakeLists.txt
fi

mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

# Skip ustream-ssl build since we're disabling TLS for fuzzing
echo "Skipping ustream-ssl build (TLS disabled for fuzzing compatibility)"

# Return to source directory
cd ..

# Remove static declarations from functions we want to fuzz
echo "Making fuzzing target functions non-static..."
sed -i 's/static void client_parse_header/void client_parse_header/g' client.c
sed -i 's/static bool __handle_file_request/bool __handle_file_request/g' file.c

# Add function declarations to header if not already present
if ! grep -q "void client_parse_header" uhttpd.h; then
    echo "Adding client_parse_header declaration to uhttpd.h..."
    sed -i '/void uh_client_notify_state/a void client_parse_header(struct client *cl, char *data);' uhttpd.h
fi

if ! grep -q "bool __handle_file_request" uhttpd.h; then
    echo "Adding __handle_file_request declaration to uhttpd.h..."
    sed -i '/void client_parse_header/a bool __handle_file_request(struct client *cl, char *url, bool is_error_handler);' uhttpd.h
fi

# Set up build environment
: "${CFLAGS:=-O1 -fno-omit-frame-pointer}"
: "${LDFLAGS:=}"
: "${PKG_CONFIG_PATH:=}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"

# Add fuzzing and address sanitizer flags
export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link,address"
export LDFLAGS="$LDFLAGS -fsanitize=fuzzer-no-link,address"

# Add dependencies to build environment
export PKG_CONFIG_PATH="$DEPS_DIR/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include"
export LDFLAGS="$LDFLAGS -L$DEPS_DIR/install/lib"

# Add uhttpd-specific flags (disable TLS to avoid OpenSSL compatibility issues in fuzzing)
export CFLAGS="$CFLAGS -D_GNU_SOURCE -DHAVE_SHADOW -DHAVE_UBUS"
export CFLAGS="$CFLAGS -Wno-c23-extensions -std=gnu99"

echo "Compiling uhttpd source files..."

# Compile uhttpd source files (excluding main.c to avoid conflicts)
$CC $CFLAGS -c utils.c -o utils.o
$CC $CFLAGS -c client.c -o client.o  
$CC $CFLAGS -c file.c -o file.o
$CC $CFLAGS -c auth.c -o auth.o
$CC $CFLAGS -c proc.c -o proc.o
$CC $CFLAGS -c handler.c -o handler.o
$CC $CFLAGS -c listen.c -o listen.o
$CC $CFLAGS -c plugin.c -o plugin.o
$CC $CFLAGS -c relay.c -o relay.o
# Skip tls.c since TLS is disabled
$CC $CFLAGS -c cgi.c -o cgi.o

# Conditionally compile optional modules
if [ -f "ubus.c" ]; then
    echo "Compiling ubus support..."
    $CC $CFLAGS -c ubus.c -o ubus.o
    UBUS_OBJ="ubus.o"
else
    UBUS_OBJ=""
fi

if [ -f "lua.c" ]; then
    echo "Compiling Lua support..."
    $CC $CFLAGS -c lua.c -o lua.o
    LUA_OBJ="lua.o"
else
    LUA_OBJ=""
fi

if [ -f "ucode.c" ]; then
    echo "Compiling ucode support..."
    $CC $CFLAGS -c ucode.c -o ucode.o
    UCODE_OBJ="ucode.o"
else
    UCODE_OBJ=""
fi

echo "Creating mock libubox functions for fuzzing..."
cat > mock_libubox.c << 'EOF'
// Mock libubox functions for fuzzing
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Blob/blobmsg functions
void blob_buf_init(void *buf, int id) { 
    memset(buf, 0, 64); // Rough size estimate
}

void blob_buf_free(void *buf) { }

int blobmsg_add_string(void *buf, const char *name, const char *string) { 
    return 0; 
}

char *blobmsg_data(void *attr) { 
    static char dummy[] = "test"; 
    return dummy; 
}

char *blobmsg_name(void *attr) { 
    static char dummy[] = "name"; 
    return dummy; 
}

void *blob_data(void *attr) { 
    return attr; 
}

int blob_len(void *attr) { 
    return 4; 
}

int blobmsg_parse(void *policy, int policy_len, void **tb, void *data, int len) { 
    // Clear the table
    if (tb) {
        for (int i = 0; i < policy_len; i++) {
            tb[i] = NULL;
        }
    }
    return 0; 
}

char *blobmsg_get_string(void *attr) { 
    static char dummy[] = "value"; 
    return dummy; 
}

// Uloop functions  
void uloop_timeout_cancel(void *timeout) { }
void uloop_timeout_set(void *timeout, int msecs) { }

// List functions
void list_add(void *new, void *head) { }
void list_add_tail(void *new, void *head) { }
void list_del(void *entry) { }

// Utility functions
int canonpath(const char *path, char *result) { 
    if (result && path) {
        strncpy(result, path, 256);
        result[255] = '\0';
    }
    return path ? 1 : 0;
}

// Additional blob functions that might be needed
void blob_for_each_attr(void *pos, void *attr, int rem) { }
int blobmsg_type(void *attr) { return 0; }
int blobmsg_data_len(void *attr) { return 0; }
int blobmsg_parse_array(void *policy, int policy_len, void **tb, void *data, int len) { return 0; }
void *blobmsg_open_table(void *buf, const char *name) { return NULL; }
void blobmsg_close_table(void *buf, void *cookie) { }
int blobmsg_add_json_element(void *buf, const char *name, void *json) { return 0; }
int blobmsg_add_field(void *buf, int type, const char *name, void *data, int len) { return 0; }
void blobmsg_add_u32(void *buf, const char *name, uint32_t val) { }

// TLS functions (mocked since TLS is disabled)
int uh_tls_init(const char *key, const char *crt, const char *ciphers) { return 0; }
void uh_tls_client_attach(void *cl) { }
void uh_tls_client_detach(void *cl) { }
int uh_first_tls_port(int family) { return -1; }
EOF

$CC $CFLAGS -c mock_libubox.c -o mock_libubox.o

echo "Compiling fuzzer..."
$CC $CFLAGS -c uhttpd-fuzz.c -o uhttpd-fuzz.o

echo "Linking fuzzer..."
$CC $CFLAGS $LIB_FUZZING_ENGINE uhttpd-fuzz.o \
    utils.o client.o file.o auth.o proc.o handler.o listen.o plugin.o \
    relay.o cgi.o mock_libubox.o $UBUS_OBJ $LUA_OBJ $UCODE_OBJ \
    $LDFLAGS -ljson-c -lcrypt -ldl \
    -o $OUT/uhttpd_fuzzer

# Clean up object files
rm -f *.o

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/uhttpd_fuzzer"