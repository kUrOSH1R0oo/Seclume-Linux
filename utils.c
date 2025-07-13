/**
 * @file utils.c
 * @brief Utility functions for Seclume.
 */

#include "seclume.h"
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <fnmatch.h>

VerbosityLevel verbosity = VERBOSE_BASIC;

/**
 * @brief Converts POSIX file mode to a string representation (e.g., -rwxr-xr-x).
 * @param mode POSIX file mode (st_mode).
 * @param str Output string (must be at least 11 bytes).
 */
void mode_to_string(uint32_t mode, char *str) {
    str[0] = (S_ISDIR(mode)) ? 'd' : '-';
    str[1] = (mode & S_IRUSR) ? 'r' : '-';
    str[2] = (mode & S_IWUSR) ? 'w' : '-';
    str[3] = (mode & S_IXUSR) ? 'x' : '-';
    str[4] = (mode & S_IRGRP) ? 'r' : '-';
    str[5] = (mode & S_IWGRP) ? 'w' : '-';
    str[6] = (mode & S_IXGRP) ? 'x' : '-';
    str[7] = (mode & S_IROTH) ? 'r' : '-';
    str[8] = (mode & S_IWOTH) ? 'w' : '-';
    str[9] = (mode & S_IXOTH) ? 'x' : '-';
    str[10] = '\0';
}

/**
 * @brief Prints a message if verbosity level is sufficient.
 * @param level Required verbosity level.
 * @param fmt Format string.
 * @param ... Arguments for format string.
 */
void verbose_print(VerbosityLevel level, const char *fmt, ...) {
    if (verbosity < level) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/**
 * @brief Securely zeros a memory region.
 * @param ptr Pointer to memory.
 * @param len Length of memory to zero.
 */
void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) *p++ = 0;
}

/**
 * @brief Derives an AES key using PBKDF2 with SHA256.
 * @param password Password string.
 * @param salt Salt for PBKDF2.
 * @param key Output key (AES_KEY_SIZE bytes).
 * @param context Context string for key derivation.
 * @return 0 on success, 1 on failure.
 */
int derive_key(const char *password, const uint8_t *salt, uint8_t *key, const char *context) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (!kdf) {
        fprintf(stderr, "Error: PBKDF2 not available\n");
        return 1;
    }
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        fprintf(stderr, "Error: Failed to create KDF context\n");
        return 1;
    }

    OSSL_PARAM params[6];
    params[0] = OSSL_PARAM_construct_octet_string("pass", (void *)password, strlen(password));
    params[1] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, SALT_SIZE);
    params[2] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[3] = OSSL_PARAM_construct_int("iter", &(int){1000000});
    params[4] = OSSL_PARAM_construct_octet_string("info", (void *)context, strlen(context));
    params[5] = OSSL_PARAM_construct_end();

    int ret = EVP_KDF_derive(kctx, key, AES_KEY_SIZE, params);
    EVP_KDF_CTX_free(kctx);
    if (ret != 1) {
        fprintf(stderr, "Error: Key derivation failed\n");
        return 1;
    }
    return 0;
}

/**
 * @brief Computes HMAC-SHA256 of data.
 * @param key HMAC key.
 * @param data Data to hash.
 * @param data_len Length of data.
 * @param hmac Output HMAC (HMAC_SIZE bytes).
 * @return 0 on success, 1 on failure.
 */
int compute_hmac(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *hmac) {
    unsigned int len = HMAC_SIZE;
    if (!HMAC(EVP_sha256(), key, AES_KEY_SIZE, data, data_len, hmac, &len) || len != HMAC_SIZE) {
        fprintf(stderr, "Error: HMAC computation failed\n");
        return 1;
    }
    return 0;
}

/**
 * @brief Checks if a path contains traversal components (../).
 * @param path Path to check.
 * @return 1 if traversal detected, 0 otherwise.
 */
int has_path_traversal(const char *path) {
    if (strstr(path, "../") || strstr(path, "..\\") || strcmp(path, "..") == 0) {
        return 1;
    }
    const char *p = path;
    if (p[0] == '/') p++;
    if (strncmp(p, "..", 2) == 0 && (p[2] == '\0' || p[2] == '/')) {
        return 1;
    }
    return 0;
}

/**
 * @brief Checks if a password meets strength requirements.
 * @param password Password to check.
 * @param weak_password If 1, skip strength check.
 * @return 0 if strong or weak_password is 1, 1 if weak.
 */
int check_password_strength(const char *password, int weak_password) {
    if (weak_password) return 0;
    size_t len = strlen(password);
    if (len < 8) {
        fprintf(stderr, "Error: Password too short (minimum 8 characters)\n");
        return 1;
    }
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    for (size_t i = 0; i < len; i++) {
        if (password[i] >= 'A' && password[i] <= 'Z') has_upper = 1;
        else if (password[i] >= 'a' && password[i] <= 'z') has_lower = 1;
        else if (password[i] >= '0' && password[i] <= '9') has_digit = 1;
        else has_special = 1;
    }
    if (!(has_upper && has_lower && has_digit && has_special)) {
        fprintf(stderr, "Error: Password must contain uppercase, lowercase, digits, and special characters\n");
        return 1;
    }
    return 0;
}

/**
 * @brief Checks if a filename matches a glob pattern.
 * @param filename Filename to check.
 * @param pattern Glob pattern (e.g., "*.log").
 * @return 1 if the filename matches the pattern, 0 otherwise.
 */
int matches_glob_pattern(const char *filename, const char *pattern) {
    return fnmatch(pattern, filename, FNM_PATHNAME) == 0;
}