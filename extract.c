/**
 * @file extract.c
 * @brief Extraction function for Seclume.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

/**
 * @brief Extracts and decrypts files from a .slm archive.
 * @param archive Path to the input archive file (.slm).
 * @param password Password for decryption.
 * @param outdir User-specified output directory (NULL to use archive's outdir or current directory).
 * @param force If 1, overwrite existing output files.
 * @return 0 on success, 1 on failure.
 */
int extract_files(const char *archive, const char *password, const char *outdir, int force) {
    if (!archive || !password) {
        fprintf(stderr, "Error: Invalid extract parameters\n");
        return 1;
    }
    FILE *in = fopen(archive, "rb");
    if (!in) {
        fprintf(stderr, "Error: Cannot open archive file %s: %s\n", archive, strerror(errno));
        return 1;
    }
    ArchiveHeader header;
    if (fread(&header, sizeof(header), 1, in) != 1) {
        fprintf(stderr, "Error: Failed to read archive header\n");
        fclose(in);
        return 1;
    }
    CompressionAlgo algo;
    if (strncmp(header.magic, "SLM", 4) != 0 || (header.version < 4 || header.version > 6)) {
        fprintf(stderr, "Error: Invalid archive format or version (expected 4 to 6, got %d)\n", header.version);
        fclose(in);
        return 1;
    }
    if (header.version == 4) {
        algo = COMPRESSION_LZMA; // Version 4 is always LZMA
    } else {
        algo = header.compression_algo;
        if (algo != COMPRESSION_ZLIB && algo != COMPRESSION_LZMA) {
            fprintf(stderr, "Error: Invalid compression algorithm in header (%d)\n", algo);
            fclose(in);
            return 1;
        }
    }
    if (header.file_count > MAX_FILES) {
        fprintf(stderr, "Error: Too many files in archive (%u > %d)\n", header.file_count, MAX_FILES);
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_BASIC, "Read archive header, version %d, %u files, compression %s level %d",
                  header.version, header.file_count, algo == COMPRESSION_ZLIB ? "zlib" : "LZMA", header.compression_level);
    uint8_t file_key[AES_KEY_SIZE];
    uint8_t meta_key[AES_KEY_SIZE];
    if (derive_key(password, header.salt, file_key, "file encryption") != 0 ||
        derive_key(password, header.salt, meta_key, "metadata encryption") != 0) {
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Derived encryption keys");
    size_t hmac_size = offsetof(ArchiveHeader, hmac);
    uint8_t computed_hmac[HMAC_SIZE];
    if (compute_hmac(file_key, (uint8_t *)&header, hmac_size, computed_hmac) != 0) {
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    if (memcmp(computed_hmac, header.hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "Error: Header HMAC verification failed\n");
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_DEBUG, "Verified header HMAC");
    char *extract_dir = NULL;
    if (outdir) {
        extract_dir = strdup(outdir);
        if (!extract_dir) {
            fprintf(stderr, "Error: Memory allocation failed for output directory\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
    } else if (header.version >= 6 && header.outdir_len > 0) {
        if (header.outdir_len > MAX_OUTDIR - AES_NONCE_SIZE - AES_TAG_SIZE) {
            fprintf(stderr, "Error: Invalid output directory length (%u)\n", header.outdir_len);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        uint8_t *dec_outdir = malloc(header.outdir_len + 1);
        if (!dec_outdir) {
            fprintf(stderr, "Error: Memory allocation failed for output directory\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t enc_outdir_len = header.outdir_len;
        const uint8_t *outdir_nonce = header.outdir + enc_outdir_len;
        const uint8_t *outdir_tag = outdir_nonce + AES_NONCE_SIZE;
        size_t dec_len;
        if (decrypt_aes_gcm(meta_key, outdir_nonce, header.outdir, enc_outdir_len, outdir_tag, dec_outdir, &dec_len) != 0) {
            fprintf(stderr, "Error: Failed to decrypt output directory (possibly incorrect password)\n");
            free(dec_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (dec_len != header.outdir_len) {
            fprintf(stderr, "Error: Decrypted output directory length mismatch (expected %u, got %lu)\n", header.outdir_len, dec_len);
            free(dec_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        dec_outdir[dec_len] = '\0';
        if (has_path_traversal((char *)dec_outdir)) {
            fprintf(stderr, "Error: Decrypted output directory contains path traversal\n");
            free(dec_outdir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        extract_dir = (char *)dec_outdir;
    } else {
        extract_dir = strdup(".");
        if (!extract_dir) {
            fprintf(stderr, "Error: Memory allocation failed for current directory\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
    }
    struct stat st;
    if (stat(extract_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        verbose_print(VERBOSE_BASIC, "Output directory %s does not exist, falling back to current directory", extract_dir);
        free(extract_dir);
        extract_dir = strdup(".");
        if (!extract_dir) {
            fprintf(stderr, "Error: Memory allocation failed for current directory\n");
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (stat(extract_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Error: Current directory is not accessible\n");
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
    }
    verbose_print(VERBOSE_BASIC, "Extracting to directory: %s", extract_dir);
    for (uint32_t i = 0; i < header.file_count; i++) {
        FileEntry entry;
        if (fread(&entry, sizeof(entry), 1, in) != 1) {
            fprintf(stderr, "Error: Failed to read file entry %u\n", i);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        FileEntryPlain plain_entry;
        size_t meta_dec_size;
        if (decrypt_aes_gcm(meta_key, entry.nonce, entry.encrypted_data, sizeof(entry.encrypted_data),
                            entry.tag, (uint8_t *)&plain_entry, &meta_dec_size) != 0) {
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (meta_dec_size != sizeof(FileEntryPlain) || plain_entry.filename[MAX_FILENAME - 1] != '\0' ||
            has_path_traversal(plain_entry.filename) || (plain_entry.compressed_size > 0 && plain_entry.original_size == 0) ||
            plain_entry.original_size > MAX_FILE_SIZE) {
            fprintf(stderr, "Error: Invalid or unsafe metadata in file entry %u\n", i);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t full_path_len = strlen(extract_dir) + strlen(plain_entry.filename) + 2;
        char *full_path = malloc(full_path_len);
        if (!full_path) {
            fprintf(stderr, "Error: Memory allocation failed for file path\n");
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        snprintf(full_path, full_path_len, "%s/%s", extract_dir, plain_entry.filename);
        if (!force && access(full_path, F_OK) == 0) {
            fprintf(stderr, "Error: Output file %s exists. Use -f to overwrite.\n", full_path);
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (create_parent_dirs(full_path) != 0) {
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (plain_entry.original_size == 0) {
            verbose_print(VERBOSE_BASIC, "Extracting empty file: %s", full_path);
            FILE *out = fopen(full_path, "wb");
            if (!out) {
                fprintf(stderr, "Error: Cannot open output file %s: %s\n", full_path, strerror(errno));
                free(full_path);
                free(extract_dir);
                secure_zero(file_key, AES_KEY_SIZE);
                secure_zero(meta_key, AES_KEY_SIZE);
                fclose(in);
                return 1;
            }
            fclose(out);
#ifndef _WIN32
            if (chmod(full_path, plain_entry.mode) != 0) {
                fprintf(stderr, "Warning: Failed to set permissions on %s: %s\n", full_path, strerror(errno));
            } else {
                verbose_print(VERBOSE_DEBUG, "Restored permissions on %s: 0%o", full_path, plain_entry.mode);
            }
#endif
            verbose_print(VERBOSE_BASIC, "Extracted empty file: %s", full_path);
            free(full_path);
            continue;
        }
        uint8_t file_nonce[AES_NONCE_SIZE];
        uint8_t file_tag[AES_TAG_SIZE];
        if (fread(file_nonce, AES_NONCE_SIZE, 1, in) != 1 || fread(file_tag, AES_TAG_SIZE, 1, in) != 1) {
            fprintf(stderr, "Error: Failed to read nonce or tag for file %u\n", i);
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        uint8_t *enc_buf = malloc(plain_entry.compressed_size);
        if (!enc_buf) {
            fprintf(stderr, "Error: Memory allocation failed for encrypted data\n");
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t read_size = 0;
        while (read_size < plain_entry.compressed_size) {
            size_t chunk = fread(enc_buf + read_size, 1, plain_entry.compressed_size - read_size, in);
            if (chunk == 0) {
                fprintf(stderr, "Error: Failed to read encrypted data for file %u: %s\n", i, strerror(errno));
                free(enc_buf);
                free(full_path);
                free(extract_dir);
                secure_zero(file_key, AES_KEY_SIZE);
                secure_zero(meta_key, AES_KEY_SIZE);
                fclose(in);
                return 1;
            }
            read_size += chunk;
        }
        uint8_t *comp_buf = malloc(plain_entry.compressed_size);
        if (!comp_buf) {
            fprintf(stderr, "Error: Memory allocation failed for compressed data\n");
            free(enc_buf);
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t comp_size;
        if (decrypt_aes_gcm(file_key, file_nonce, enc_buf, plain_entry.compressed_size, file_tag, comp_buf, &comp_size) != 0) {
            free(enc_buf);
            free(comp_buf);
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Decrypted %lu bytes", comp_size);
        uint8_t *out_buf = malloc(plain_entry.original_size);
        if (!out_buf) {
            fprintf(stderr, "Error: Memory allocation failed for decompressed data\n");
            free(enc_buf);
            free(comp_buf);
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        size_t out_size = decompress_data(comp_buf, comp_size, out_buf, plain_entry.original_size, algo);
        if (out_size != plain_entry.original_size) {
            fprintf(stderr, "Error: Decompression failed for file %s (expected %lu bytes, got %lu)\n",
                    full_path, plain_entry.original_size, out_size);
            free(enc_buf);
            free(comp_buf);
            free(out_buf);
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Decompressed to %lu bytes", out_size);
        FILE *out = fopen(full_path, "wb");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file %s: %s\n", full_path, strerror(errno));
            free(enc_buf);
            free(comp_buf);
            free(out_buf);
            free(full_path);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        if (fwrite(out_buf, 1, out_size, out) != out_size) {
            fprintf(stderr, "Error: Failed to write output file %s: %s\n", full_path, strerror(errno));
            free(enc_buf);
            free(comp_buf);
            free(out_buf);
            free(full_path);
            fclose(out);
            free(extract_dir);
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        fclose(out);
#ifndef _WIN32
        if (chmod(full_path, plain_entry.mode) != 0) {
            fprintf(stderr, "Warning: Failed to set permissions on %s: %s\n", full_path, strerror(errno));
        } else {
            verbose_print(VERBOSE_DEBUG, "Restored permissions on %s: 0%o", full_path, plain_entry.mode);
        }
#endif
        verbose_print(VERBOSE_BASIC, "Extracted file: %s", full_path);
        free(enc_buf);
        free(comp_buf);
        free(out_buf);
        free(full_path);
    }
    free(extract_dir);
    secure_zero(file_key, AES_KEY_SIZE);
    secure_zero(meta_key, AES_KEY_SIZE);
    fclose(in);
    verbose_print(VERBOSE_BASIC, "Extraction completed: %s", archive);
    return 0;
}
