/**
 * @file list.c
 * @brief Lists contents of a Seclume archive.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

/**
 * @brief Lists the contents of a .slm archive.
 * @param archive Path to the input archive file (.slm).
 * @param password Password for decryption.
 * @return 0 on success, 1 on failure.
 */
int list_files(const char *archive, const char *password) {
    if (!archive || !password) {
        fprintf(stderr, "Error: Invalid list parameters\n");
        return 1;
    }
    FILE *in = fopen(archive, "rb");
    if (!in) {
        fprintf(stderr, "Error: Cannot open archive file %s: %s\n", archive, strerror(errno));
        return 1;
    }
    ArchiveHeader header;
    memset(&header, 0, sizeof(header));
    if (fread(&header, sizeof(header), 1, in) != 1) {
        fprintf(stderr, "Error: Failed to read archive header\n");
        fclose(in);
        return 1;
    }
    if (strncmp(header.magic, "SLM", 4) != 0 || (header.version < 4 || header.version > 6)) {
        fprintf(stderr, "Error: Invalid archive format or version (expected 4 to 6, got %d)\n", header.version);
        fclose(in);
        return 1;
    }
    if (header.file_count > MAX_FILES) {
        fprintf(stderr, "Error: Too many files in archive (%u > %d)\n", header.file_count, MAX_FILES);
        fclose(in);
        return 1;
    }
    verbose_print(VERBOSE_BASIC, "Read archive header, version %d, %u files, compression %s level %d",
                  header.version, header.file_count, header.compression_algo == COMPRESSION_ZLIB ? "zlib" : "LZMA", header.compression_level);
    uint8_t file_key[AES_KEY_SIZE];
    uint8_t meta_key[AES_KEY_SIZE];
    memset(file_key, 0, AES_KEY_SIZE);
    memset(meta_key, 0, AES_KEY_SIZE);
    if (derive_key(password, header.salt, file_key, "file encryption") != 0 ||
        derive_key(password, header.salt, meta_key, "metadata encryption") != 0) {
        secure_zero(file_key, AES_KEY_SIZE);
        secure_zero(meta_key, AES_KEY_SIZE);
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
    printf("Contents of %s:\n", archive);
    printf("%-11s %-12s %s\n", "Permissions", "Size", "Filename");
    printf("%-11s %-12s %s\n", "-----------", "------------", "--------");
    int errors = 0;
    for (uint32_t i = 0; i < header.file_count; i++) {
        long file_pos = ftell(in);
        if (file_pos == -1) {
            fprintf(stderr, "Error: Failed to get file position for entry %u: %s\n", i, strerror(errno));
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        FileEntry entry;
        memset(&entry, 0, sizeof(entry));
        size_t read_bytes = fread(&entry, 1, sizeof(entry), in);
        if (read_bytes != sizeof(entry)) {
            fprintf(stderr, "Error: Failed to read file entry %u at offset %ld: %s (read %zu of %zu bytes)\n",
                    i, file_pos, feof(in) ? "unexpected EOF" : strerror(errno), read_bytes, sizeof(entry));
            secure_zero(file_key, AES_KEY_SIZE);
            secure_zero(meta_key, AES_KEY_SIZE);
            fclose(in);
            return 1;
        }
        FileEntryPlain plain_entry;
        memset(&plain_entry, 0, sizeof(plain_entry));
        size_t meta_dec_size;
        if (decrypt_aes_gcm(meta_key, entry.nonce, entry.encrypted_data, sizeof(entry.encrypted_data),
                            entry.tag, (uint8_t *)&plain_entry, &meta_dec_size) != 0) {
            fprintf(stderr, "Error: AES-GCM decryption failed for file entry %u at offset %ld (wrong password or corrupted data?)\n", i, file_pos);
            errors++;
            long skip_pos = ftell(in);
            if (skip_pos == -1) {
                fprintf(stderr, "Error: Failed to get file position after decryption failure for entry %u: %s\n", i, strerror(errno));
                secure_zero(file_key, AES_KEY_SIZE);
                secure_zero(meta_key, AES_KEY_SIZE);
                fclose(in);
                return 1;
            }
            uint8_t file_nonce[AES_NONCE_SIZE];
            uint8_t file_tag[AES_TAG_SIZE];
            if (fread(file_nonce, AES_NONCE_SIZE, 1, in) == 1 && fread(file_tag, AES_TAG_SIZE, 1, in) == 1) {
                fprintf(stderr, "Warning: Cannot skip data for entry %u due to unknown size; stopping\n", i);
                secure_zero(file_key, AES_KEY_SIZE);
                secure_zero(meta_key, AES_KEY_SIZE);
                fclose(in);
                return 1;
            }
            fseek(in, skip_pos, SEEK_SET);
            continue;
        }
        if (meta_dec_size != sizeof(FileEntryPlain) || plain_entry.filename[MAX_FILENAME - 1] != '\0' ||
            has_path_traversal(plain_entry.filename) || (plain_entry.compressed_size > 0 && plain_entry.original_size == 0) ||
            plain_entry.original_size > MAX_FILE_SIZE) {
            fprintf(stderr, "Error: Invalid or unsafe metadata in file entry %u at offset %ld\n", i, file_pos);
            errors++;
            if (plain_entry.compressed_size > 0) {
                long skip_pos = ftell(in);
                if (skip_pos == -1) {
                    fprintf(stderr, "Error: Failed to get file position for skipping data in entry %u: %s\n", i, strerror(errno));
                    secure_zero(file_key, AES_KEY_SIZE);
                    secure_zero(meta_key, AES_KEY_SIZE);
                    fclose(in);
                    return 1;
                }
                if (fseek(in, plain_entry.compressed_size + AES_NONCE_SIZE + AES_TAG_SIZE, SEEK_CUR) != 0) {
                    fprintf(stderr, "Error: Failed to skip data for entry %u: %s\n", i, strerror(errno));
                    secure_zero(file_key, AES_KEY_SIZE);
                    secure_zero(meta_key, AES_KEY_SIZE);
                    fclose(in);
                    return 1;
                }
            }
            continue;
        }
        char mode_str[11];
        mode_to_string(plain_entry.mode, mode_str);
        printf("%-11s %12lu %s\n", mode_str, plain_entry.original_size, plain_entry.filename);
        if (plain_entry.compressed_size > 0) {
            long skip_pos = ftell(in);
            if (skip_pos == -1) {
                fprintf(stderr, "Error: Failed to get file position for skipping data in entry %u: %s\n", i, strerror(errno));
                secure_zero(file_key, AES_KEY_SIZE);
                secure_zero(meta_key, AES_KEY_SIZE);
                fclose(in);
                return 1;
            }
            if (fseek(in, plain_entry.compressed_size + AES_NONCE_SIZE + AES_TAG_SIZE, SEEK_CUR) != 0) {
                fprintf(stderr, "Error: Failed to skip data for entry %u (%s): %s\n", i, plain_entry.filename, strerror(errno));
                secure_zero(file_key, AES_KEY_SIZE);
                secure_zero(meta_key, AES_KEY_SIZE);
                fclose(in);
                return 1;
            }
        }
    }
    secure_zero(file_key, AES_KEY_SIZE);
    secure_zero(meta_key, AES_KEY_SIZE);
    fclose(in);
    if (errors > 0) {
        fprintf(stderr, "Warning: %d file entries could not be processed\n", errors);
        return 1;
    }
    return 0;
}
