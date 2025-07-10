/**
 * @file file_ops.c
 * @brief File and directory operation functions for Seclume.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

/** @brief Maximum allowed path length (including null terminator) */
#define MAX_PATH_LENGTH 4096
/** @brief Maximum allowed filename component length (including null terminator) */
#define MAX_NAME_LENGTH 256

/**
 * @brief Creates parent directories for a file path if they don't exist.
 * @param filepath The file path for which to create parent directories.
 * @return 0 on success, 1 on failure.
 */
int create_parent_dirs(const char *filepath) {
    if (!filepath) return 1;
    char *path = strdup(filepath);
    if (!path) {
        fprintf(stderr, "Error: Memory allocation failed for path\n");
        return 1;
    }
    char *slash = strrchr(path, '/');
    if (!slash) slash = strrchr(path, '\\');
    if (slash) {
        *slash = '\0';
        if (strlen(path) > 0) {
            struct stat st;
            if (stat(path, &st) != 0) {
                if (create_parent_dirs(path) != 0) {
                    free(path);
                    return 1;
                }
                if (mkdir(path, 0755) != 0 && errno != EEXIST) {
                    fprintf(stderr, "Error: Failed to create directory %s: %s\n", path, strerror(errno));
                    free(path);
                    return 1;
                }
                verbose_print(VERBOSE_BASIC, "Created directory: %s", path);
            }
        }
    }
    free(path);
    return 0;
}

/**
 * @brief Collects files from a directory recursively.
 * @param path Directory or file path to process.
 * @param file_list Array to store collected file paths.
 * @param file_count Pointer to the number of collected files.
 * @param max_files Maximum number of files allowed.
 * @return 0 on success, 1 on failure.
 */
int collect_files(const char *path, char ***file_list, int *file_count, int max_files) {
    if (!path || !file_list || !file_count) return 1;

    size_t path_len = strlen(path);
    if (path_len >= MAX_PATH_LENGTH - MAX_NAME_LENGTH - 1) {
        fprintf(stderr, "Error: Path too long: %s (max %d bytes, accounting for filename)\n",
                path, MAX_PATH_LENGTH - MAX_NAME_LENGTH - 2);
        return 1;
    }

    DIR *dir = opendir(path);
    if (!dir) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (*file_count >= max_files) {
                fprintf(stderr, "Error: Too many files (max %d)\n", max_files);
                return 1;
            }
            (*file_list)[*file_count] = strdup(path);
            if (!(*file_list)[*file_count]) {
                fprintf(stderr, "Error: Memory allocation failed for file path\n");
                return 1;
            }
            (*file_count)++;
            verbose_print(VERBOSE_DEBUG, "Added file: %s", path);
            return 0;
        }
        fprintf(stderr, "Error: Cannot open directory %s: %s\n", path, strerror(errno));
        return 1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        size_t name_len = strlen(entry->d_name);
        if (name_len >= MAX_NAME_LENGTH) {
            fprintf(stderr, "Error: Filename component too long: %s (max %d bytes)\n",
                    entry->d_name, MAX_NAME_LENGTH - 1);
            closedir(dir);
            return 1;
        }

        size_t full_path_len = path_len + name_len + 2;

        if (full_path_len >= MAX_PATH_LENGTH) {
            fprintf(stderr, "Error: Path too long: %s/%s (max %d bytes)\n",
                    path, entry->d_name, MAX_PATH_LENGTH - 1);
            closedir(dir);
            return 1;
        }

        char *full_path = malloc(full_path_len);
        if (!full_path) {
            fprintf(stderr, "Error: Memory allocation failed for file path\n");
            closedir(dir);
            return 1;
        }

        snprintf(full_path, full_path_len, "%s/%s", path, entry->d_name);

        if (has_path_traversal(full_path)) {
            fprintf(stderr, "Error: Path traversal detected in %s\n", full_path);
            free(full_path);
            closedir(dir);
            return 1;
        }

        struct stat st;
        if (stat(full_path, &st) != 0) {
            fprintf(stderr, "Error: Cannot stat %s: %s\n", full_path, strerror(errno));
            free(full_path);
            closedir(dir);
            return 1;
        }

        if (S_ISDIR(st.st_mode)) {
            if (collect_files(full_path, file_list, file_count, max_files) != 0) {
                free(full_path);
                closedir(dir);
                return 1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (*file_count >= max_files) {
                fprintf(stderr, "Error: Too many files (max %d)\n", max_files);
                free(full_path);
                closedir(dir);
                return 1;
            }
            (*file_list)[*file_count] = strdup(full_path);
            if (!(*file_list)[*file_count]) {
                fprintf(stderr, "Error: Memory allocation failed for file path\n");
                free(full_path);
                closedir(dir);
                return 1;
            }
            (*file_count)++;
            verbose_print(VERBOSE_DEBUG, "Added file: %s", full_path);
        }
        free(full_path);
    }

    closedir(dir);
    return 0;
}