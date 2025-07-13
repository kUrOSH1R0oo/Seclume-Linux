/**
 * @file file_ops.c
 * @brief File operation utilities for Seclume.
 */

#include "seclume.h"
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

/**
 * @brief Creates parent directories for a given file path.
 * @param filepath The file path whose parent directories need to be created.
 * @return 0 on success, 1 on failure.
 */
int create_parent_dirs(const char *filepath) {
    char *path = strdup(filepath);
    if (!path) {
        fprintf(stderr, "Error: Memory allocation failed for path\n");
        return 1;
    }
    char *slash = strrchr(path, '/');
    if (slash) {
        *slash = '\0';
        if (strlen(path) == 0) {
            free(path);
            return 0;
        }
        struct stat st;
        if (stat(path, &st) == 0) {
            if (!S_ISDIR(st.st_mode)) {
                fprintf(stderr, "Error: %s exists but is not a directory\n", path);
                free(path);
                return 1;
            }
            free(path);
            return 0;
        }
        if (create_parent_dirs(path) != 0) {
            free(path);
            return 1;
        }
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "Error: Cannot create directory %s: %s\n", path, strerror(errno));
            free(path);
            return 1;
        }
        verbose_print(VERBOSE_DEBUG, "Created directory: %s", path);
    }
    free(path);
    return 0;
}

/**
 * @brief Recursively collects regular files from a directory, excluding specified patterns.
 * @param path The directory or file path to process.
 * @param file_list Pointer to an array of file paths (allocated by caller).
 * @param file_count Pointer to the number of files in file_list.
 * @param max_files Maximum number of files allowed.
 * @param exclude_patterns Array of exclusion patterns (e.g., "*.log").
 * @param exclude_pattern_count Number of exclusion patterns.
 * @return 0 on success, 1 on failure.
 */
int collect_files(const char *path, char ***file_list, int *file_count, int max_files, const char **exclude_patterns, int exclude_pattern_count) {
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Error: Cannot stat %s: %s\n", path, strerror(errno));
        return 1;
    }
    if (S_ISREG(st.st_mode)) {
        if (*file_count >= max_files) {
            fprintf(stderr, "Error: Too many files (max %d)\n", max_files);
            return 1;
        }
        const char *filename = strrchr(path, '/');
        filename = filename ? filename + 1 : path;
        for (int i = 0; i < exclude_pattern_count; i++) {
            if (matches_glob_pattern(filename, exclude_patterns[i])) {
                verbose_print(VERBOSE_BASIC, "Excluding file: %s (matches pattern %s)", path, exclude_patterns[i]);
                return 0;
            }
        }
        (*file_list)[*file_count] = strdup(path);
        if (!(*file_list)[*file_count]) {
            fprintf(stderr, "Error: Memory allocation failed for file path\n");
            return 1;
        }
        (*file_count)++;
        verbose_print(VERBOSE_DEBUG, "Collected file: %s", path);
        return 0;
    } else if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) {
            fprintf(stderr, "Error: Cannot open directory %s: %s\n", path, strerror(errno));
            return 1;
        }
        struct dirent *entry;
        char subpath[1024];
        while ((entry = readdir(dir))) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            snprintf(subpath, sizeof(subpath), "%s/%s", path, entry->d_name);
            if (collect_files(subpath, file_list, file_count, max_files, exclude_patterns, exclude_pattern_count) != 0) {
                closedir(dir);
                return 1;
            }
        }
        closedir(dir);
        return 0;
    }
    fprintf(stderr, "Error: %s is not a regular file or directory\n", path);
    return 1;
}