#include "button.h"

// Helper function to check if a file starts with the user stamp
int is_user_file(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        printf("\n\n\nCOULDN'T OPEN FILE\n\n\n");
        syslog(LOG_ERR, "Error opening file: %s", path);
        return 0;
    }

    unsigned char stamp[STAMP_SIZE] = {0};
    size_t bytes_read = fread(stamp, 1, STAMP_SIZE, file);
    fclose(file);

    // Check if the first 3 bytes match the user-defined stamp "CFS"
    return (bytes_read == STAMP_SIZE && memcmp(stamp, USER_STAMP, STAMP_SIZE) == 0);
}

// Recursive function to delete user files
void delete_all_user_files(const char *dirpath, const char* no_go_zone) {
    printf("\n\n\n PATH:%s\n\n\n",dirpath);
    struct dirent *entry;
    if (access(dirpath, F_OK) != 0) {
        perror("access failed");
        syslog(LOG_ERR, "Mount point does not exist: %s", dirpath);
        printf("\n\n\nMount point does not exist: %s\n\n\n",dirpath);
        return;
    }
    printf("\n\n\n ACCESSED DIR:%s\n\n\n",dirpath);
    DIR *dir = opendir(dirpath);
    if (dir == NULL) {
        syslog(LOG_ERR, "Error opening directory: %s", dirpath);
        printf("\n\n\nError opening directory: %s \n\n\n",dirpath);
        return;
    }
    printf("\n\n\nPATH OPENED SUCCESSFULY\n\n\n");
    while ((entry = readdir(dir)) != NULL) {
        char full_path[PATH_MAX];
        if (entry == NULL) {
            syslog(LOG_ERR, "Error reading directory: %s", dirpath);
            printf("Error reading directory: %s\n", dirpath);
            break;
        }
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);
        printf("\n\n\nChecking: %s\n", full_path);
        // Skip '.' and '..' entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        if (strcmp(full_path, no_go_zone) == 0 || 
            strcmp(full_path, "//sys") == 0 || 
            strcmp(full_path, "//proc") == 0) {
            printf("Skipping directory: %s\n", full_path);
            continue;
        }
        struct stat statbuf;
        if (lstat(full_path, &statbuf) == -1) {
            syslog(LOG_ERR, "Error retrieving file info: %s", full_path);
            continue;
        }

        // Skip symbolic links to prevent unintended deletions
        if (S_ISLNK(statbuf.st_mode)) {
            continue;
        }

        // Check if it's a directory or a file
        if (S_ISDIR(statbuf.st_mode)) {
            // Recursively delete files inside
            printf("\n\n\nNO GO ZONE IS:%s",no_go_zone);
            delete_all_user_files(full_path, no_go_zone);
        } else if (S_ISREG(statbuf.st_mode)) {
            // If it's a regular file, check if it's a user file (with stamp)
            if (is_user_file(full_path)) {
                if (remove(full_path) == 0) {
                    printf("Deleted: %s\n", full_path);
                    syslog(LOG_INFO, "Deleted user file: %s", full_path);
                } else {
                    syslog(LOG_ERR, "Error deleting file: %s", full_path);
                }
            }
        }
    }
    closedir(dir);
}
// Wrapper to start deletion from the FUSE mount point
void delete_from_fuse_mount(const char* mount_point) {
    char updated_mount_point[PATH_MAX];

    // Ensure the mount_point starts with a '/'
    // Prepend a '/' regardless of the current mount_point format
    snprintf(updated_mount_point, sizeof(updated_mount_point), "/%s", mount_point);
    struct fuse_context *ctx = fuse_get_context();
    if (!ctx) {
        printf("\n\n\nError getting FUSE context \n\n\n");
        syslog(LOG_ERR, "Error getting FUSE context");
        return;
    }
    printf("Starting deletion from: %s\n", mount_point);
    delete_all_user_files("/", updated_mount_point);
}