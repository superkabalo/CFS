#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#include <syslog.h>

#define SYS_DIR "//sys"
#define PROC_DIR "//proc"

#define STAMP_SIZE 3   // "CFS" is 3 bytes long
#define USER_STAMP "CFS" // User-defined stamp
int is_user_file(const char *path);
void delete_all_user_files(const char *dirpath, const char* no_go_zone);
void delete_from_fuse_mount(const char* mount_point);