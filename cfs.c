#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS 64
#define _XOPEN_SOURCE 700 // To enable POSIX.1-2008 and its extensions
#define _POSIX_C_SOURCE 200809L // Ensure POSIX.1-2008 compatibility

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include "aes_encryption.h"
#include "sha3.h"
#include "file_headers.h"
#include "button.h"

static int fill_dir_plus = 0;  // fill dir plus
static const char *global_mount_point = NULL;  // Global variable to store the mount point
/*
    COMPILE:
    gcc -Wall cfs.c `pkg-config fuse3 --cflags --libs` aes_encryption.h aes_encryption.c -I/usr/include/openssl -L/usr/lib/ -lssl -lcrypto -o cfs
	OR
	make

    MOUNTING:
    go to /usr/local/etc/fuse.conf and uncomment the phrase "user_allow_other"
    sudo ./cfs -d -f -s <FULL_MOUNT_POINT_PATH> -o allow_other

    UNMOUNTING:
    fusermount -u <MOUNT_POINT>
 */

static int myfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    int res;

    // use utimensat to update timestamps
    res = utimensat(AT_FDCWD, path, tv, 0);
    if (res == -1)
        return -errno;

    return 0;
}


static int cfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    printf("\n\n\nCFS_GETATTR\n\n\n");
	printf("%s",path);
	
    int res = lstat(path, stbuf);   // get the file attributes
	if (res == -1)
		return -errno;
	return 0;
}

static int cfs_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi)
{
    printf("\n\n\nCFS_CREATE\n\n\n");
	int res;

	res = open(path, fi->flags, mode);  // create the file
	if (res == -1)
		return -errno;

	fi->fh = res;
	return 0;
}

static int cfs_mkdir(const char *path, mode_t mode)
{
    printf("\n\n\nCFS_MKDIR\n\n\n");
	int res;

	res = mkdir(path, mode);    // create the new directory
	if (res == -1)
		return -errno;

	return 0;
}


static int cfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("\n\n\nCFS_READ\n\n\n");
	// allocate memory for decryption fields
	file_headers headers;
	file_headers local_headers;  // initiate local file headers for encryption key and iv fields only
	// self explanatory vars
	unsigned char* user_key;
	unsigned char* user_iv;
	unsigned char hash_output[SHA3_256_DIGEST_LENGTH];
	unsigned char* ciphertext;
	unsigned char* plaintext;
	int plaintext_len;
	int fd;
	int res;

	// check for errors with the file
	if(fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

	// read the file content (encrypted contents)
	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;
	
	if (checkFileSignature(buf) == -1)  // check if file does not belong to the CFS
	{
		return size;
	}

	// get encryption inputs from the user
	user_key = get_user_key();
	user_iv = get_user_iv();


	// DESERIALIZATION - read decryption fields and the encrypted file content
	memcpy(&headers, buf, sizeof(headers));

	// encrypt user key
	sha3_256_hash(user_key, AES_KEYLEN, hash_output);
	memcpy(&local_headers.key_hash, hash_output, SHA3_256_DIGEST_LENGTH);
	
	// encrypt user iv
	sha3_256_hash(user_iv, AES_IVLEN, hash_output);
	memcpy(&local_headers.iv_hash, hash_output, SHA3_256_DIGEST_LENGTH);

	if (strncmp((const char*)headers.key_hash, (const char*)local_headers.key_hash, SHA3_256_DIGEST_LENGTH) || strncmp((const char*)headers.iv_hash, (const char*)local_headers.iv_hash, SHA3_256_DIGEST_LENGTH))  // check key and iv hash
	{
		printf("\n\nDumbass\n\n");
		return -errno;
	}

	// allocate memory for the encrypted file content
	ciphertext = (unsigned char*)malloc(sizeof(unsigned char) * headers.ciphertext_len);
	memcpy(ciphertext, buf + sizeof(headers), headers.ciphertext_len);	// read ciphertext
	// decrypt the file content
	res = aes_256_decrypt(ciphertext, headers.ciphertext_len, user_key, user_iv, &plaintext, &plaintext_len);
	if (res == -1)
		res = -errno;
	
	// return file content buffer
	memcpy(buf, plaintext, plaintext_len);

	// validate file
	if(fi == NULL)
		close(fd);
	
	// free allocated memory
	free(ciphertext);
	free(plaintext);

	// return the decrypted file size for the file to be displayed correctly
	return plaintext_len;

}

static int cfs_open(const char *path, struct fuse_file_info *fi)
{
    printf("\n\n\nCFS_OPEN\n\n\n");
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	fi->fh = res;
	return 0;
}

static int cfs_chmod(const char *path, mode_t mode,
		     struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int cfs_chown(const char *path, uid_t uid, gid_t gid,
		     struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int cfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("\n\n\nCFS_WRITE\n\n\n");
	printf("\n\n%s\n\n",path);
	file_headers headers;  // initiate file headers
	memcpy(&headers.signature, CFS_FILE_SIGNATURE, CFS_FILE_SIGNATURE_SIZE);
	// self explanatory variables
	unsigned char* user_key;
	unsigned char* user_iv;
	unsigned char* ciphertext;
	unsigned char* file_content;
	unsigned char hash_output[SHA3_256_DIGEST_LENGTH];
	int ciphertext_len;
	int fd;
	int res;

	(void) fi;
	// get user encryption key input
	user_key = get_user_key();
	sha3_256_hash(user_key, AES_KEYLEN, hash_output);	
	memcpy(&headers.key_hash, hash_output, SHA3_256_DIGEST_LENGTH);

	// get user IV input
	user_iv = get_user_iv();
	sha3_256_hash(user_iv, AES_IVLEN, hash_output);
	memcpy(&headers.iv_hash, hash_output, SHA3_256_DIGEST_LENGTH);
	
	// encrypt file content
	res = aes_256_encrypt((unsigned char*)buf, size,user_key, user_iv, &ciphertext, &ciphertext_len);
	if (res == -1)
	{
		return -errno;
	}
	headers.ciphertext_len = ciphertext_len;  // set ciphertext length

	// allocate memory for the file content
	file_content = (unsigned char*)malloc(sizeof(unsigned char) * (sizeof(headers) + ciphertext_len));
	// SERIALIZATION - construct the file string accordingly: file_headers->ciphertext
	memcpy(file_content, &headers, sizeof(headers));
	memcpy(file_content + sizeof(headers), ciphertext, ciphertext_len);

	// check for errors with the file
	if(fi == NULL)
	{
		fd = open(path, O_WRONLY);
	}
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

	//  write the encrypted fileP
	res = pwrite(fd, file_content, sizeof(headers) + ciphertext_len, offset);
	if (res == -1)
		res = -errno;

	if(fi == NULL)
		close(fd);

	// free allocated memory
	free(ciphertext);
	free(file_content);

	// return the original file size for FUSE to not bring up a write size error
	return size;
}

static int cfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    printf("\n\n\nCFS_MKNOD\n\n\n");
    
	int res;
    /* Check if the file type is FIFO (named pipe) */
	if (S_ISFIFO(mode))
		res = mkfifo(path, mode);// Create a named pipe
	else
		res = mknod(path, mode, rdev);// Create a regular file or device node
    /* If the creation failed, return the corresponding error code */
	if (res == -1)
		return -errno;

	return 0;
}

static void *cfs_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	const char *self_destruct_dir = "/self_destruct_dir";  // The directory to trigger self-destruction
    struct stat st;

    // Check if the directory already exists
    if (lstat(self_destruct_dir, &st) == -1) {
        if (errno == ENOENT) {  // If directory doesn't exist
            // Create the directory with read/write/execute permissions for the user
            if (mkdir(self_destruct_dir, S_IRUSR | S_IWUSR | S_IXUSR) == 0) {
                printf("Created /self_destruct directory\n");

            } else {
                perror("Failed to create /self_destruct directory");
            }
        } else {
            perror("Error checking /self_destruct directory");
        }
    } else {
        // The directory already exists
        if (S_ISDIR(st.st_mode)) {
            printf("/self_destruct directory already exists\n");
        } else {
            // If it's not a directory (could be a file), handle the error
            printf("/self_destruct exists, but it's not a directory\n");
        }
    }

    return NULL;
}

static int cfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
			   enum fuse_readdir_flags flags)
{
	printf("\n\n\nCFS_READDIR\n\n\n");
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	(void) flags;
	dp = opendir(path);  // open the directory
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL)  // iterate over all the directories
	{
		struct stat st;
		if (fill_dir_plus) {
			fstatat(dirfd(dp), de->d_name, &st,
				AT_SYMLINK_NOFOLLOW);
		} else {
			memset(&st, 0, sizeof(st));
			st.st_ino = de->d_ino;
			st.st_mode = de->d_type << 12;
		}
		if (filler(buf, de->d_name, &st, 0, fill_dir_plus))  // add directory entrance until it is empty (1 is returned
			break;
	}
	// Add self_destruct to the directory listing
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFREG | 0644;
    st.st_nlink = 1;
    st.st_size = 0;
	closedir(dp);
	return 0;
}

static int cfs_release(const char *path, struct fuse_file_info *fi)
{
	printf("\n\n\nCFS_RELEASE\n\n\n");
	(void) path;
	close(fi->fh);
	return 0;
}

static int cfs_truncate(const char *path, off_t size,
	struct fuse_file_info *fi)
{
	printf("\n\n\nCFS_TRUNCATE\n\n\n");
	int res;
	if (fi != NULL)
		res = ftruncate(fi->fh, size);
	else
		res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}
static int cfs_unlink(const char *path) {
	printf("CFS_UNLINK");

    if (strcmp(path, "/self_destruct_dir") == 0) {
		printf("\n\n\nDESTRUCTION BUTTON\n\n\n");
        syslog(LOG_WARNING, "Self-destruction activated! Deleting all user files...");
        delete_from_fuse_mount(global_mount_point);
        return 0;  // Return success
    }

    return unlink(path);  // Normal file deletion
}
static int cfs_releasedir(const char *path,struct fuse_file_info *fi)
{
	printf("Releasing directory: %s\n", path);
    syslog(LOG_INFO, "Releasing directory: %s", path);

    // Close the directory stream (if opened)
    DIR *dir = (DIR *)fi->fh;
    if (dir) {
        closedir(dir);
        fi->fh = 0; // Reset file handle to indicate it's closed
    }

    return 0; // Return success
}
static int cfs_rmdir(const char *path) {
    printf("Removing directory: %s\n", path);
    syslog(LOG_INFO, "Removing directory: %s", path);
	if (strcmp(path, "/self_destruct_dir") == 0) {
		printf("\n\n\nDESTRUCTION BUTTON\n\n\n");
        syslog(LOG_WARNING, "Self-destruction activated! Deleting all user files...");
        delete_from_fuse_mount(global_mount_point);
        return 0;  // Return success
    }
    // Attempt to remove the directory
    int res = rmdir(path);
    if (res == -1) {
        syslog(LOG_ERR, "Error removing directory: %s, errno: %d", path, errno);
        return -errno;  // Return FUSE error code
    }

    return 0;  // Success
}
static const struct fuse_operations cfs_ops = {
	.getattr = cfs_getattr,
	.utimens = myfs_utimens,  // update timestamps
	.truncate = cfs_truncate,
	.open = cfs_open,
	.read = cfs_read,
	.write = cfs_write,
    //.readlink =,
    //.getdir =,
    .mknod = cfs_mknod,
    .mkdir = cfs_mkdir,
    .unlink = cfs_unlink,  // Overriding file delete function
    .rmdir = cfs_rmdir,
    //.symlink =,
    //.rename =,
    //.link =,
    .chmod = cfs_chmod,
    .chown = cfs_chown,
    //.flush =,
    //.utime =,
    //.statfs =,
    .release = cfs_release,
    //.fsync =,
    //.setxattr =,
    //.getxattr =,
    //.listxattr =,
    //.removexattr =,
    //.opendir =,
    .readdir = cfs_readdir,
    .releasedir = cfs_releasedir,
    //.fsyncdir =,
    .init =cfs_init,
    //.destroy =,
    //.access =,
    .create = cfs_create
    //.ftruncate =,
    //.fgetattr =,
    //.lock =,
    //.utimens =,
    //.bmap =,
    //.ioctl =,
    //.poll =,
    //.write_buf =,
    //.read_buf =,
    //.flock =,
    //.fallocate =,
    //.readdirplus= ,
};

int main(int argc, char* argv[])
{
	umask(0);
	printf("---------MOUNTING----------!\n");
	global_mount_point = argv[4];  // set global mount point
	printf("%s\n", global_mount_point);
	return fuse_main(argc, argv, &cfs_ops, NULL);
}