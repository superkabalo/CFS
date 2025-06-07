#include "file_headers.h"

int checkFileSignature(char* buf)
{
    if (!strncmp(buf, CFS_FILE_SIGNATURE, CFS_FILE_SIGNATURE_SIZE))  // check if file is a user file
    {
        return 1;
    }
    return -1;
}
