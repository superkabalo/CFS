cfs: cfs.c aes_encryption.c aes_encryption.h sha3.c sha3.h file_headers.c file_headers.h button.c button.h
	gcc -Wall cfs.c aes_encryption.c sha3.c file_headers.c button.c `pkg-config fuse3 --cflags --libs` -I/usr/include/openssl -L/usr/lib/ -lssl -lcrypto -o cfs

clean:
	rm -f cfs
