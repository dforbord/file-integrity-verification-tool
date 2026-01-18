/**
 * @file filecompare.c
 * @author ** Dylan Forbord **
 * @date ** December 14 2025 **
 * @brief Program that demonstrates the use of the SHA256 hashing algorithm in
 *        the OpenSSL library to determine whether two files whose names are 
 *        given as command line arguments are identical.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/evp.h>

#define BUF_SIZE 4096

static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s file1 file2\n", prog_name);
}

/*
 * Compute SHA256 for a file of any size and any type.
 * Returns true or false on failure.
 */
static bool sha256_file(const char *filename, unsigned char hash_out[EVP_MAX_MD_SIZE], unsigned int *hash_len_out) {
    int fd = -1;
    EVP_MD_CTX *ctx = NULL;
    unsigned char buffer[BUF_SIZE];
    ssize_t bytes_read;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error: could not open %s: %s\n", filename, strerror(errno));
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: EVP_MD_CTX_new failed\n");
        close(fd);
        return false;
    }

    /* Initialize for SHA256 */
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Error: EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        close(fd);
        return false;
    }

    /* Read the whole file in chunks and update the hash */
    while (1) {
        bytes_read = read(fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            fprintf(stderr, "Error: could not read %s: %s\n", filename, strerror(errno));
            EVP_MD_CTX_free(ctx);
            close(fd);
            return false;
        }
        if (bytes_read == 0) {
            break; 
        }

        if (EVP_DigestUpdate(ctx, buffer, (size_t)bytes_read) != 1) {
            fprintf(stderr, "Error: EVP_DigestUpdate failed\n");
            EVP_MD_CTX_free(ctx);
            close(fd);
            return false;
        }
    }

    /* Finalize the hash */
    if (EVP_DigestFinal_ex(ctx, hash_out, hash_len_out) != 1) {
        fprintf(stderr, "Error: EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(ctx);
        close(fd);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    close(fd);
    return true;
}

static bool hashes_equal(const unsigned char *h1, const unsigned char *h2, unsigned int len) {
    unsigned int i;
    for (i = 0; i < len; i++) {
        if (h1[i] != h2[i]) {
            return false;
        }
    }
    return true;
}

int main(int argc, char *argv[]) {
    const char *file1;
    const char *file2;

    unsigned char hash1[EVP_MAX_MD_SIZE];
    unsigned char hash2[EVP_MAX_MD_SIZE];
    unsigned int hash1_len = 0;
    unsigned int hash2_len = 0;

    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    file1 = argv[1];
    file2 = argv[2];

    if (!sha256_file(file1, hash1, &hash1_len)) {
        return 1;
    }
    if (!sha256_file(file2, hash2, &hash2_len)) {
        return 1;
    }

    /* Compare the two hashes to see if the files match */
    if (hash1_len == hash2_len && hashes_equal(hash1, hash2, hash1_len)) {
        printf("Files %s and %s are identical\n", file1, file2);
    } else {
        printf("Files %s and %s differ\n", file1, file2);
    }

    return 0;
}

