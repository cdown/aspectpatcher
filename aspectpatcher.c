#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define NR_BYTES 4

static void die(const char *fmt, ...) {
    int sv = errno;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    size_t len = strlen(fmt);
    if (len > 0 && fmt[len - 1] == ':') {
        fputc(' ', stderr);
        errno = sv;
        perror(NULL);
    } else {
        fputc('\n', stderr);
    }
    exit(1);
}

static void float_to_le(float f, uint8_t *out) {
    uint32_t u;
    memcpy(&u, &f, sizeof(u));
    for (int i = 0; i < NR_BYTES; i++)
        out[i] = (u >> (i * 8)) & 0xFF;
}

static void parse_arg(const char *s, uint8_t *out) {
    int n = 0;

    /* hex, use %n to make sure we don't copy any garbage */
    if (sscanf(s, "%hhx %hhx %hhx %hhx%n", &out[0], &out[1], &out[2], &out[3],
               &n) == 4 &&
        !s[n])
        return;

    /* ratio */
    float w, h;
    char sep;
    if (sscanf(s, "%f%c%f%n", &w, &sep, &h, &n) == 3 && !s[n] &&
        strchr(":xX", sep)) {
        if (w > 0 && h > 0) {
            float_to_le(w / h, out);
            return;
        }
    }

    /* float itself */
    char *end;
    float f = strtof(s, &end);
    if (*end == '\0') {
        float_to_le(f, out);
        return;
    }

    die("invalid input '%s', expected hex, ratio, or float", s);
}

int main(int argc, char *argv[]) {
    uint8_t tgt[NR_BYTES], rep[NR_BYTES];
    int opt, has_t = 0, has_r = 0;

    while ((opt = getopt(argc, argv, "t:r:")) != -1) {
        switch (opt) {
            case 't':
                parse_arg(optarg, tgt);
                has_t = 1;
                break;
            case 'r':
                parse_arg(optarg, rep);
                has_r = 1;
                break;
            default:
                return 1;
        }
    }

    if (!has_t || !has_r || optind >= argc)
        die("usage: %s -t <target> -r <replace> <file>", argv[0]);

    if (argv[optind + 1])
        die("multiple files provided");

    int fd = open(argv[optind], O_RDWR);
    if (fd < 0)
        die("open %s:", argv[optind]);

    struct stat st;
    if (fstat(fd, &st) < 0)
        die("fstat:");

    uint8_t *data =
        mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED)
        die("mmap:");

    posix_madvise(data, st.st_size, POSIX_MADV_SEQUENTIAL);

    size_t count = 0;
    for (size_t i = 0; i + NR_BYTES <= (size_t)st.st_size; i++) {
        if (data[i] == tgt[0] && memcmp(data + i, tgt, NR_BYTES) == 0) {
            memcpy(data + i, rep, NR_BYTES);
            count++;
            i += (NR_BYTES - 1);
        }
    }

    if (munmap(data, st.st_size) < 0)
        die("munmap:");
    if (close(fd) < 0)
        die("close:");

    printf("%zu matches replaced\n", count);
}
