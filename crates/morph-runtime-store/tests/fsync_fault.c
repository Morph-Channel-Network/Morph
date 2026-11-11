/* Test-only syscall fault. Loaded solely into an owned Rust test subprocess. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int should_fail(void) {
    const char *marker = getenv("MORPH_STORE_TEST_SYNC_FAILURE");
    return marker && access(marker, F_OK) == 0;
}

int fsync(int fd) {
    if (should_fail()) { errno = EIO; return -1; }
    int (*real_sync)(int) = dlsym(RTLD_NEXT, "fsync");
    if (!real_sync) { errno = EIO; return -1; }
    return real_sync(fd);
}

int fdatasync(int fd) {
    if (should_fail()) { errno = EIO; return -1; }
    int (*real_sync)(int) = dlsym(RTLD_NEXT, "fdatasync");
    if (!real_sync) { errno = EIO; return -1; }
    return real_sync(fd);
}

static int full_database_fd(int fd) {
    const char *marker = getenv("MORPH_STORE_TEST_WRITE_FAILURE");
    const char *database = getenv("MORPH_STORE_TEST_PATH");
    if (!marker || !database || access(marker, F_OK) != 0) return 0;
    char descriptor[64], path[4096];
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(descriptor, path, sizeof(path) - 1);
    if (length < 0) return 0;
    path[length] = 0;
    size_t prefix = strlen(database);
    return strncmp(path, database, prefix) == 0 &&
        (path[prefix] == 0 || path[prefix] == '-');
}

ssize_t write(int fd, const void *data, size_t size) {
    if (full_database_fd(fd)) { errno = ENOSPC; return -1; }
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    if (!real_write) { errno = EIO; return -1; }
    return real_write(fd, data, size);
}

ssize_t pwrite64(int fd, const void *data, size_t size, off64_t offset) {
    if (full_database_fd(fd)) { errno = ENOSPC; return -1; }
    ssize_t (*real_write)(int, const void *, size_t, off64_t) = dlsym(RTLD_NEXT, "pwrite64");
    if (!real_write) { errno = EIO; return -1; }
    return real_write(fd, data, size, offset);
}

ssize_t pwrite(int fd, const void *data, size_t size, off_t offset) {
    if (full_database_fd(fd)) { errno = ENOSPC; return -1; }
    ssize_t (*real_write)(int, const void *, size_t, off_t) = dlsym(RTLD_NEXT, "pwrite");
    if (!real_write) { errno = EIO; return -1; }
    return real_write(fd, data, size, offset);
}
