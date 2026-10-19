
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define DEFAULT_PORT 4040

static volatile sig_atomic_t running = 1;

static void stop(int sig)
{
    running = 0;
}

int main(int argc, char **argv)
{
    unsigned long port = DEFAULT_PORT;
    char *end = NULL;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        return 1;
    }

    if (argc == 2) {
        port = strtoul(argv[1], &end, 10);

        if (!argv[1][0] || !end || *end ||
            port < 1 || port > 65535) {
            fprintf(stderr, "Invalid port\n");
            return 1;
        }
    }

    struct bpf_object *obj =
        bpf_object__open_file("filter.bpf.o", NULL);

    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Could not open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Could not load BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj,
                                         "filter_process");

    struct bpf_map *map =
        bpf_object__find_map_by_name(obj, "allowed_port");

    if (!prog || !map) {
        fprintf(stderr, "Program or map not found\n");
        bpf_object__close(obj);
        return 1;
    }

    __u32 key = 0;
    __u32 value = (__u32)port;

    if (bpf_map_update_elem(bpf_map__fd(map),
                            &key, &value, BPF_ANY)) {
        perror("Map update failed");
        bpf_object__close(obj);
        return 1;
    }

    int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Could not open cgroup v2");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_link *link =
        bpf_program__attach_cgroup(prog, cgroup_fd);

    if (libbpf_get_error(link)) {
        fprintf(stderr, "Could not attach eBPF program\n");
        close(cgroup_fd);
        bpf_object__close(obj);
        return 1;
    }

    printf("Process: myprocess\n");
    printf("Allowed TCP destination port: %lu\n", port);
    printf("Attached to cgroup v2. Press Ctrl+C to stop.\n");

    signal(SIGINT, stop);
    signal(SIGTERM, stop);

    while (running)
        pause();

    bpf_link__destroy(link);
    close(cgroup_fd);
    bpf_object__close(obj);

    return 0;
}
