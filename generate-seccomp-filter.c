/*
 * Generates a compiled seccomp-bpf filter for bwrap's --seccomp flag.
 *
 * Denylist approach: allow everything by default, block known-dangerous
 * syscalls. An allowlist would be more secure but too fragile for a complex
 * application (Go runtime + shell + git + dev tools).
 *
 * Usage:
 *   ./generate-seccomp-filter              # writes BPF to stdout
 *   ./generate-seccomp-filter 10           # writes BPF to fd 10
 *   ./generate-seccomp-filter -o filter.bpf  # writes BPF to file
 *
 * Compile:
 *   gcc -O2 -o generate-seccomp-filter generate-seccomp-filter.c -lseccomp
 */

#include <errno.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct blocked_syscall {
    int nr;
    const char *name;
    const char *reason;
};

static const struct blocked_syscall blocklist[] = {
    /* ── Mounting / filesystem topology ─────────────────────────────── */
    /* mount/umount2/pivot_root are REQUIRED by a nested bwrap (Claude Code's
     * inner Bash sandbox spawns bwrap on Linux even when its own sandbox is
     * disabled). bwrap's first setup step is mount(NULL,"/",NULL,MS_SLAVE|MS_REC)
     * which seccomp would reject with EPERM ("Failed to make / slave").
     * These are left UNBLOCKED so nested bwrap can complete. The file-visibility
     * boundary is still enforced by the OUTER mount namespace + bind mounts in
     * claude-sandboxed (a nested mount only affects the already-restricted view),
     * so this does not expose new host paths — it only restores kernel mount-API
     * attack surface. chroot stays blocked (bwrap uses pivot_root, not chroot). */
    { SCMP_SYS(chroot),            "chroot",            "prevent chroot escape tricks" },
#ifdef __NR_fsopen
    { SCMP_SYS(fsopen),            "fsopen",            "new mount API" },
#endif
#ifdef __NR_fsconfig
    { SCMP_SYS(fsconfig),          "fsconfig",          "new mount API" },
#endif
#ifdef __NR_fsmount
    { SCMP_SYS(fsmount),           "fsmount",           "new mount API" },
#endif
#ifdef __NR_fspick
    { SCMP_SYS(fspick),            "fspick",            "new mount API" },
#endif
#ifdef __NR_move_mount
    { SCMP_SYS(move_mount),        "move_mount",        "new mount API" },
#endif
#ifdef __NR_open_tree
    { SCMP_SYS(open_tree),         "open_tree",         "new mount API" },
#endif
#ifdef __NR_mount_setattr
    { SCMP_SYS(mount_setattr),     "mount_setattr",     "new mount API" },
#endif

    /* ── Kernel modules ────────────────────────────────────────────── */
    { SCMP_SYS(init_module),       "init_module",       "prevent kernel module loading" },
    { SCMP_SYS(finit_module),      "finit_module",      "prevent kernel module loading" },
    { SCMP_SYS(delete_module),     "delete_module",     "prevent kernel module removal" },

    /* ── Kernel boot / execution ───────────────────────────────────── */
    { SCMP_SYS(kexec_load),        "kexec_load",        "prevent loading new kernel" },
    { SCMP_SYS(kexec_file_load),   "kexec_file_load",   "prevent loading new kernel" },
    { SCMP_SYS(reboot),            "reboot",            "prevent system reboot" },

    /* ── Process tracing / debugging ───────────────────────────────── */
    { SCMP_SYS(ptrace),            "ptrace",            "prevent tracing other processes" },
    { SCMP_SYS(process_vm_readv),  "process_vm_readv",  "prevent reading process memory" },
    { SCMP_SYS(process_vm_writev), "process_vm_writev", "prevent writing process memory" },
#ifdef __NR_process_madvise
    { SCMP_SYS(process_madvise),   "process_madvise",   "prevent cross-process memory hints" },
#endif

    /* ── Swap manipulation ─────────────────────────────────────────── */
    { SCMP_SYS(swapon),            "swapon",            "prevent swap manipulation" },
    { SCMP_SYS(swapoff),           "swapoff",           "prevent swap manipulation" },

    /* ── Host identity ─────────────────────────────────────────────── */
    { SCMP_SYS(sethostname),       "sethostname",       "prevent hostname change" },
    { SCMP_SYS(setdomainname),     "setdomainname",     "prevent domain change" },

    /* ── Time manipulation ─────────────────────────────────────────── */
    { SCMP_SYS(settimeofday),      "settimeofday",      "prevent system clock change" },
    { SCMP_SYS(adjtimex),          "adjtimex",          "prevent clock adjustment" },
    { SCMP_SYS(clock_adjtime),     "clock_adjtime",     "prevent clock adjustment" },
    { SCMP_SYS(clock_settime),     "clock_settime",     "prevent clock set" },

    /* ── Accounting ────────────────────────────────────────────────── */
    { SCMP_SYS(acct),              "acct",              "prevent process accounting changes" },

    /* ── Kernel keyring ────────────────────────────────────────────── */
    { SCMP_SYS(keyctl),            "keyctl",            "prevent kernel keyring access" },
    { SCMP_SYS(add_key),           "add_key",           "prevent kernel keyring access" },
    { SCMP_SYS(request_key),       "request_key",       "prevent kernel keyring access" },

    /* ── BPF (eBPF program loading) ────────────────────────────────── */
    { SCMP_SYS(bpf),               "bpf",               "prevent loading eBPF programs" },

    /* ── Performance / tracing (info leaks) ────────────────────────── */
    { SCMP_SYS(perf_event_open),   "perf_event_open",   "prevent performance monitoring (info leak)" },
    { SCMP_SYS(lookup_dcookie),    "lookup_dcookie",    "prevent kernel info leak" },
#ifdef __NR_kcmp
    { SCMP_SYS(kcmp),              "kcmp",              "prevent kernel comparison (info leak)" },
#endif

    /* ── io_uring (large attack surface, many CVEs) ────────────────── */
#ifdef __NR_io_uring_setup
    { SCMP_SYS(io_uring_setup),    "io_uring_setup",    "block io_uring (CVE-heavy)" },
#endif
#ifdef __NR_io_uring_enter
    { SCMP_SYS(io_uring_enter),    "io_uring_enter",    "block io_uring (CVE-heavy)" },
#endif
#ifdef __NR_io_uring_register
    { SCMP_SYS(io_uring_register), "io_uring_register", "block io_uring (CVE-heavy)" },
#endif

    /* ── Filesystem handle bypass ──────────────────────────────────── */
    { SCMP_SYS(open_by_handle_at), "open_by_handle_at", "prevent chroot/namespace bypass" },
    { SCMP_SYS(name_to_handle_at), "name_to_handle_at", "prevent chroot/namespace bypass" },

    /* ── userfaultfd (exploit primitive) ───────────────────────────── */
    { SCMP_SYS(userfaultfd),       "userfaultfd",       "block exploit primitive" },

    /* ── I/O port access (x86 only, ring-0 equivalent) ────────────── */
    { SCMP_SYS(ioperm),            "ioperm",            "prevent I/O port access" },
    { SCMP_SYS(iopl),              "iopl",              "prevent I/O privilege level change" },

    /* ── Disk quotas ───────────────────────────────────────────────── */
    { SCMP_SYS(quotactl),          "quotactl",          "prevent quota manipulation" },
#ifdef __NR_quotactl_fd
    { SCMP_SYS(quotactl_fd),       "quotactl_fd",       "prevent quota manipulation" },
#endif

    /* ── Terminal hangup ───────────────────────────────────────────── */
    { SCMP_SYS(vhangup),           "vhangup",           "prevent terminal hangup" },

    /* ── Personality (can disable ASLR) ────────────────────────────── */
    { SCMP_SYS(personality),        "personality",       "prevent ASLR disable" },

    /* ── Filesystem notify (excessive monitoring) ──────────────────── */
    { SCMP_SYS(fanotify_init),     "fanotify_init",     "prevent filesystem-wide monitoring" },

    /* ── Obsolete / dangerous ──────────────────────────────────────── */
    { SCMP_SYS(nfsservctl),        "nfsservctl",        "obsolete NFS control" },

    /* ── Raw socket creation (block SOCK_RAW only) ─────────────────  */
    /* Handled separately below via SCMP_A1 argument filter            */
};

static const size_t blocklist_len = sizeof(blocklist) / sizeof(blocklist[0]);

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-o FILE] [-v] [FD]\n"
        "  -o FILE   write BPF to FILE instead of fd\n"
        "  -v        verbose: print blocked syscalls to stderr\n"
        "  FD        write BPF to this fd number (default: stdout)\n",
        prog);
}

int main(int argc, char *argv[]) {
    int out_fd = STDOUT_FILENO;
    const char *out_file = NULL;
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out_file = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            out_fd = atoi(argv[i]);
            if (out_fd <= 0) {
                fprintf(stderr, "Invalid fd: %s\n", argv[i]);
                return 1;
            }
        }
    }

    if (out_file) {
        out_fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd < 0) {
            perror("open output file");
            return 1;
        }
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        return 1;
    }

    int rc;
    int blocked_count = 0;
    for (size_t i = 0; i < blocklist_len; i++) {
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
                              blocklist[i].nr, 0);
        if (rc < 0) {
            fprintf(stderr, "warning: failed to add rule for %s: %s\n",
                    blocklist[i].name, strerror(-rc));
            continue;
        }
        blocked_count++;
        if (verbose) {
            fprintf(stderr, "  blocked: %-24s (%s)\n",
                    blocklist[i].name, blocklist[i].reason);
        }
    }

    /* Block SOCK_RAW in socket() — prevents packet sniffing / spoofing.
     * Allow SOCK_STREAM (TCP) and SOCK_DGRAM (UDP) normally.
     *
     * AF_NETLINK is EXEMPTED from this block. Like the mount/umount2/pivot_root
     * exemptions above, this is required by a nested bwrap (Claude Code's inner
     * Bash sandbox spawns bwrap on Linux). That inner bwrap unshares the network
     * namespace and brings up loopback via
     *   socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)
     * If we block it, the inner bwrap dies and *every shell command* fails with:
     *   bwrap: loopback: Failed to create NETLINK_ROUTE socket: Operation not permitted
     * A netlink "raw" socket is just the netlink convention — it is NOT a
     * packet-sniffing/spoofing primitive, so exempting it costs no security
     * (and llm_restricted has no CAP_NET_ADMIN to reconfigure host networking).
     * We still block SOCK_RAW for every other family, which is the real attack
     * surface: AF_INET/AF_INET6 raw IP (spoofing, raw ICMP) and AF_PACKET (L2
     * sniffing). The two comparisons (family != AF_NETLINK) AND (type has
     * SOCK_RAW) are ANDed, so only non-netlink raw sockets are rejected. */
    rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
                          SCMP_SYS(socket), 2,
                          SCMP_A0(SCMP_CMP_NE, AF_NETLINK),
                          SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_RAW, SOCK_RAW));
    if (rc == 0) {
        blocked_count++;
        if (verbose)
            fprintf(stderr, "  blocked: %-24s (%s)\n",
                    "socket(SOCK_RAW)", "prevent raw socket creation");
    }

    rc = seccomp_export_bpf(ctx, out_fd);
    if (rc < 0) {
        fprintf(stderr, "seccomp_export_bpf failed: %s\n", strerror(-rc));
        seccomp_release(ctx);
        return 1;
    }

    seccomp_release(ctx);

    if (verbose)
        fprintf(stderr, "seccomp filter: %d syscalls blocked\n", blocked_count);

    if (out_file)
        close(out_fd);

    return 0;
}
