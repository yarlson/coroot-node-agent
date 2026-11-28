#define UV_STREAM_FD_OFFSET 184

struct nodejs_ptr_key {
    __u64 ptr;
    __u32 pid;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct nodejs_ptr_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 32768);
} nodejs_lsw_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct nodejs_ptr_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 32768);
} nodejs_tls_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} nodejs_uv_read_lsw SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} nodejs_enc_out_tls SEC(".maps");

static __always_inline
__s64 nodejs_record_uv_stream(__u32 pid, void *stream) {
    if (!stream) {
        return -1;
    }
    __u64 lsw = 0;
    __s32 fd = -1;
    if (bpf_probe_read(&lsw, sizeof(lsw), stream) || !lsw) {
        return -1;
    }
    if (bpf_probe_read(&fd, sizeof(fd), (char *)stream + UV_STREAM_FD_OFFSET) || fd < 0) {
        return -1;
    }
    struct nodejs_ptr_key k = {.ptr = lsw, .pid = pid};
    __u64 fd64 = (__u64)fd;
    __u64 *cur = bpf_map_lookup_elem(&nodejs_lsw_fd, &k);
    if (!cur || *cur != fd64) {
        bpf_map_update_elem(&nodejs_lsw_fd, &k, &fd64, BPF_ANY);
    }
    return fd64;
}

SEC("uprobe/nodejs_tls_enc_out")
int nodejs_tls_enc_out(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 tls = PT_REGS_PARM1(ctx);
    struct nodejs_ptr_key k = {.ptr = tls, .pid = tid >> 32};
    if (bpf_map_lookup_elem(&nodejs_tls_fd, &k)) {
        return 0;
    }
    bpf_map_update_elem(&nodejs_enc_out_tls, &tid, &tls, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_enc_out_exit")
int nodejs_tls_enc_out_exit(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_enc_out_tls, &tid);
    return 0;
}

SEC("uprobe/nodejs_uv_read_start")
int nodejs_uv_read_start(struct pt_regs *ctx) {
    nodejs_record_uv_stream(bpf_get_current_pid_tgid() >> 32, (void *)PT_REGS_PARM1(ctx));
    return 0;
}

SEC("uprobe/nodejs_uv_try_write")
int nodejs_uv_try_write(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    // clear any ssl_pending left by distro libssl SSL_write before libuv's write syscall runs
    bpf_map_delete_elem(&ssl_pending, &tid);
    __s64 fd = nodejs_record_uv_stream(pid, (void *)PT_REGS_PARM1(ctx));
    __u64 *tls = bpf_map_lookup_elem(&nodejs_enc_out_tls, &tid);
    if (!tls) {
        return 0;
    }
    struct nodejs_ptr_key k = {.ptr = *tls, .pid = pid};
    bpf_map_delete_elem(&nodejs_enc_out_tls, &tid);
    if (fd >= 0) {
        __u64 fd64 = (__u64)fd;
        bpf_map_update_elem(&nodejs_tls_fd, &k, &fd64, BPF_NOEXIST);
    }
    return 0;
}

SEC("uprobe/nodejs_on_uv_read_enter")
int nodejs_on_uv_read_enter(struct pt_regs *ctx) {
    __s64 nread = (__s64)PT_REGS_PARM2(ctx);
    if (nread <= 0) {
        return 0;
    }
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 lsw = PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&nodejs_uv_read_lsw, &tid, &lsw, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_on_uv_read_exit")
int nodejs_on_uv_read_exit(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&nodejs_uv_read_lsw, &tid);
    return 0;
}

SEC("uprobe/nodejs_tls_on_stream_read")
int nodejs_tls_on_stream_read(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 *lsw = bpf_map_lookup_elem(&nodejs_uv_read_lsw, &tid);
    if (!lsw) {
        return 0;
    }
    struct nodejs_ptr_key k = {.ptr = *lsw, .pid = tid >> 32};
    bpf_map_delete_elem(&nodejs_uv_read_lsw, &tid);
    __u64 *fd = bpf_map_lookup_elem(&nodejs_lsw_fd, &k);
    if (!fd) {
        return 0;
    }
    __u64 fd64 = *fd;
    k.ptr = PT_REGS_PARM1(ctx);
    __u64 *cur = bpf_map_lookup_elem(&nodejs_tls_fd, &k);
    if (!cur || *cur != fd64) {
        bpf_map_update_elem(&nodejs_tls_fd, &k, &fd64, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/nodejs_tls_clear_out_enter")
int nodejs_tls_clear_out_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct nodejs_ptr_key k = {.ptr = PT_REGS_PARM1(ctx), .pid = tid >> 32};
    __u64 *fd = bpf_map_lookup_elem(&nodejs_tls_fd, &k);
    if (!fd) {
        bpf_map_delete_elem(&ssl_last_fd, &tid);
        return 0;
    }
    __u64 fd64 = *fd;
    bpf_map_update_elem(&ssl_last_fd, &tid, &fd64, BPF_ANY);
    return 0;
}

SEC("uprobe/nodejs_tls_clear_out_exit")
int nodejs_tls_clear_out_exit(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_last_fd, &tid);
    return 0;
}

UPROBE_NO_PREEMPT(nodejs_tls_do_write) {
    __u64 count = PT_REGS_PARM4(ctx);
    if (!count) {
        return 0;
    }
    __u64 tid = bpf_get_current_pid_tgid();
    struct nodejs_ptr_key k = {.ptr = PT_REGS_PARM1(ctx), .pid = tid >> 32};
    __u64 *fd_ptr = bpf_map_lookup_elem(&nodejs_tls_fd, &k);
    if (!fd_ptr) {
        return 0;
    }
    return trace_enter_write(ctx, *fd_ptr, 1, 1, (char *)PT_REGS_PARM3(ctx), 0, count);
}

SEC("uprobe/nodejs_tls_do_write_exit")
int nodejs_tls_do_write_exit(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_pending, &tid);
    return 0;
}

SEC("uprobe/nodejs_tls_destroy")
int nodejs_tls_destroy(struct pt_regs *ctx) {
    struct nodejs_ptr_key k = {.ptr = PT_REGS_PARM1(ctx), .pid = bpf_get_current_pid_tgid() >> 32};
    bpf_map_delete_elem(&nodejs_tls_fd, &k);
    return 0;
}
