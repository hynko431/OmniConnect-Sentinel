//! Test Gate T30: Linux Default-Deny BPF Seccomp Allowlist, Landlock Total FS Deny & W^X Enforcement (`CSE-05`, `Story 3.1`)
//!
//! Validates Master Plan v2 §2.1 & §4.3 (Sub-Phase 1.1):
//! 1. Dual-Architecture Allowlist: Strict stdio/memory/exit syscall allowlist on x86_64 and aarch64.
//! 2. Anti-x32 Masking: Immediate SECCOMP_RET_KILL_PROCESS if nr & 0x4000_0000 != 0.
//! 3. W^X Enforcement: mmap and mprotect inspected at argument level; PROT_EXEC (0x04) killed.
//! 4. Default-Deny: Any unallowed or unknown syscall returns SECCOMP_RET_KILL_PROCESS.
//! 5. Landlock ABI v1-v4: Total empty-filesystem restriction (zero path rules allowed).
//! 6. Falco Rule YAML Integrity: Verifies detection rule structure and syntax.

use sentinel_sys::{
    generate_seccomp_bpf_filter_aarch64, generate_seccomp_bpf_filter_x86_64,
    landlock_handled_access_fs, simulate_seccomp_filter, SeccompData,
    AARCH64_ALLOWED_SIMPLE_SYSCALLS, AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64, PROT_EXEC,
    SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, X32_SYSCALL_BIT, X86_64_ALLOWED_SIMPLE_SYSCALLS,
};

#[test]
fn test_t30_x86_64_bpf_filter_structural_soundness() {
    let filter = generate_seccomp_bpf_filter_x86_64();
    assert!(
        !filter.is_empty(),
        "x86_64 BPF filter must contain instructions"
    );

    // Final instruction must be ALLOW, and preceding instruction must be KILL_PROCESS
    let last = filter[filter.len() - 1];
    let second_last = filter[filter.len() - 2];
    assert_eq!(last.code, sentinel_sys::bpf_sandbox::BPF_RET_K);
    assert_eq!(last.k, SECCOMP_RET_ALLOW);
    assert_eq!(second_last.code, sentinel_sys::bpf_sandbox::BPF_RET_K);
    assert_eq!(second_last.k, SECCOMP_RET_KILL_PROCESS);
}

#[test]
fn test_t30_x86_64_allowed_simple_syscalls_simulation() {
    let filter = generate_seccomp_bpf_filter_x86_64();

    for &sc in X86_64_ALLOWED_SIMPLE_SYSCALLS {
        let data = SeccompData::new(AUDIT_ARCH_X86_64, sc as i32, [0; 6]);
        let ret = simulate_seccomp_filter(&filter, &data);
        assert_eq!(
            ret, SECCOMP_RET_ALLOW,
            "Syscall {sc} on x86_64 must be permitted by allowlist"
        );
    }
}

#[test]
fn test_t30_x86_64_disallowed_syscalls_killed() {
    let filter = generate_seccomp_bpf_filter_x86_64();

    // Critical hostile / evasion syscalls:
    // open(2), execve(59), execveat(322), fork(57), vfork(58), clone(56), clone3(435),
    // socket(41), connect(42), bind(49), listen(50), accept(43), ptrace(101),
    // io_uring_setup(425), bpf(321), unshare(272), setuid(105), openat(257), openat2(437)
    let hostile_syscalls: &[i32] = &[
        2, 41, 42, 43, 49, 50, 56, 57, 58, 59, 101, 105, 257, 272, 321, 322, 425, 435, 437,
    ];

    for &sc in hostile_syscalls {
        let data = SeccompData::new(AUDIT_ARCH_X86_64, sc, [0; 6]);
        let ret = simulate_seccomp_filter(&filter, &data);
        assert_eq!(
            ret, SECCOMP_RET_KILL_PROCESS,
            "Hostile syscall {sc} MUST be immediately killed by default-deny"
        );
    }
}

#[test]
fn test_t30_x86_64_x32_abi_bit_immediate_kill() {
    let filter = generate_seccomp_bpf_filter_x86_64();

    // Attacker sets bit 30 (0x4000_0000) on an otherwise allowed syscall (e.g. read=0 or write=1)
    let poisoned_read = X32_SYSCALL_BIT as i32;
    let poisoned_write = (X32_SYSCALL_BIT | 1) as i32;
    let poisoned_execve = (X32_SYSCALL_BIT | 59) as i32;

    for &poisoned in &[poisoned_read, poisoned_write, poisoned_execve] {
        let data = SeccompData::new(AUDIT_ARCH_X86_64, poisoned, [0; 6]);
        let ret = simulate_seccomp_filter(&filter, &data);
        assert_eq!(
            ret, SECCOMP_RET_KILL_PROCESS,
            "x32 ABI evasion (nr {poisoned:#x}) MUST be killed immediately"
        );
    }
}

#[test]
fn test_t30_x86_64_wx_memory_protection_enforcement() {
    let filter = generate_seccomp_bpf_filter_x86_64();

    // 1. mmap (nr = 9): arg 2 is prot
    // Non-executable: PROT_READ (1) | PROT_WRITE (2) = 3
    let mut args_clean = [0u64; 6];
    args_clean[2] = 0x03; // RW
    let data_clean = SeccompData::new(AUDIT_ARCH_X86_64, 9, args_clean);
    assert_eq!(
        simulate_seccomp_filter(&filter, &data_clean),
        SECCOMP_RET_ALLOW,
        "mmap with PROT_READ|PROT_WRITE must be allowed"
    );

    // Executable: PROT_READ (1) | PROT_EXEC (4) = 5
    let mut args_exec = [0u64; 6];
    args_exec[2] = (0x01 | PROT_EXEC) as u64; // RX
    let data_exec = SeccompData::new(AUDIT_ARCH_X86_64, 9, args_exec);
    assert_eq!(
        simulate_seccomp_filter(&filter, &data_exec),
        SECCOMP_RET_KILL_PROCESS,
        "mmap with PROT_EXEC MUST be killed by W^X policy"
    );

    // 2. mprotect (nr = 10): arg 2 is prot
    let data_prot_clean = SeccompData::new(AUDIT_ARCH_X86_64, 10, args_clean);
    assert_eq!(
        simulate_seccomp_filter(&filter, &data_prot_clean),
        SECCOMP_RET_ALLOW,
        "mprotect with non-executable prot must be allowed"
    );

    let data_prot_exec = SeccompData::new(AUDIT_ARCH_X86_64, 10, args_exec);
    assert_eq!(
        simulate_seccomp_filter(&filter, &data_prot_exec),
        SECCOMP_RET_KILL_PROCESS,
        "mprotect with PROT_EXEC MUST be killed by W^X policy"
    );
}

#[test]
fn test_t30_aarch64_bpf_filter_simulation() {
    let filter = generate_seccomp_bpf_filter_aarch64();

    // Allowed simple syscalls
    for &sc in AARCH64_ALLOWED_SIMPLE_SYSCALLS {
        let data = SeccompData::new(AUDIT_ARCH_AARCH64, sc as i32, [0; 6]);
        assert_eq!(
            simulate_seccomp_filter(&filter, &data),
            SECCOMP_RET_ALLOW,
            "Syscall {sc} on aarch64 must be allowed"
        );
    }

    // Hostile syscalls: execve(221), clone(220), openat(56), socket(198), connect(203)
    for &sc in &[56, 198, 203, 220, 221] {
        let data = SeccompData::new(AUDIT_ARCH_AARCH64, sc, [0; 6]);
        assert_eq!(
            simulate_seccomp_filter(&filter, &data),
            SECCOMP_RET_KILL_PROCESS,
            "Hostile aarch64 syscall {sc} must be killed"
        );
    }

    // mmap (nr = 222) and mprotect (nr = 226) W^X check
    let mut args_clean = [0u64; 6];
    args_clean[2] = 0x03;
    let data_clean = SeccompData::new(AUDIT_ARCH_AARCH64, 222, args_clean);
    assert_eq!(
        simulate_seccomp_filter(&filter, &data_clean),
        SECCOMP_RET_ALLOW
    );

    let mut args_exec = [0u64; 6];
    args_exec[2] = PROT_EXEC as u64;
    let data_exec = SeccompData::new(AUDIT_ARCH_AARCH64, 222, args_exec);
    assert_eq!(
        simulate_seccomp_filter(&filter, &data_exec),
        SECCOMP_RET_KILL_PROCESS
    );
}

#[test]
fn test_t30_architecture_mismatch_killed() {
    let filter_x86 = generate_seccomp_bpf_filter_x86_64();
    let filter_arm = generate_seccomp_bpf_filter_aarch64();

    // x86_64 filter tested with aarch64 data
    let data_arm = SeccompData::new(AUDIT_ARCH_AARCH64, 0, [0; 6]);
    assert_eq!(
        simulate_seccomp_filter(&filter_x86, &data_arm),
        SECCOMP_RET_KILL_PROCESS,
        "x86_64 filter must kill aarch64 arch payload"
    );

    // aarch64 filter tested with x86_64 data
    let data_x86 = SeccompData::new(AUDIT_ARCH_X86_64, 63, [0; 6]);
    assert_eq!(
        simulate_seccomp_filter(&filter_arm, &data_x86),
        SECCOMP_RET_KILL_PROCESS,
        "aarch64 filter must kill x86_64 arch payload"
    );

    // Random arch
    let data_bogus = SeccompData::new(0xDEADBEEF, 0, [0; 6]);
    assert_eq!(
        simulate_seccomp_filter(&filter_x86, &data_bogus),
        SECCOMP_RET_KILL_PROCESS
    );
}

#[test]
fn test_t30_landlock_abi_access_coverage() {
    // ABI v1: bits 0..12 (13 bits)
    let v1 = landlock_handled_access_fs(1);
    assert_eq!(v1, (1 << 13) - 1);

    // ABI v2: adds bit 13 (REFER)
    let v2 = landlock_handled_access_fs(2);
    assert_eq!(v2, (1 << 14) - 1);

    // ABI v3: adds bit 14 (TRUNCATE)
    let v3 = landlock_handled_access_fs(3);
    assert_eq!(v3, (1 << 15) - 1);

    // ABI v4: adds bit 15 (IOCTL_DEV)
    let v4 = landlock_handled_access_fs(4);
    assert_eq!(v4, (1 << 16) - 1);
}

#[test]
fn test_t30_falco_rule_file_integrity() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let falco_rule_path = workspace_root
        .join("rules")
        .join("falco")
        .join("omniconnect-sentinel-cdr.yaml");

    assert!(
        falco_rule_path.exists(),
        "Falco rule file must exist at rules/falco/omniconnect-sentinel-cdr.yaml"
    );

    let content = std::fs::read_to_string(&falco_rule_path).expect("read falco rule");
    assert!(content.contains("OmniConnect Sentinel CDR Worker Unauthorized Syscall"));
    assert!(content.contains("OmniConnect Sentinel CDR Worker W^X Memory Protection Violation"));
    assert!(content.contains("priority: CRITICAL"));
    assert!(content.contains("container_escape") || content.contains("mitre_execution"));
}
