//! Cold-Eye Compliance Auditor: Adversarial Break-It Probe for Sub-Phase 1.1 (`CSE-05`, `Story 3.1`)
//!
//! Rigorously verifies:
//! 1. Architecture Spoofing Immunity (x86_64, aarch64, i386, ARM, invalid/poisoned arch)
//! 2. Anti-x32 Masking Probe on simple, memory, and fuzzed syscall numbers
//! 3. Default-Deny Semantics: Fuzzing 1000+ syscalls + negative syscalls + dangerous Linux syscall sweeps
//! 4. Full 8-bit Exhaustive W^X Probe on mmap & mprotect
//! 5. BPF Static Analysis: Jump offset bounds, strictly forward jumps, no errno/trap fallbacks
//! 6. Landlock ABI v1-v4 Exact Bitfield Coverage
//! 7. Falco Ruleset Semantic Compliance & Attack Surface Coverage

use sentinel_sys::{
    generate_seccomp_bpf_filter_aarch64, generate_seccomp_bpf_filter_x86_64,
    landlock_handled_access_fs, simulate_seccomp_filter, SeccompData,
    AARCH64_ALLOWED_SIMPLE_SYSCALLS, AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64, PROT_EXEC,
    SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, X32_SYSCALL_BIT, X86_64_ALLOWED_SIMPLE_SYSCALLS,
};

#[test]
fn adversarial_probe_bpf_static_instruction_safety() {
    let x86_filter = generate_seccomp_bpf_filter_x86_64();
    let arm_filter = generate_seccomp_bpf_filter_aarch64();

    for (name, filter) in [("x86_64", &x86_filter), ("aarch64", &arm_filter)] {
        assert!(filter.len() >= 10, "{name} filter too short");
        assert!(filter.len() <= 512, "{name} filter excessively large");

        for (idx, insn) in filter.iter().enumerate() {
            // Check that all jump targets are forward and strictly within filter bounds
            match insn.code {
                sentinel_sys::bpf_sandbox::BPF_JMP_JEQ_K
                | sentinel_sys::bpf_sandbox::BPF_JMP_JSET_K => {
                    let target_true = idx + 1 + (insn.jt as usize);
                    let target_false = idx + 1 + (insn.jf as usize);
                    assert!(
                        target_true < filter.len(),
                        "{name}: Instruction {idx} jt targets {target_true} out of bounds ({})",
                        filter.len()
                    );
                    assert!(
                        target_false < filter.len(),
                        "{name}: Instruction {idx} jf targets {target_false} out of bounds ({})",
                        filter.len()
                    );
                }
                sentinel_sys::bpf_sandbox::BPF_RET_K => {
                    // Returns must strictly be SECCOMP_RET_ALLOW or SECCOMP_RET_KILL_PROCESS
                    // NEVER SECCOMP_RET_ERRNO, SECCOMP_RET_TRAP, or SECCOMP_RET_LOG
                    assert!(
                        insn.k == SECCOMP_RET_ALLOW || insn.k == SECCOMP_RET_KILL_PROCESS,
                        "{name}: Return instruction at {idx} returns unauthorized action {:#x}",
                        insn.k
                    );
                }
                sentinel_sys::bpf_sandbox::BPF_LD_W_ABS => {
                    // Only load from valid seccomp_data offsets
                    assert!(
                        insn.k <= 60 && insn.k % 4 == 0,
                        "{name}: Invalid load offset {} at instruction {idx}",
                        insn.k
                    );
                }
                _ => panic!(
                    "{name}: Unexpected opcode {:#x} at instruction {idx}",
                    insn.code
                ),
            }
        }

        // Terminal instructions must strictly be KILL followed by ALLOW
        let last = filter[filter.len() - 1];
        let second_last = filter[filter.len() - 2];
        assert_eq!(last.code, sentinel_sys::bpf_sandbox::BPF_RET_K);
        assert_eq!(last.k, SECCOMP_RET_ALLOW);
        assert_eq!(second_last.code, sentinel_sys::bpf_sandbox::BPF_RET_K);
        assert_eq!(second_last.k, SECCOMP_RET_KILL_PROCESS);
    }
}

#[test]
fn adversarial_probe_architecture_spoofing_immunity() {
    let x86_filter = generate_seccomp_bpf_filter_x86_64();
    let arm_filter = generate_seccomp_bpf_filter_aarch64();

    let bogus_architectures: &[u32] = &[
        0x0000_0000,        // NULL
        0x4000_0003,        // AUDIT_ARCH_I386
        0x4000_0028,        // AUDIT_ARCH_ARM (32-bit)
        0xC000_003E ^ 0x01, // x86_64 single-bit flipped
        0xC000_00B7 ^ 0x01, // aarch64 single-bit flipped
        0x8000_0000,        // High bit set
        0x7FFF_FFFF,        // Max i32
        0xFFFF_FFFF,        // All ones
    ];

    for &arch in bogus_architectures {
        // Even for syscalls that would be allowed under correct arch
        for sc in [0, 1, 9, 10, 60, 231] {
            let data = SeccompData::new(arch, sc, [0; 6]);
            assert_eq!(
                simulate_seccomp_filter(&x86_filter, &data),
                SECCOMP_RET_KILL_PROCESS,
                "x86_64 filter permitted syscall {sc} with forged arch {arch:#x}"
            );
            assert_eq!(
                simulate_seccomp_filter(&arm_filter, &data),
                SECCOMP_RET_KILL_PROCESS,
                "aarch64 filter permitted syscall {sc} with forged arch {arch:#x}"
            );
        }
    }
}

#[test]
fn adversarial_probe_anti_x32_abi_exhaustive_poisoning() {
    let filter = generate_seccomp_bpf_filter_x86_64();

    // 1. Poison every allowed simple syscall with X32 bit
    for &sc in X86_64_ALLOWED_SIMPLE_SYSCALLS {
        let poisoned = (X32_SYSCALL_BIT | sc) as i32;
        let data = SeccompData::new(AUDIT_ARCH_X86_64, poisoned, [0; 6]);
        assert_eq!(
            simulate_seccomp_filter(&filter, &data),
            SECCOMP_RET_KILL_PROCESS,
            "x32-poisoned simple syscall {sc} was NOT killed!"
        );
    }

    // 2. Poison mmap (9) and mprotect (10)
    for &sc in &[9, 10] {
        let poisoned = (X32_SYSCALL_BIT | sc) as i32;
        let mut clean_args = [0u64; 6];
        clean_args[2] = 0x03; // RW without EXEC
        let data = SeccompData::new(AUDIT_ARCH_X86_64, poisoned, clean_args);
        assert_eq!(
            simulate_seccomp_filter(&filter, &data),
            SECCOMP_RET_KILL_PROCESS,
            "x32-poisoned memory syscall {sc} was NOT killed!"
        );
    }

    // 3. Fuzz 500 syscall numbers with x32 bit set
    for sc in 0..500 {
        let poisoned = (X32_SYSCALL_BIT | sc) as i32;
        let data = SeccompData::new(AUDIT_ARCH_X86_64, poisoned, [0; 6]);
        assert_eq!(
            simulate_seccomp_filter(&filter, &data),
            SECCOMP_RET_KILL_PROCESS,
            "x32-poisoned fuzz syscall {sc} was NOT killed!"
        );
    }
}

#[test]
fn adversarial_probe_exhaustive_default_deny_and_negative_syscalls() {
    let x86_filter = generate_seccomp_bpf_filter_x86_64();
    let arm_filter = generate_seccomp_bpf_filter_aarch64();

    // 1. Negative syscall numbers (Linux seccomp nr is signed 32-bit)
    let negative_nrs = [-1, -2, -10, -59, -100, -1000, i32::MIN];
    for &nr in &negative_nrs {
        let data_x86 = SeccompData::new(AUDIT_ARCH_X86_64, nr, [0; 6]);
        assert_eq!(
            simulate_seccomp_filter(&x86_filter, &data_x86),
            SECCOMP_RET_KILL_PROCESS,
            "Negative syscall {nr} did not trigger KILL on x86_64"
        );
        let data_arm = SeccompData::new(AUDIT_ARCH_AARCH64, nr, [0; 6]);
        assert_eq!(
            simulate_seccomp_filter(&arm_filter, &data_arm),
            SECCOMP_RET_KILL_PROCESS,
            "Negative syscall {nr} did not trigger KILL on aarch64"
        );
    }

    // 2. Exhaustive 0..600 sweep on x86_64: ONLY allowed simple + mmap + mprotect may allow
    let mut allowed_x86_set = std::collections::HashSet::new();
    for &sc in X86_64_ALLOWED_SIMPLE_SYSCALLS {
        allowed_x86_set.insert(sc);
    }
    allowed_x86_set.insert(9); // mmap
    allowed_x86_set.insert(10); // mprotect

    for nr in 0..600 {
        if !allowed_x86_set.contains(&(nr as u32)) {
            let data = SeccompData::new(AUDIT_ARCH_X86_64, nr, [0; 6]);
            assert_eq!(
                simulate_seccomp_filter(&x86_filter, &data),
                SECCOMP_RET_KILL_PROCESS,
                "Syscall {nr} is NOT in allowlist but was NOT killed on x86_64!"
            );
        }
    }

    // 3. Exhaustive 0..600 sweep on aarch64: ONLY allowed simple + mmap + mprotect may allow
    let mut allowed_arm_set = std::collections::HashSet::new();
    for &sc in AARCH64_ALLOWED_SIMPLE_SYSCALLS {
        allowed_arm_set.insert(sc);
    }
    allowed_arm_set.insert(222); // mmap
    allowed_arm_set.insert(226); // mprotect

    for nr in 0..600 {
        if !allowed_arm_set.contains(&(nr as u32)) {
            let data = SeccompData::new(AUDIT_ARCH_AARCH64, nr, [0; 6]);
            assert_eq!(
                simulate_seccomp_filter(&arm_filter, &data),
                SECCOMP_RET_KILL_PROCESS,
                "Syscall {nr} is NOT in allowlist but was NOT killed on aarch64!"
            );
        }
    }
}

#[test]
fn adversarial_probe_exhaustive_wx_memory_protection() {
    let x86_filter = generate_seccomp_bpf_filter_x86_64();
    let arm_filter = generate_seccomp_bpf_filter_aarch64();

    // Probe all 256 byte combinations for prot (0x00 to 0xFF)
    for prot in 0u64..256 {
        let has_exec = (prot & (PROT_EXEC as u64)) != 0;
        let expected = if has_exec {
            SECCOMP_RET_KILL_PROCESS
        } else {
            SECCOMP_RET_ALLOW
        };

        // x86_64: mmap (9) and mprotect (10)
        for &sc in &[9, 10] {
            let mut args = [0u64; 6];
            args[2] = prot;
            let data = SeccompData::new(AUDIT_ARCH_X86_64, sc, args);
            assert_eq!(
                simulate_seccomp_filter(&x86_filter, &data),
                expected,
                "x86_64 syscall {sc} with prot {prot:#x} (has_exec={has_exec}) failed W^X check"
            );
        }

        // aarch64: mmap (222) and mprotect (226)
        for &sc in &[222, 226] {
            let mut args = [0u64; 6];
            args[2] = prot;
            let data = SeccompData::new(AUDIT_ARCH_AARCH64, sc, args);
            assert_eq!(
                simulate_seccomp_filter(&arm_filter, &data),
                expected,
                "aarch64 syscall {sc} with prot {prot:#x} (has_exec={has_exec}) failed W^X check"
            );
        }
    }
}

#[test]
fn adversarial_probe_landlock_abi_boundary_exactness() {
    // ABI 0 falls back to baseline v1
    assert_eq!(landlock_handled_access_fs(0), (1 << 13) - 1);

    // Exact bitmasks
    assert_eq!(landlock_handled_access_fs(1), 0x1FFF); // 13 bits
    assert_eq!(landlock_handled_access_fs(2), 0x3FFF); // 14 bits (REFER)
    assert_eq!(landlock_handled_access_fs(3), 0x7FFF); // 15 bits (TRUNCATE)
    assert_eq!(landlock_handled_access_fs(4), 0xFFFF); // 16 bits (IOCTL_DEV)

    // Future ABI >= 5 maintains ABI 4 flags until kernel bump
    assert_eq!(landlock_handled_access_fs(5), 0xFFFF);
    assert_eq!(landlock_handled_access_fs(100), 0xFFFF);
}

#[test]
fn adversarial_probe_falco_rule_attack_surface_coverage() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let falco_path = workspace_root
        .join("rules")
        .join("falco")
        .join("omniconnect-sentinel-cdr.yaml");

    let text = std::fs::read_to_string(&falco_path).expect("read falco yaml");

    // Must match both process binary names
    assert!(text.contains("sentinel_cdr_worker"));
    assert!(text.contains("sentinel-cdr-worker"));

    // Must detect unauthorized process spawning & execution
    for keyword in &["execve", "execveat", "fork", "vfork", "clone", "clone3"] {
        assert!(text.contains(keyword), "Falco missing keyword: {keyword}");
    }

    // Must detect network calls
    for keyword in &["socket", "connect", "bind", "listen", "accept"] {
        assert!(text.contains(keyword), "Falco missing keyword: {keyword}");
    }

    // Must detect memory W^X violations
    assert!(text.contains("mmap"));
    assert!(text.contains("mprotect"));
    assert!(text.contains("PROT_EXEC"));
    assert!(text.contains("rawarg.prot & 4 != 0"));

    // Must tag with priority CRITICAL
    assert!(text.contains("priority: CRITICAL"));
}
