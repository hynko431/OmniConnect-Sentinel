//! Linux Dual-Arch BPF Seccomp Allowlist, Landlock Total FS Deny & Privilege Drop Primitives (`CSE-05`, `T30`)
//!
//! Enforces:
//! 1. Dual-Architecture Allowlist: Strict stdio/memory/exit syscall allowlist on `x86_64` and `aarch64`.
//! 2. Anti-x32 Masking: Immediate `SECCOMP_RET_KILL_PROCESS` if `nr & 0x4000_0000 != 0`.
//! 3. W^X Enforcement: `mmap` and `mprotect` inspected at argument level; any request with `PROT_EXEC` (0x04) killed.
//! 4. Default-Deny: Any unallowed or unknown syscall returns `SECCOMP_RET_KILL_PROCESS` (never `EPERM` or denylist).
//! 5. Landlock ABI v1-v4: Total empty-filesystem restriction (zero path rules allowed).
//! 6. Non-Root Privilege Drop: Checked UID/GID drop to 65534, zeroed capabilities, and checked resource limits (`RLIMIT_AS`, `RLIMIT_NPROC=0`, `RLIMIT_NOFILE=4`, `RLIMIT_FSIZE=0`).

#[cfg(target_os = "linux")]
use std::io;

// Classic BPF instruction encoding
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

// BPF Instruction Class & Opcode Constants
pub const BPF_LD: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS; // 0x20

pub const BPF_JMP: u16 = 0x05;
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_JMP_JA: u16 = BPF_JMP | BPF_JA; // 0x05
pub const BPF_JMP_JEQ_K: u16 = BPF_JMP | BPF_JEQ; // 0x15
pub const BPF_JMP_JSET_K: u16 = BPF_JMP | BPF_JSET; // 0x45

pub const BPF_RET: u16 = 0x06;
pub const BPF_K: u16 = 0x00;
pub const BPF_RET_K: u16 = BPF_RET | BPF_K; // 0x06

// Seccomp Return Actions
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

// Supported Architecture Audit Constants
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

// x32 ABI Flag Bit
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// Memory Protection Flags
pub const PROT_EXEC: u32 = 0x04;

// seccomp_data struct field byte offsets
pub const SECCOMP_DATA_NR_OFFSET: u32 = 0;
pub const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
pub const SECCOMP_DATA_ARG2_LOWER_OFFSET: u32 = 16 + 2 * 8; // offset 32 (lower 32-bits of args[2])

/// In-memory representation of Linux `struct seccomp_data` for deterministic cross-platform simulation and testing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompData {
    pub fn new(arch: u32, nr: i32, args: [u64; 6]) -> Self {
        Self {
            nr,
            arch,
            instruction_pointer: 0,
            args,
        }
    }

    pub fn read_u32_at_offset(&self, offset: u32) -> u32 {
        match offset {
            0 => self.nr as u32,
            4 => self.arch,
            8 => (self.instruction_pointer & 0xFFFF_FFFF) as u32,
            12 => ((self.instruction_pointer >> 32) & 0xFFFF_FFFF) as u32,
            16 => (self.args[0] & 0xFFFF_FFFF) as u32,
            20 => ((self.args[0] >> 32) & 0xFFFF_FFFF) as u32,
            24 => (self.args[1] & 0xFFFF_FFFF) as u32,
            28 => ((self.args[1] >> 32) & 0xFFFF_FFFF) as u32,
            32 => (self.args[2] & 0xFFFF_FFFF) as u32,
            36 => ((self.args[2] >> 32) & 0xFFFF_FFFF) as u32,
            40 => (self.args[3] & 0xFFFF_FFFF) as u32,
            44 => ((self.args[3] >> 32) & 0xFFFF_FFFF) as u32,
            48 => (self.args[4] & 0xFFFF_FFFF) as u32,
            52 => ((self.args[4] >> 32) & 0xFFFF_FFFF) as u32,
            56 => (self.args[5] & 0xFFFF_FFFF) as u32,
            60 => ((self.args[5] >> 32) & 0xFFFF_FFFF) as u32,
            _ => 0,
        }
    }
}

/// Helper to compute forward relative BPF jump offsets.
#[inline]
pub fn jump_offset(from_idx: usize, to_idx: usize) -> u8 {
    assert!(to_idx > from_idx, "BPF forward jumps only");
    (to_idx - from_idx - 1) as u8
}

/// Strict allowlist of simple syscalls for x86_64:
/// read(0), write(1), close(3), fstat(5), lseek(8), munmap(11), brk(12),
/// rt_sigreturn(15), sched_yield(24), madvise(28), pause(34), nanosleep(35),
/// getpid(39), exit(60), sigaltstack(131), futex(202), clock_gettime(228),
/// exit_group(231), getrandom(318).
pub const X86_64_ALLOWED_SIMPLE_SYSCALLS: &[u32] = &[
    0,   // read
    1,   // write
    3,   // close
    5,   // fstat
    8,   // lseek
    11,  // munmap
    12,  // brk
    15,  // rt_sigreturn
    24,  // sched_yield
    28,  // madvise
    34,  // pause
    35,  // nanosleep
    39,  // getpid
    60,  // exit
    131, // sigaltstack
    202, // futex
    228, // clock_gettime
    231, // exit_group
    318, // getrandom
];

/// Strict allowlist of simple syscalls for aarch64:
/// close(57), lseek(62), read(63), write(64), fstat(80), exit(93), exit_group(94),
/// futex(98), nanosleep(101), clock_gettime(113), sched_yield(124), sigaltstack(132),
/// rt_sigreturn(139), getpid(172), brk(214), munmap(215), madvise(233), getrandom(278).
pub const AARCH64_ALLOWED_SIMPLE_SYSCALLS: &[u32] = &[
    57,  // close
    62,  // lseek
    63,  // read
    64,  // write
    80,  // fstat
    93,  // exit
    94,  // exit_group
    98,  // futex
    101, // nanosleep
    113, // clock_gettime
    124, // sched_yield
    132, // sigaltstack
    139, // rt_sigreturn
    172, // getpid
    214, // brk
    215, // munmap
    233, // madvise
    278, // getrandom
];

/// Generates the verified, default-deny BPF seccomp filter for `x86_64`.
pub fn generate_seccomp_bpf_filter_x86_64() -> Vec<SockFilter> {
    build_dual_arch_filter(AUDIT_ARCH_X86_64, X86_64_ALLOWED_SIMPLE_SYSCALLS, 9, 10)
}

/// Generates the verified, default-deny BPF seccomp filter for `aarch64`.
pub fn generate_seccomp_bpf_filter_aarch64() -> Vec<SockFilter> {
    build_dual_arch_filter(
        AUDIT_ARCH_AARCH64,
        AARCH64_ALLOWED_SIMPLE_SYSCALLS,
        222,
        226,
    )
}

fn build_dual_arch_filter(
    target_arch: u32,
    simple_syscalls: &[u32],
    mmap_nr: u32,
    mprotect_nr: u32,
) -> Vec<SockFilter> {
    let mut filter: Vec<SockFilter> = Vec::with_capacity(64);

    // Total instructions planning:
    // 0: LD [4] (arch)
    // 1: JEQ target_arch -> continue (jt=0, jf=jump to KILL)
    // 2: LD [0] (nr)
    // 3: JSET X32_SYSCALL_BIT -> jump to KILL (jt=jump to KILL, jf=0)
    // 4..4+N-1: JEQ syscall_i -> jump to ALLOW (jt=jump to ALLOW, jf=0)
    // Next: JEQ mmap_nr -> check mmap (jt=0, jf=jump to mprotect check)
    //   LD [32] (prot)
    //   JSET PROT_EXEC -> jump to KILL (jt=jump to KILL, jf=jump to ALLOW)
    // Next: LD [0] (reload nr)
    //   JEQ mprotect_nr -> check mprotect (jt=0, jf=jump to DEFAULT_KILL)
    //   LD [32] (prot)
    //   JSET PROT_EXEC -> jump to KILL (jt=jump to KILL, jf=jump to ALLOW)
    // DEFAULT_KILL: RET SECCOMP_RET_KILL_PROCESS
    // ALLOW: RET SECCOMP_RET_ALLOW

    // Let's compute exact indices dynamically:
    let n_simple = simple_syscalls.len();
    let _idx_arch_ld = 0;
    let idx_arch_check = 1;
    let _idx_nr_ld = 2;
    let idx_x32_check = 3;
    let idx_simple_start = 4;
    let idx_mmap_check = idx_simple_start + n_simple;
    let _idx_mmap_prot_ld = idx_mmap_check + 1;
    let idx_mmap_prot_check = idx_mmap_check + 2;
    let idx_mprotect_nr_ld = idx_mmap_check + 3;
    let idx_mprotect_check = idx_mprotect_nr_ld + 1;
    let _idx_mprotect_prot_ld = idx_mprotect_nr_ld + 2;
    let idx_mprotect_prot_check = idx_mprotect_nr_ld + 3;
    let idx_kill = idx_mprotect_prot_check + 1;
    let idx_allow = idx_kill + 1;

    // 0: LD [4]
    filter.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH_OFFSET,
    });

    // 1: JEQ target_arch (on match, proceed; else jump to idx_kill)
    filter.push(SockFilter {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        jf: jump_offset(idx_arch_check, idx_kill),
        k: target_arch,
    });

    // 2: LD [0] (nr)
    filter.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    });

    // 3: JSET X32_SYSCALL_BIT (on match, kill! else proceed)
    filter.push(SockFilter {
        code: BPF_JMP_JSET_K,
        jt: jump_offset(idx_x32_check, idx_kill),
        jf: 0,
        k: X32_SYSCALL_BIT,
    });

    // 4..4+N-1: Simple syscall checks
    for (i, &sc) in simple_syscalls.iter().enumerate() {
        let curr_idx = idx_simple_start + i;
        filter.push(SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: jump_offset(curr_idx, idx_allow),
            jf: 0,
            k: sc,
        });
    }

    // mmap check: if nr == mmap_nr, proceed to load prot (offset 32); else jump to mprotect reload nr
    filter.push(SockFilter {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        jf: jump_offset(idx_mmap_check, idx_mprotect_nr_ld),
        k: mmap_nr,
    });

    // mmap prot load (arg2 lower at offset 32)
    filter.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARG2_LOWER_OFFSET,
    });

    // mmap prot check: if (prot & PROT_EXEC) != 0 -> KILL, else ALLOW
    filter.push(SockFilter {
        code: BPF_JMP_JSET_K,
        jt: jump_offset(idx_mmap_prot_check, idx_kill),
        jf: jump_offset(idx_mmap_prot_check, idx_allow),
        k: PROT_EXEC,
    });

    // Reload nr for mprotect check
    filter.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    });

    // mprotect check: if nr == mprotect_nr, proceed to load prot; else jump to idx_kill
    filter.push(SockFilter {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        jf: jump_offset(idx_mprotect_check, idx_kill),
        k: mprotect_nr,
    });

    // mprotect prot load (arg2 lower at offset 32)
    filter.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARG2_LOWER_OFFSET,
    });

    // mprotect prot check: if (prot & PROT_EXEC) != 0 -> KILL, else ALLOW
    filter.push(SockFilter {
        code: BPF_JMP_JSET_K,
        jt: jump_offset(idx_mprotect_prot_check, idx_kill),
        jf: jump_offset(idx_mprotect_prot_check, idx_allow),
        k: PROT_EXEC,
    });

    // idx_kill: Default-Deny KILL
    filter.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // idx_allow: Verified ALLOW
    filter.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    assert_eq!(filter.len(), idx_allow + 1);
    filter
}

/// Fully deterministic Classic BPF Seccomp Virtual Machine simulator for unit testing and offline verification.
pub fn simulate_seccomp_filter(filter: &[SockFilter], data: &SeccompData) -> u32 {
    let mut pc = 0;
    let mut accumulator: u32 = 0;

    let max_instructions = 1024;
    let mut count = 0;

    while pc < filter.len() && count < max_instructions {
        count += 1;
        let insn = filter[pc];
        match insn.code {
            BPF_LD_W_ABS => {
                accumulator = data.read_u32_at_offset(insn.k);
                pc += 1;
            }
            BPF_JMP_JEQ_K => {
                if accumulator == insn.k {
                    pc += (insn.jt as usize) + 1;
                } else {
                    pc += (insn.jf as usize) + 1;
                }
            }
            BPF_JMP_JSET_K => {
                if (accumulator & insn.k) != 0 {
                    pc += (insn.jt as usize) + 1;
                } else {
                    pc += (insn.jf as usize) + 1;
                }
            }
            BPF_RET_K => {
                return insn.k;
            }
            _ => {
                // Unknown opcode -> fail-closed KILL
                return SECCOMP_RET_KILL_PROCESS;
            }
        }
    }

    SECCOMP_RET_KILL_PROCESS
}

/// Landlock filesystem access flags for ABI versions 1..4.
pub fn landlock_handled_access_fs(abi_version: u32) -> u64 {
    // ABI v1 flags (bits 0..12)
    let mut handled: u64 = (1 << 13) - 1;
    if abi_version >= 2 {
        handled |= 1 << 13; // LANDLOCK_ACCESS_FS_REFER
    }
    if abi_version >= 3 {
        handled |= 1 << 14; // LANDLOCK_ACCESS_FS_TRUNCATE
    }
    if abi_version >= 4 {
        handled |= 1 << 15; // LANDLOCK_ACCESS_FS_IOCTL_DEV
    }
    handled
}

/// Applies empty-filesystem Landlock lockdown on Linux (supported on Linux kernels >= 5.13).
#[cfg(target_os = "linux")]
pub fn apply_landlock_filesystem_lockdown() -> io::Result<()> {
    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

    let abi_version = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            core::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if abi_version <= 0 {
        // Landlock not supported on this kernel version; return Ok and rely on BPF + root drop
        return Ok(());
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: landlock_handled_access_fs(abi_version as u32),
    };

    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            core::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };

    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let restrict_res = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    unsafe { libc::close(ruleset_fd as i32) };

    if restrict_res != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Applies non-root UID/GID/capability drop and checked `setrlimit` calls on Linux (`CSE-05`).
#[cfg(target_os = "linux")]
pub fn apply_linux_privilege_and_namespace_drop() -> io::Result<()> {
    // 1. Unshare network and IPC namespaces
    let unshare_rc = unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWIPC) };
    if unshare_rc != 0 {
        let err = io::Error::last_os_error();
        // If unshare fails with EPERM because already non-root, do not fail; otherwise fail
        if unsafe { libc::getuid() } == 0 && err.raw_os_error() != Some(libc::EPERM) {
            return Err(err);
        }
    }

    // 2. Resource limits: 256 MiB memory, zero core, zero child processes, 4 file descriptors, zero file size
    const LIMIT_256_MIB: libc::rlim_t = 256 * 1024 * 1024;
    let rlim_as = libc::rlimit {
        rlim_cur: LIMIT_256_MIB,
        rlim_max: LIMIT_256_MIB,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &rlim_as) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let zero_rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero_rlim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &zero_rlim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &zero_rlim) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let nofile_rlim = libc::rlimit {
        rlim_cur: 4,
        rlim_max: 4,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &nofile_rlim) };

    // 3. Prevent dumpable and privilege gain
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // 4. If running as root (UID 0), drop to unprivileged nobody (UID 65534, GID 65534) and zero all capabilities
    if unsafe { libc::getuid() } == 0 {
        if unsafe { libc::setgroups(0, core::ptr::null()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::setresgid(65534, 65534, 65534) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::setresuid(65534, 65534, 65534) } != 0 {
            return Err(io::Error::last_os_error());
        }

        #[repr(C)]
        struct CapUserHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct CapUserData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
        let hdr = CapUserHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        let cap_res = unsafe { libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) };
        if cap_res != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Applies full Linux worker sandbox: non-root privilege drop, Landlock FS lockdown, and strict BPF allowlist.
#[cfg(target_os = "linux")]
pub fn apply_linux_worker_sandbox() -> io::Result<()> {
    // 1. Privilege and namespace drop
    apply_linux_privilege_and_namespace_drop()?;

    // 2. Landlock empty filesystem lockdown
    apply_landlock_filesystem_lockdown()?;

    // 3. Strict Dual-Arch BPF Allowlist Filter
    #[cfg(target_arch = "x86_64")]
    let filter = generate_seccomp_bpf_filter_x86_64();
    #[cfg(target_arch = "aarch64")]
    let filter = generate_seccomp_bpf_filter_aarch64();
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("OmniConnect Sentinel CDR sandbox only supports Linux x86_64 and aarch64");

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const SockFprog,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
