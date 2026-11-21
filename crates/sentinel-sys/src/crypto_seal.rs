use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
#[cfg(windows)]
use tracing::info;
use tracing::warn;

use crate::mem_guard::zeroize_slice;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyProtectionPosture {
    /// Hardware-backed TPM 2.0 (Windows Platform Crypto Provider non-exportable RSA-2048 OAEP key wrapping,
    /// or Linux TPM 2.0 resource manager `/dev/tpmrm0` when feature `linux-tpm2` is active)
    Tpm2Assisted,
    /// Windows DPAPI CRYPTPROTECT_LOCAL_MACHINE fallback (`POSTURE_REDUCED_NO_TPM`)
    DpapiLocalMachine,
    /// Linux kernel keyring (`SYS_keyctl(KEYCTL_SEARCH)` / `SYS_add_key`, non-swappable kernel memory — no disk `master.seed`, `POSTURE_REDUCED_NO_TPM`)
    LinuxKernelKeyring,
    /// Unix root-restricted `0400` file-backed wrapping fallback (`master.seed`, `POSTURE_REDUCED_NO_TPM`; refused in strict kiosk mode)
    UnixLocalKeyring,
}

impl KeyProtectionPosture {
    /// Returns `true` when key custody relies on a local plaintext seed file on disk (`master.seed`),
    /// which strict OT kiosk mode refuses fail-closed (`CSE-28`).
    pub fn is_file_backed_fallback(self) -> bool {
        matches!(self, Self::UnixLocalKeyring)
    }

    /// Returns `true` when key custody is anchored directly in hardware TPM 2.0.
    pub fn is_hardware_backed(self) -> bool {
        matches!(self, Self::Tpm2Assisted)
    }

    /// Returns `true` when key custody uses hardware TPM 2.0 or OS kernel-managed memory/DPAPI
    /// rather than a local disk seed file (`CSE-28`).
    pub fn is_strict_kiosk_acceptable(self) -> bool {
        matches!(
            self,
            Self::Tpm2Assisted | Self::DpapiLocalMachine | Self::LinuxKernelKeyring
        )
    }
}

/// Allowed TPM 2.0 PCP RSA-OAEP hash algorithms (`CSE-28`): SHA-256 exclusively (SHA-1 fallback retired).
pub const TPM_OAEP_ALLOWED_ALGORITHMS: &[(&str, bool)] = &[("SHA256", true), ("SHA256", false)];

/// Evaluates whether a `KeyProtectionPosture` is permissible in strict OT kiosk mode (`CSE-28`).
/// File-backed `UnixLocalKeyring` (`master.seed`) is refused fail-closed with `POSTURE_REDUCED_NO_TPM`.
pub fn evaluate_strict_kiosk_key_posture(posture: KeyProtectionPosture) -> Result<(), String> {
    if posture.is_file_backed_fallback() {
        return Err(
            "POSTURE_REDUCED_NO_TPM: Refusing strict kiosk session with file-backed key fallback (UnixLocalKeyring / master.seed); require hardware TPM 2.0 or Linux kernel keyring"
                .to_string(),
        );
    }
    Ok(())
}

/// Deterministic Linux key-sealing backend priority selector (`CSE-28`):
/// 1. Hardware TPM 2.0 (`/dev/tpmrm0`, feature-gated `linux-tpm2`) -> `Tpm2Assisted` (no reduced posture)
/// 2. Linux kernel keyring (`SYS_keyctl(KEYCTL_SEARCH)` / `SYS_add_key`) -> `LinuxKernelKeyring` (`POSTURE_REDUCED_NO_TPM`)
/// 3. File-backed `master.seed` fallback -> `UnixLocalKeyring` (`POSTURE_REDUCED_NO_TPM`, refused in strict kiosk mode)
pub fn resolve_linux_key_sealing_backend(
    tpm2_available: bool,
    kernel_keyring_available: bool,
) -> (KeyProtectionPosture, Option<&'static str>) {
    if tpm2_available {
        (KeyProtectionPosture::Tpm2Assisted, None)
    } else if kernel_keyring_available {
        (
            KeyProtectionPosture::LinuxKernelKeyring,
            Some("POSTURE_REDUCED_NO_TPM"),
        )
    } else {
        (
            KeyProtectionPosture::UnixLocalKeyring,
            Some("POSTURE_REDUCED_NO_TPM"),
        )
    }
}

/// Probes whether a Linux TPM 2.0 in-kernel resource manager character device (`/dev/tpmrm0`) exists.
pub fn is_linux_tpm2_device_present() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::symlink_metadata("/dev/tpmrm0")
            .map(|m| !m.file_type().is_symlink() && m.file_type().is_char_device())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// RFC 5869 audited `HKDF-SHA256` key derivation returning a 32-byte volatile-zeroized key (`CSE-28`).
pub fn hkdf_sha256_derive_32(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> io::Result<crate::mem_guard::ZeroizingBytes<32>> {
    use hkdf::Hkdf;

    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| io::Error::other(format!("HKDF-SHA256 expand failed: {e}")))?;
    let guarded = crate::mem_guard::ZeroizingBytes::new(okm);
    zeroize_slice(&mut okm);
    Ok(guarded)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKeyBlob {
    pub posture: KeyProtectionPosture,
    pub kek_id: String,
    pub sealed_bytes: Vec<u8>,
    #[serde(default)]
    pub reduced_posture_event: Option<String>,
}

/// Offline SOC Recovery Escrow Blob (`Master Plan v2 §1.1 #2`, `ADR-005`).
/// Contains ONLY the RSA-3072-OAEP-SHA256 (or stronger) ciphertext of the 32-byte Master KEK encrypted
/// under the offline SOC public key. No private key material is stored on the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocEscrowBlob {
    pub version: u16,
    pub algorithm: String,
    pub kek_id: String,
    pub soc_key_fingerprint: String,
    pub rsa_oaep_ciphertext: Vec<u8>,
}

/// Wire magic for Hybrid Post-Quantum SOC Escrow Envelope `v3` (`OCESCROW3`, `Sub-Phase 2.2`, `CSE-14`).
pub const OCESCROW3_MAGIC: &[u8; 9] = b"OCESCROW3";
/// NIST FIPS 203 `ML-KEM-768` Encapsulation Key byte length (`1184` bytes).
pub const MLKEM768_EK_LEN: usize = 1184;
/// NIST FIPS 203 `ML-KEM-768` Decapsulation Key byte length (`2400` bytes).
pub const MLKEM768_DK_LEN: usize = 2400;
/// NIST FIPS 203 `ML-KEM-768` Ciphertext byte length (`1088` bytes).
pub const MLKEM768_CT_LEN: usize = 1088;

/// Offline SOC Hybrid Post-Quantum Public Key Bundle (`RSA-3072-OAEP` + `FIPS 203 ML-KEM-768`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridSocPublicKeyBundle {
    pub version: u16,
    pub rsa_public_blob: Vec<u8>,
    pub mlkem768_encapsulation_key: Vec<u8>,
}

/// Offline Air-Gapped SOC Hybrid Post-Quantum Private Key Bundle (volatile-zeroized on `Drop`).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridSocPrivateKeyBundle {
    pub rsa_private_blob: Vec<u8>,
    pub mlkem768_decapsulation_key: Vec<u8>,
}

impl Drop for HybridSocPrivateKeyBundle {
    fn drop(&mut self) {
        zeroize_slice(&mut self.rsa_private_blob);
        zeroize_slice(&mut self.mlkem768_decapsulation_key);
    }
}

/// Hybrid Post-Quantum SOC Recovery Escrow Envelope `v3` (`OCESCROW3`, `Master Plan v2 Sub-Phase 2.2`, `CSE-14`).
///
/// Combines a classical `RSA-3072-OAEP-SHA256` shared secret (`ss_rsa`, 32 bytes) with a NIST FIPS 203
/// `ML-KEM-768` shared secret (`ss_mlkem768`, 32 bytes) via `HKDF-SHA256` bound to both ciphertexts,
/// wrapping the 32-byte Vault Master KEK under `AES-256-GCM`. Security holds if EITHER `RSA-OAEP` OR
/// `ML-KEM-768` remains unbroken ("harvest-now, decrypt-later" protection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridSocEscrowBlobV3 {
    pub magic: String,
    pub version: u16,
    pub algorithm: String,
    pub kek_id: String,
    pub soc_rsa_fingerprint: String,
    pub soc_mlkem768_fingerprint: String,
    pub hkdf_salt: Vec<u8>,
    pub aes_gcm_nonce: Vec<u8>,
    pub rsa_oaep_ciphertext: Vec<u8>,
    pub mlkem768_ciphertext: Vec<u8>,
    pub wrapped_kek_ciphertext: Vec<u8>,
    pub ocescrow3_wire_bytes: Vec<u8>,
}

/// Sealed Asymmetric ECDSA P-256 Keypair Blob for Tamper-Evident Audit Ledger & Policy Signing (`Phase 4.2`, `Phase 4.4`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEcdsaKeyPair {
    pub posture: KeyProtectionPosture,
    pub key_id: String,
    /// Public key in CNG `BCRYPT_ECCKEY_BLOB` (`ECCPUBLICBLOB`, 72 bytes: magic `ECS1` + len `32` + X[32] + Y[32])
    pub public_key_blob: Vec<u8>,
    /// When `posture == Tpm2Assisted`, empty (private key resides inside TPM 2.0 PCP).
    /// When `posture != Tpm2Assisted`, contains the `SealedKeyBlob` wrapping the 104-byte `ECCPRIVATEBLOB`.
    pub sealed_private_key: Option<SealedKeyBlob>,
    #[serde(default)]
    pub reduced_posture_event: Option<String>,
}

#[cfg(windows)]
use windows_sys::Win32::Foundation::STATUS_SUCCESS;

#[cfg(windows)]
#[repr(C)]
struct CryptoApiBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[cfg(windows)]
#[repr(C)]
struct BcryptOaepPaddingInfo {
    psz_alg_id: *const u16,
    pb_label: *const u8,
    cb_label: u32,
}

#[cfg(windows)]
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
#[cfg(windows)]
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

#[cfg(windows)]
const NCRYPT_PAD_OAEP_FLAG: u32 = 0x0000_0004;
#[cfg(windows)]
const NCRYPT_MACHINE_KEY_FLAG: u32 = 0x0000_0020;
#[cfg(windows)]
const NCRYPT_SILENT_FLAG: u32 = 0x0000_0040;
#[cfg(windows)]
const BCRYPT_PAD_OAEP: u32 = 0x0000_0004;

#[cfg(windows)]
#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        pDataIn: *const CryptoApiBlob,
        szDataDescr: *const u16,
        pOptionalEntropy: *const CryptoApiBlob,
        pvReserved: *mut core::ffi::c_void,
        pPromptStruct: *const core::ffi::c_void,
        dwFlags: u32,
        pDataOut: *mut CryptoApiBlob,
    ) -> i32;

    fn CryptUnprotectData(
        pDataIn: *const CryptoApiBlob,
        ppszDataDescr: *mut *mut u16,
        pOptionalEntropy: *const CryptoApiBlob,
        pvReserved: *mut core::ffi::c_void,
        pPromptStruct: *const core::ffi::c_void,
        dwFlags: u32,
        pDataOut: *mut CryptoApiBlob,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

#[cfg(windows)]
#[link(name = "ncrypt")]
extern "system" {
    fn NCryptOpenStorageProvider(
        phProvider: *mut usize,
        pszProviderName: *const u16,
        dwFlags: u32,
    ) -> i32;
    fn NCryptOpenKey(
        hProvider: usize,
        phKey: *mut usize,
        pszKeyName: *const u16,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptCreatePersistedKey(
        hProvider: usize,
        phKey: *mut usize,
        pszAlgId: *const u16,
        pszKeyName: *const u16,
        dwLegacyKeySpec: u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptSetProperty(
        hObject: usize,
        pszProperty: *const u16,
        pbInput: *const u8,
        cbInput: u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptFinalizeKey(hKey: usize, dwFlags: u32) -> i32;
    fn NCryptEncrypt(
        hKey: usize,
        pbInput: *const u8,
        cbInput: u32,
        pPaddingInfo: *const core::ffi::c_void,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptDecrypt(
        hKey: usize,
        pbInput: *const u8,
        cbInput: u32,
        pPaddingInfo: *const core::ffi::c_void,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptExportKey(
        hKey: usize,
        hExportKey: usize,
        pszBlobType: *const u16,
        pParameterList: *const core::ffi::c_void,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptSignHash(
        hKey: usize,
        pPaddingInfo: *const core::ffi::c_void,
        pbHashValue: *const u8,
        cbHashValue: u32,
        pbSignature: *mut u8,
        cbSignature: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn NCryptFreeObject(hObject: usize) -> i32;
}

#[cfg(windows)]
#[link(name = "bcrypt")]
extern "system" {
    fn BCryptOpenAlgorithmProvider(
        phAlgorithm: *mut usize,
        pszAlgId: *const u16,
        pszImplementation: *const u16,
        dwFlags: u32,
    ) -> i32;
    fn BCryptCloseAlgorithmProvider(hAlgorithm: usize, dwFlags: u32) -> i32;
    fn BCryptGenerateKeyPair(
        hAlgorithm: usize,
        phKey: *mut usize,
        dwLength: u32,
        dwFlags: u32,
    ) -> i32;
    fn BCryptFinalizeKeyPair(hKey: usize, dwFlags: u32) -> i32;
    fn BCryptExportKey(
        hKey: usize,
        hExportKey: usize,
        pszBlobType: *const u16,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn BCryptImportKeyPair(
        hAlgorithm: usize,
        hImportKey: usize,
        pszBlobType: *const u16,
        phKey: *mut usize,
        pbInput: *const u8,
        cbInput: u32,
        dwFlags: u32,
    ) -> i32;
    fn BCryptEncrypt(
        hKey: usize,
        pbInput: *const u8,
        cbInput: u32,
        pPaddingInfo: *const core::ffi::c_void,
        pbIV: *mut u8,
        cbIV: u32,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn BCryptDecrypt(
        hKey: usize,
        pbInput: *const u8,
        cbInput: u32,
        pPaddingInfo: *const core::ffi::c_void,
        pbIV: *mut u8,
        cbIV: u32,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn BCryptSignHash(
        hKey: usize,
        pPaddingInfo: *const core::ffi::c_void,
        pbInput: *const u8,
        cbInput: u32,
        pbOutput: *mut u8,
        cbOutput: u32,
        pcbResult: *mut u32,
        dwFlags: u32,
    ) -> i32;
    fn BCryptVerifySignature(
        hKey: usize,
        pPaddingInfo: *const core::ffi::c_void,
        pbHash: *const u8,
        cbHash: u32,
        pbSignature: *const u8,
        cbSignature: u32,
        dwFlags: u32,
    ) -> i32;
    fn BCryptDestroyKey(hKey: usize) -> i32;
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

/// Checks if the Microsoft Platform Crypto Provider (TPM 2.0 KSP) is available on this endpoint.
#[cfg(windows)]
static TPM_PCP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn is_tpm2_pcp_available() -> bool {
    #[cfg(windows)]
    {
        let _tpm_guard = TPM_PCP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let provider_name = to_wide("Microsoft Platform Crypto Provider");
        let mut handle: usize = 0;
        let status = unsafe { NCryptOpenStorageProvider(&mut handle, provider_name.as_ptr(), 0) };
        if status == STATUS_SUCCESS && handle != 0 {
            unsafe {
                let _ = NCryptFreeObject(handle);
            }
            return true;
        }
        false
    }
    #[cfg(not(windows))]
    {
        Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
    }
}

/// Wraps `raw_key` using a non-exportable 2048-bit RSA key inside the Windows TPM 2.0
/// Platform Crypto Provider (`MS_PLATFORM_CRYPTO_PROVIDER`) via `NCryptCreatePersistedKey` /
/// `NCryptOpenKey` and `NCryptEncrypt(NCRYPT_PAD_OAEP_FLAG)` (`Master Plan v2 §1.1 #1`).
#[cfg(windows)]
fn tpm_pcp_rsa_seal(raw_key: &[u8], entropy_tag: &[u8], kek_id: &str) -> io::Result<Vec<u8>> {
    let _tpm_guard = TPM_PCP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let provider_name = to_wide("Microsoft Platform Crypto Provider");
    let mut h_prov: usize = 0;
    let status = unsafe { NCryptOpenStorageProvider(&mut h_prov, provider_name.as_ptr(), 0) };
    if status != 0 || h_prov == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER) failed: 0x{:08X}",
                status as u32
            ),
        ));
    }

    let key_name = to_wide(&format!("OmniConnectSentinelVaultRsa2048_{kek_id}"));
    let alg_rsa = to_wide("RSA");
    let prop_len = to_wide("Length");
    let mut h_key: usize = 0;

    // Try opening existing non-exportable TPM RSA key (machine scope first, then user scope)
    let mut open_status = unsafe {
        NCryptOpenKey(
            h_prov,
            &mut h_key,
            key_name.as_ptr(),
            0,
            NCRYPT_MACHINE_KEY_FLAG,
        )
    };
    if open_status != 0 || h_key == 0 {
        open_status = unsafe { NCryptOpenKey(h_prov, &mut h_key, key_name.as_ptr(), 0, 0) };
    }

    if open_status != 0 || h_key == 0 {
        // Strictly require NCRYPT_MACHINE_KEY_FLAG so persisted TPM keys are machine-scoped
        // (never bound to an ephemeral user/container SID).
        let create_status = unsafe {
            NCryptCreatePersistedKey(
                h_prov,
                &mut h_key,
                alg_rsa.as_ptr(),
                key_name.as_ptr(),
                0,
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        if create_status != 0 || h_key == 0 {
            unsafe {
                let _ = NCryptFreeObject(h_prov);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "NCryptCreatePersistedKey(RSA) on TPM PCP failed: 0x{:08X}",
                    create_status as u32
                ),
            ));
        }

        let bits: u32 = 2048;
        let _ = unsafe {
            NCryptSetProperty(
                h_key,
                prop_len.as_ptr(),
                &bits as *const u32 as *const u8,
                core::mem::size_of::<u32>() as u32,
                0,
            )
        };
        let prop_usage = to_wide("Key Usage");
        let usage_flags: u32 = 0x0000_0001 | 0x0000_0002; // NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG
        let _ = unsafe {
            NCryptSetProperty(
                h_key,
                prop_usage.as_ptr(),
                &usage_flags as *const u32 as *const u8,
                core::mem::size_of::<u32>() as u32,
                0,
            )
        };

        let fin_status = unsafe { NCryptFinalizeKey(h_key, NCRYPT_SILENT_FLAG) };
        if fin_status != 0 {
            unsafe {
                let _ = NCryptFreeObject(h_key);
                let _ = NCryptFreeObject(h_prov);
            }
            return Err(io::Error::other(format!(
                "NCryptFinalizeKey(RSA) on TPM PCP failed: 0x{:08X}",
                fin_status as u32
            )));
        }
    }

    // Encrypt `raw_key` with RSA-OAEP-SHA256 exclusively (SHA-1 fallback retired per `CSE-28`)
    // and verify round-trip hardware TPM decryption before committing
    for &(alg_name, use_label) in TPM_OAEP_ALLOWED_ALGORITHMS {
        let wide_alg = to_wide(alg_name);
        let label_slice = if use_label { entropy_tag } else { &[][..] };
        let padding = BcryptOaepPaddingInfo {
            psz_alg_id: wide_alg.as_ptr(),
            pb_label: if label_slice.is_empty() {
                core::ptr::null()
            } else {
                label_slice.as_ptr()
            },
            cb_label: label_slice.len() as u32,
        };
        let mut cb_result: u32 = 0;
        let q_status = unsafe {
            NCryptEncrypt(
                h_key,
                raw_key.as_ptr(),
                raw_key.len() as u32,
                &padding as *const _ as *const core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                &mut cb_result,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if q_status == 0 && cb_result > 0 {
            let mut out = vec![0u8; cb_result as usize];
            let enc_status = unsafe {
                NCryptEncrypt(
                    h_key,
                    raw_key.as_ptr(),
                    raw_key.len() as u32,
                    &padding as *const _ as *const core::ffi::c_void,
                    out.as_mut_ptr(),
                    cb_result,
                    &mut cb_result,
                    NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
                )
            };
            if enc_status == 0 {
                out.truncate(cb_result as usize);
                // Verify that the TPM 2.0 PCP hardware key can decrypt this OAEP ciphertext
                let mut verify_buf = vec![0u8; out.len().max(256)];
                let mut cb_dec: u32 = 0;
                let dec_status = unsafe {
                    NCryptDecrypt(
                        h_key,
                        out.as_ptr(),
                        out.len() as u32,
                        &padding as *const _ as *const core::ffi::c_void,
                        verify_buf.as_mut_ptr(),
                        verify_buf.len() as u32,
                        &mut cb_dec,
                        NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
                    )
                };
                let dec_ok = dec_status == 0
                    && (cb_dec as usize) == raw_key.len()
                    && &verify_buf[..cb_dec as usize] == raw_key;
                zeroize_slice(&mut verify_buf);
                if dec_ok {
                    unsafe {
                        let _ = NCryptFreeObject(h_key);
                        let _ = NCryptFreeObject(h_prov);
                    }
                    return Ok(out);
                }
            }
        }
    }

    unsafe {
        let _ = NCryptFreeObject(h_key);
        let _ = NCryptFreeObject(h_prov);
    }
    Err(io::Error::other(
        "NCryptEncrypt/NCryptDecrypt(NCRYPT_PAD_OAEP_FLAG) roundtrip failed on TPM PCP key",
    ))
}

/// Unwraps a TPM 2.0 PCP RSA-OAEP sealed key blob via `NCryptDecrypt(NCRYPT_PAD_OAEP_FLAG)`.
#[cfg(windows)]
fn tpm_pcp_rsa_unseal(
    sealed_bytes: &[u8],
    entropy_tag: &[u8],
    kek_id: &str,
) -> io::Result<Vec<u8>> {
    let _tpm_guard = TPM_PCP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let provider_name = to_wide("Microsoft Platform Crypto Provider");
    let mut h_prov: usize = 0;
    let status = unsafe { NCryptOpenStorageProvider(&mut h_prov, provider_name.as_ptr(), 0) };
    if status != 0 || h_prov == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER) failed: 0x{:08X}",
                status as u32
            ),
        ));
    }

    let key_name = to_wide(&format!("OmniConnectSentinelVaultRsa2048_{kek_id}"));
    let mut h_key: usize = 0;
    let mut open_status = unsafe {
        NCryptOpenKey(
            h_prov,
            &mut h_key,
            key_name.as_ptr(),
            0,
            NCRYPT_MACHINE_KEY_FLAG,
        )
    };
    if open_status != 0 || h_key == 0 {
        open_status = unsafe { NCryptOpenKey(h_prov, &mut h_key, key_name.as_ptr(), 0, 0) };
    }
    if open_status != 0 || h_key == 0 {
        unsafe {
            let _ = NCryptFreeObject(h_prov);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "NCryptOpenKey failed for TPM PCP key '{}': 0x{:08X}",
                kek_id, open_status as u32
            ),
        ));
    }

    // Unwrap strictly via RSA-OAEP-SHA256 (SHA-1 OAEP fallback retired per `CSE-28`)
    for &(alg_name, use_label) in TPM_OAEP_ALLOWED_ALGORITHMS {
        let wide_alg = to_wide(alg_name);
        let label_slice = if use_label { entropy_tag } else { &[][..] };
        let padding = BcryptOaepPaddingInfo {
            psz_alg_id: wide_alg.as_ptr(),
            pb_label: if label_slice.is_empty() {
                core::ptr::null()
            } else {
                label_slice.as_ptr()
            },
            cb_label: label_slice.len() as u32,
        };
        let mut out = vec![0u8; sealed_bytes.len().max(256)];
        let mut cb_result: u32 = 0;
        let dec_status = unsafe {
            NCryptDecrypt(
                h_key,
                sealed_bytes.as_ptr(),
                sealed_bytes.len() as u32,
                &padding as *const _ as *const core::ffi::c_void,
                out.as_mut_ptr(),
                out.len() as u32,
                &mut cb_result,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if dec_status == 0 && cb_result > 0 && (cb_result as usize) <= out.len() {
            out.truncate(cb_result as usize);
            unsafe {
                let _ = NCryptFreeObject(h_key);
                let _ = NCryptFreeObject(h_prov);
            }
            return Ok(out);
        }
    }

    unsafe {
        let _ = NCryptFreeObject(h_key);
        let _ = NCryptFreeObject(h_prov);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "NCryptDecrypt(NCRYPT_PAD_OAEP_FLAG) failed on TPM PCP key",
    ))
}

#[cfg(windows)]
fn dpapi_local_machine_seal(raw_key: &[u8], entropy_tag: &[u8]) -> io::Result<Vec<u8>> {
    let mut in_copy = raw_key.to_vec();
    let mut ent_copy = entropy_tag.to_vec();

    let in_blob = CryptoApiBlob {
        cb_data: in_copy.len() as u32,
        pb_data: in_copy.as_mut_ptr(),
    };
    let ent_blob = CryptoApiBlob {
        cb_data: ent_copy.len() as u32,
        pb_data: ent_copy.as_mut_ptr(),
    };
    let mut out_blob = CryptoApiBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };

    let flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE;
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            &ent_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            flags,
            &mut out_blob,
        )
    };

    zeroize_slice(&mut in_copy);
    zeroize_slice(&mut ent_copy);

    if ok == 0 || out_blob.pb_data.is_null() {
        return Err(io::Error::last_os_error());
    }

    let sealed_bytes =
        unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec() };
    unsafe {
        let _ = LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
    }
    Ok(sealed_bytes)
}

#[cfg(windows)]
fn dpapi_local_machine_unseal(sealed_bytes: &[u8], entropy_tag: &[u8]) -> io::Result<Vec<u8>> {
    let mut in_copy = sealed_bytes.to_vec();
    let mut ent_copy = entropy_tag.to_vec();

    let in_blob = CryptoApiBlob {
        cb_data: in_copy.len() as u32,
        pb_data: in_copy.as_mut_ptr(),
    };
    let ent_blob = CryptoApiBlob {
        cb_data: ent_copy.len() as u32,
        pb_data: ent_copy.as_mut_ptr(),
    };
    let mut out_blob = CryptoApiBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            &ent_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    zeroize_slice(&mut in_copy);
    zeroize_slice(&mut ent_copy);

    if ok == 0 || out_blob.pb_data.is_null() {
        return Err(io::Error::last_os_error());
    }

    let unsealed =
        unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec() };
    unsafe {
        let raw_slice = std::slice::from_raw_parts_mut(out_blob.pb_data, out_blob.cb_data as usize);
        zeroize_slice(raw_slice);
        let _ = LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
    }
    Ok(unsealed)
}

/// Seals a raw key using hardware TPM 2.0 PCP RSA-2048 OAEP key wrapping when available,
/// falling back to DPAPI `CRYPTPROTECT_LOCAL_MACHINE` (or root-restricted `0400` keyring on Unix)
/// and emitting `POSTURE_REDUCED_NO_TPM` (`Master Plan v2 §1.1 #1, §5.1`).
///
/// Never reports `KeyProtectionPosture::Tpm2Assisted` unless TPM 2.0 PCP encryption actually succeeded.
pub fn seal_key_bytes(
    raw_key: &[u8],
    entropy_tag: &[u8],
    kek_id: &str,
) -> io::Result<SealedKeyBlob> {
    #[cfg(windows)]
    {
        match tpm_pcp_rsa_seal(raw_key, entropy_tag, kek_id) {
            Ok(tpm_ciphertext) => {
                info!(
                    "KEK '{}' sealed in hardware via TPM 2.0 Platform Crypto Provider (RSA-2048 OAEP)",
                    kek_id
                );
                Ok(SealedKeyBlob {
                    posture: KeyProtectionPosture::Tpm2Assisted,
                    kek_id: kek_id.to_string(),
                    sealed_bytes: tpm_ciphertext,
                    reduced_posture_event: None,
                })
            }
            Err(tpm_err) => {
                warn!(
                    "POSTURE_REDUCED_NO_TPM: TPM 2.0 PCP key wrapping unavailable for '{}' ({}); falling back to DPAPI CRYPTPROTECT_LOCAL_MACHINE",
                    kek_id, tpm_err
                );
                let sealed_bytes = dpapi_local_machine_seal(raw_key, entropy_tag)?;
                Ok(SealedKeyBlob {
                    posture: KeyProtectionPosture::DpapiLocalMachine,
                    kek_id: kek_id.to_string(),
                    sealed_bytes,
                    reduced_posture_event: Some("POSTURE_REDUCED_NO_TPM".to_string()),
                })
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // 1. Optional feature-gated Linux TPM 2.0 hardware sealing (`/dev/tpmrm0`, `CSE-28`)
        #[cfg(feature = "linux-tpm2")]
        {
            if let Ok(tpm_sealed) = tpm2_linux_seal(raw_key, entropy_tag, kek_id) {
                return Ok(SealedKeyBlob {
                    posture: KeyProtectionPosture::Tpm2Assisted,
                    kek_id: kek_id.to_string(),
                    sealed_bytes: tpm_sealed,
                    reduced_posture_event: None,
                });
            }
        }

        // 2. Prefer Linux kernel keyring (`SYS_keyctl(KEYCTL_SEARCH)` / `SYS_add_key`, non-swappable kernel memory — zero disk `master.seed`)
        match load_or_create_linux_kernel_keyring_key(true) {
            Ok(mut kernel_secret) => {
                let sealed_res =
                    unix_authenticated_seal(raw_key, &kernel_secret, entropy_tag, kek_id);
                zeroize_slice(&mut kernel_secret);
                let sealed = sealed_res?;
                warn!(
                    "POSTURE_REDUCED_NO_TPM: Hardware TPM 2.0 unavailable; sealing '{}' via Linux kernel keyring (non-swappable kernel memory, no disk master.seed)",
                    kek_id
                );
                return Ok(SealedKeyBlob {
                    posture: KeyProtectionPosture::LinuxKernelKeyring,
                    kek_id: kek_id.to_string(),
                    sealed_bytes: sealed,
                    reduced_posture_event: Some("POSTURE_REDUCED_NO_TPM".to_string()),
                });
            }
            Err(keyring_err) => {
                warn!(
                    "POSTURE_REDUCED_NO_TPM: Linux kernel keyring unavailable for '{}' ({}); falling back to file-backed UnixLocalKeyring (master.seed; refused in strict kiosk mode)",
                    kek_id, keyring_err
                );
            }
        }

        // 3. Last-resort fallback: root-restricted `0400` file-backed wrapping key (`master.seed`)
        let mut master_secret = load_or_create_unix_root_wrapping_key()?;
        let sealed_res = unix_authenticated_seal(raw_key, &master_secret, entropy_tag, kek_id);
        zeroize_slice(&mut master_secret);
        let sealed = sealed_res?;
        Ok(SealedKeyBlob {
            posture: KeyProtectionPosture::UnixLocalKeyring,
            kek_id: kek_id.to_string(),
            sealed_bytes: sealed,
            reduced_posture_event: Some("POSTURE_REDUCED_NO_TPM".to_string()),
        })
    }

    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let mut master_secret = load_or_create_unix_root_wrapping_key()?;
        let sealed_res = unix_authenticated_seal(raw_key, &master_secret, entropy_tag, kek_id);
        zeroize_slice(&mut master_secret);
        let sealed = sealed_res?;
        warn!(
            "POSTURE_REDUCED_NO_TPM: Using Unix root-restricted 0400 wrapping key for '{}' (refused in strict kiosk mode)",
            kek_id
        );
        Ok(SealedKeyBlob {
            posture: KeyProtectionPosture::UnixLocalKeyring,
            kek_id: kek_id.to_string(),
            sealed_bytes: sealed,
            reduced_posture_event: Some("POSTURE_REDUCED_NO_TPM".to_string()),
        })
    }
}

/// Unseals a previously sealed key blob according to the exact `KeyProtectionPosture` recorded in the blob.
pub fn unseal_key_bytes(blob: &SealedKeyBlob, entropy_tag: &[u8]) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        match blob.posture {
            KeyProtectionPosture::Tpm2Assisted => {
                tpm_pcp_rsa_unseal(&blob.sealed_bytes, entropy_tag, &blob.kek_id)
            }
            KeyProtectionPosture::DpapiLocalMachine => {
                dpapi_local_machine_unseal(&blob.sealed_bytes, entropy_tag)
            }
            KeyProtectionPosture::LinuxKernelKeyring | KeyProtectionPosture::UnixLocalKeyring => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cannot unseal Linux/Unix keyring blob on Windows host",
                ))
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        match blob.posture {
            KeyProtectionPosture::Tpm2Assisted => {
                #[cfg(feature = "linux-tpm2")]
                {
                    tpm2_linux_unseal(&blob.sealed_bytes, entropy_tag, &blob.kek_id)
                }
                #[cfg(not(feature = "linux-tpm2"))]
                {
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Cannot unseal Tpm2Assisted blob on Linux without `linux-tpm2` feature enabled",
                    ))
                }
            }
            KeyProtectionPosture::LinuxKernelKeyring => {
                let mut kernel_secret = load_or_create_linux_kernel_keyring_key(false)?;
                let res = unix_authenticated_unseal(
                    &blob.sealed_bytes,
                    &kernel_secret,
                    entropy_tag,
                    &blob.kek_id,
                );
                zeroize_slice(&mut kernel_secret);
                res
            }
            KeyProtectionPosture::UnixLocalKeyring => {
                let mut master_secret = load_or_create_unix_root_wrapping_key()?;
                let res = unix_authenticated_unseal(
                    &blob.sealed_bytes,
                    &master_secret,
                    entropy_tag,
                    &blob.kek_id,
                );
                zeroize_slice(&mut master_secret);
                res
            }
            KeyProtectionPosture::DpapiLocalMachine => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot unseal Windows DPAPI blob on Linux host",
            )),
        }
    }

    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        match blob.posture {
            KeyProtectionPosture::UnixLocalKeyring => {
                let mut master_secret = load_or_create_unix_root_wrapping_key()?;
                let res = unix_authenticated_unseal(
                    &blob.sealed_bytes,
                    &master_secret,
                    entropy_tag,
                    &blob.kek_id,
                );
                zeroize_slice(&mut master_secret);
                res
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot unseal non-UnixLocalKeyring blob on this Unix host",
            )),
        }
    }
}

/// Authenticates and seals a key using HKDF-SHA256 key derivation and AES-256-GCM AEAD
/// with random salt, random nonce, and entropy/kek_id AAD binding (`Master Plan v2 §4 Sub-Phase 0.1`, `OCSL2`).
pub fn unix_authenticated_seal_with_secret(
    raw_key: &[u8],
    master_secret: &[u8; 32],
    entropy_tag: &[u8],
    kek_id: &str,
) -> io::Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;
    use rand::RngCore;

    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let hk = Hkdf::<Sha256>::new(Some(&salt), master_secret);
    let mut derived_key = [0u8; 32];
    hk.expand(
        b"OMNICONNECT-SENTINEL-UNIX-SEAL-AES256GCM-V2",
        &mut derived_key,
    )
    .map_err(|e| io::Error::other(format!("HKDF expand failed: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| io::Error::other(format!("AES-GCM key init failed: {e}")))?;
    zeroize_slice(&mut derived_key);

    let mut aad = Vec::with_capacity(entropy_tag.len() + kek_id.len() + 16);
    aad.extend_from_slice(b"OCSL2-AAD:");
    aad.extend_from_slice(entropy_tag);
    aad.extend_from_slice(kek_id.as_bytes());

    let payload = Payload {
        msg: raw_key,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| io::Error::other(format!("AES-256-GCM encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(5 + 16 + 12 + ciphertext.len());
    out.extend_from_slice(b"OCSL2");
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseals an OCSL2 envelope verifying the 128-bit AEAD authentication tag and bound AAD.
pub fn unix_authenticated_unseal_with_secret(
    sealed: &[u8],
    master_secret: &[u8; 32],
    entropy_tag: &[u8],
    kek_id: &str,
) -> io::Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;

    if sealed.len() < 5 + 16 + 12 + 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Truncated Unix OCSL2 sealed key blob",
        ));
    }
    if &sealed[0..5] != b"OCSL2" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid magic for Unix sealed key (expected OCSL2)",
        ));
    }

    let salt = &sealed[5..21];
    let nonce_bytes = &sealed[21..33];
    let ciphertext = &sealed[33..];

    let hk = Hkdf::<Sha256>::new(Some(salt), master_secret);
    let mut derived_key = [0u8; 32];
    hk.expand(
        b"OMNICONNECT-SENTINEL-UNIX-SEAL-AES256GCM-V2",
        &mut derived_key,
    )
    .map_err(|e| io::Error::other(format!("HKDF expand failed: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| io::Error::other(format!("AES-GCM key init failed: {e}")))?;
    zeroize_slice(&mut derived_key);

    let nonce = Nonce::from_slice(nonce_bytes);

    let mut aad = Vec::with_capacity(entropy_tag.len() + kek_id.len() + 16);
    aad.extend_from_slice(b"OCSL2-AAD:");
    aad.extend_from_slice(entropy_tag);
    aad.extend_from_slice(kek_id.as_bytes());

    let payload = Payload {
        msg: ciphertext,
        aad: &aad,
    };

    let plaintext = cipher.decrypt(nonce, payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "AES-256-GCM authentication failed (tampered ciphertext, salt, nonce, AAD, or wrong key)",
        )
    })?;

    Ok(plaintext)
}

#[cfg(all(target_os = "linux", feature = "linux-tpm2"))]
fn tpm2_linux_seal(_raw_key: &[u8], _entropy_tag: &[u8], _kek_id: &str) -> io::Result<Vec<u8>> {
    if !is_linux_tpm2_device_present() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Linux TPM 2.0 resource manager /dev/tpmrm0 not present",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux TPM 2.0 sealing requires an initialized tss-esapi primary storage key on /dev/tpmrm0; failing closed to next sealing tier",
    ))
}

#[cfg(all(target_os = "linux", feature = "linux-tpm2"))]
fn tpm2_linux_unseal(
    _sealed_bytes: &[u8],
    _entropy_tag: &[u8],
    _kek_id: &str,
) -> io::Result<Vec<u8>> {
    if !is_linux_tpm2_device_present() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Linux TPM 2.0 resource manager /dev/tpmrm0 not present",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux TPM 2.0 unsealing requires an initialized tss-esapi primary storage key on /dev/tpmrm0",
    ))
}

/// Loads (or provisions when `create_if_missing == true`) the 32-byte wrapping key in the
/// Linux kernel keyring (`KEYCTL_SEARCH` / `SYS_add_key` / `KEYCTL_SETPERM` / `KEYCTL_READ`, `CSE-28`)
/// so secret material stays in non-swappable kernel RAM without writing a plaintext `master.seed` file to disk.
#[cfg(target_os = "linux")]
fn load_or_create_linux_kernel_keyring_key(create_if_missing: bool) -> io::Result<[u8; 32]> {
    use rand::RngCore;
    use std::ffi::CString;

    const KEY_SPEC_PROCESS_KEYRING: libc::c_long = -2;
    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    const KEY_SPEC_USER_KEYRING: libc::c_long = -4;
    const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;
    const KEYCTL_REVOKE: libc::c_long = 3;
    const KEYCTL_SETPERM: libc::c_long = 5;
    const KEYCTL_UNLINK: libc::c_long = 9;
    const KEYCTL_SEARCH: libc::c_long = 10;
    const KEYCTL_READ: libc::c_long = 11;
    // Possessor all (0x3f) + User view/read/search (0x0b), zero group/other permissions
    const KEY_PERM_RESTRICTED: libc::c_ulong = 0x3f0b_0000;

    let key_type = CString::new("user")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid keyring type CString"))?;
    let description = CString::new("omniconnect-sentinel:master-kek-v2").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid keyring description CString",
        )
    })?;

    // Prefer `KEY_SPEC_SESSION_KEYRING` first: it is always possessed by the process and
    // inherited by child processes (including systemd `KeyringMode=private` and CI runners
    // where `KEY_SPEC_USER_KEYRING` is not linked into the session keyring). Fall back to
    // `KEY_SPEC_USER_KEYRING` and `KEY_SPEC_PROCESS_KEYRING`.
    let candidate_keyrings = [
        KEY_SPEC_SESSION_KEYRING,
        KEY_SPEC_USER_KEYRING,
        KEY_SPEC_PROCESS_KEYRING,
    ];

    // Explicitly search each candidate keyring via `KEYCTL_SEARCH` (unlike `request_key(2)`,
    // which does not directly search `KEY_SPEC_USER_KEYRING` when a systemd service uses
    // `KeyringMode=private`).
    let mut last_search_read_err: Option<io::Error> = None;
    for keyring in candidate_keyrings {
        let key_serial = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_SEARCH,
                keyring,
                key_type.as_ptr(),
                description.as_ptr(),
                0 as libc::c_long,
            )
        };
        if key_serial > 0 {
            let mut secret = [0u8; 32];
            let read_len = unsafe {
                libc::syscall(
                    libc::SYS_keyctl,
                    KEYCTL_READ,
                    key_serial,
                    secret.as_mut_ptr(),
                    secret.len() as libc::c_ulong,
                )
            };
            if read_len == 32 {
                return Ok(secret);
            }
            let read_err = io::Error::last_os_error();
            zeroize_slice(&mut secret);
            if read_len < 0 {
                // Key exists in this keyring but is unreadable/revoked (e.g. an unpossessed
                // entry in `KEY_SPEC_USER_KEYRING`); continue checking remaining keyrings.
                last_search_read_err = Some(io::Error::new(
                    read_err.kind(),
                    format!(
                        "Linux kernel keyring KEYCTL_READ failed on keyring {keyring}: {read_err}"
                    ),
                ));
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Linux kernel keyring key returned unexpected byte length: {read_len} (expected 32)"
                ),
            ));
        }
    }

    if !create_if_missing {
        return Err(last_search_read_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Linux kernel keyring key 'omniconnect-sentinel:master-kek-v2' not found for unseal",
            )
        }));
    }

    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let mut last_err = io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Linux kernel keyring add_key failed on all candidate keyrings",
    );

    for keyring in candidate_keyrings {
        let mut key_serial = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                key_type.as_ptr(),
                description.as_ptr(),
                secret.as_ptr(),
                secret.len() as libc::c_ulong,
                keyring,
            )
        };
        // Under systemd services running with `User=<non-root>` and `KeyringMode=inherit`,
        // `KEY_SPEC_SESSION_KEYRING` may point to root's read-only session keyring (`EACCES`).
        // Joining a fresh anonymous session keyring owned by the current UID gives this process
        // (and all child processes) a possessed, writable kernel keyring.
        if key_serial <= 0 && keyring == KEY_SPEC_SESSION_KEYRING {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EACCES) || err.raw_os_error() == Some(libc::EPERM) {
                let joined = unsafe {
                    libc::syscall(
                        libc::SYS_keyctl,
                        KEYCTL_JOIN_SESSION_KEYRING,
                        core::ptr::null::<libc::c_char>(),
                    )
                };
                if joined > 0 {
                    key_serial = unsafe {
                        libc::syscall(
                            libc::SYS_add_key,
                            key_type.as_ptr(),
                            description.as_ptr(),
                            secret.as_ptr(),
                            secret.len() as libc::c_ulong,
                            KEY_SPEC_SESSION_KEYRING,
                        )
                    };
                }
            }
        }
        if key_serial > 0 {
            let setperm_rc = unsafe {
                libc::syscall(
                    libc::SYS_keyctl,
                    KEYCTL_SETPERM,
                    key_serial,
                    KEY_PERM_RESTRICTED,
                )
            };
            if setperm_rc != 0 {
                let perm_err = io::Error::last_os_error();
                let _ = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_REVOKE, key_serial) };
                let _ =
                    unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_UNLINK, key_serial, keyring) };
                last_err = io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Linux kernel keyring KEYCTL_SETPERM failed ({perm_err}); unlinked key"
                    ),
                );
                continue;
            }
            let mut verify = [0u8; 32];
            let verify_len = unsafe {
                libc::syscall(
                    libc::SYS_keyctl,
                    KEYCTL_READ,
                    key_serial,
                    verify.as_mut_ptr(),
                    verify.len() as libc::c_ulong,
                )
            };
            let verified = verify_len == 32 && verify == secret;
            zeroize_slice(&mut verify);
            if verified {
                return Ok(secret);
            }
            let _ = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_REVOKE, key_serial) };
            let _ = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_UNLINK, key_serial, keyring) };
            last_err = io::Error::other("Linux kernel keyring read-back verification failed");
        } else {
            last_err = io::Error::last_os_error();
        }
    }

    zeroize_slice(&mut secret);
    Err(last_err)
}

#[cfg(not(windows))]
fn load_or_create_unix_root_wrapping_key() -> io::Result<[u8; 32]> {
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let keystore_dir = Path::new("/var/lib/omniconnect/keystore");
    if !keystore_dir.exists() {
        fs::create_dir_all(keystore_dir)?;
        let _ = fs::set_permissions(keystore_dir, PermissionsExt::from_mode(0o700));
    }

    let seed_path = keystore_dir.join("master.seed");

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&seed_path)?;

    let meta = f.metadata()?;
    let mode = meta.mode();
    let file_uid = meta.uid();
    let current_uid = unsafe { libc::geteuid() };

    if file_uid != current_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Insecure keystore ownership: UID {file_uid} != expected {current_uid}"),
        ));
    }
    if (mode & 0o077) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Insecure keystore permissions on master.seed: {:o} (must be 0600)",
                mode & 0o777
            ),
        ));
    }

    let mut secret = [0u8; 32];
    let n = f.read(&mut secret)?;
    if n == 32 {
        return Ok(secret);
    }

    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut secret);
    f.write_all(&secret)?;
    f.sync_all()?;
    let _ = fs::set_permissions(&seed_path, PermissionsExt::from_mode(0o400));
    Ok(secret)
}

#[cfg(not(windows))]
fn unix_authenticated_seal(
    raw_key: &[u8],
    master_secret: &[u8; 32],
    entropy_tag: &[u8],
    kek_id: &str,
) -> io::Result<Vec<u8>> {
    unix_authenticated_seal_with_secret(raw_key, master_secret, entropy_tag, kek_id)
}

#[cfg(not(windows))]
fn unix_authenticated_unseal(
    sealed: &[u8],
    master_secret: &[u8; 32],
    entropy_tag: &[u8],
    kek_id: &str,
) -> io::Result<Vec<u8>> {
    unix_authenticated_unseal_with_secret(sealed, master_secret, entropy_tag, kek_id)
}

/// Generates a 3072-bit RSA keypair `(rsapublicblob, rsaprivateblob)` via Windows CNG `BCryptGenerateKeyPair`
/// for offline SOC escrow provisioning and testing (`CNSA 2.0` / `CEA-DEFECT-03`).
pub fn generate_soc_rsa_keypair() -> io::Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(windows)]
    {
        let alg_rsa = to_wide("RSA");
        let pub_type = to_wide("RSAPUBLICBLOB");
        let priv_type = to_wide("RSAPRIVATEBLOB");
        let mut h_alg: usize = 0;
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_rsa.as_ptr(), core::ptr::null(), 0)
        };
        if status != 0 || h_alg == 0 {
            return Err(io::Error::other(format!(
                "BCryptOpenAlgorithmProvider(RSA) failed: 0x{:08X}",
                status as u32
            )));
        }

        let mut h_key: usize = 0;
        let gen_status = unsafe { BCryptGenerateKeyPair(h_alg, &mut h_key, 3072, 0) };
        if gen_status != 0 || h_key == 0 {
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return Err(io::Error::other(format!(
                "BCryptGenerateKeyPair(3072) failed: 0x{:08X}",
                gen_status as u32
            )));
        }

        let fin_status = unsafe { BCryptFinalizeKeyPair(h_key, 0) };
        if fin_status != 0 {
            unsafe {
                let _ = BCryptDestroyKey(h_key);
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return Err(io::Error::other(format!(
                "BCryptFinalizeKeyPair(RSA) failed: 0x{:08X}",
                fin_status as u32
            )));
        }

        let mut pub_len: u32 = 0;
        let _ = unsafe {
            BCryptExportKey(
                h_key,
                0,
                pub_type.as_ptr(),
                core::ptr::null_mut(),
                0,
                &mut pub_len,
                0,
            )
        };
        let mut pub_blob = vec![0u8; pub_len as usize];
        let exp_pub = unsafe {
            BCryptExportKey(
                h_key,
                0,
                pub_type.as_ptr(),
                pub_blob.as_mut_ptr(),
                pub_len,
                &mut pub_len,
                0,
            )
        };

        let mut priv_len: u32 = 0;
        let _ = unsafe {
            BCryptExportKey(
                h_key,
                0,
                priv_type.as_ptr(),
                core::ptr::null_mut(),
                0,
                &mut priv_len,
                0,
            )
        };
        let mut priv_blob = vec![0u8; priv_len as usize];
        let exp_priv = unsafe {
            BCryptExportKey(
                h_key,
                0,
                priv_type.as_ptr(),
                priv_blob.as_mut_ptr(),
                priv_len,
                &mut priv_len,
                0,
            )
        };

        unsafe {
            let _ = BCryptDestroyKey(h_key);
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        }

        if exp_pub != 0 || exp_priv != 0 {
            return Err(io::Error::other("BCryptExportKey(RSA) failed"));
        }
        Ok((pub_blob, priv_blob))
    }

    #[cfg(not(windows))]
    {
        generate_soc_rsa_keypair_software()
    }
}

/// Asymmetrically encrypts the 32-byte Master KEK to the offline SOC RSA-3072 (or stronger) public key
/// using Windows CNG `BCryptImportKeyPair("RSAPUBLICBLOB")` + `BCryptEncrypt(BCRYPT_PAD_OAEP)` (`Master Plan v2 §1.1 #2`).
///
/// The resulting `SocEscrowBlob` can ONLY be decrypted by the offline SOC RSA private key,
/// surviving total host/TPM/motherboard destruction. Rejects RSA keys weaker than 3072 bits.
pub fn encrypt_kek_for_soc_escrow(
    kek: &[u8; 32],
    soc_rsa_pub_blob: &[u8],
    kek_id: &str,
) -> io::Result<SocEscrowBlob> {
    use rsa::traits::PublicKeyParts;

    let pub_key = parse_rsa_public_key(soc_rsa_pub_blob)?;
    let rsa_bits = pub_key.n().bit_width();
    if rsa_bits < 3072 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SOC RSA public key strength ({rsa_bits} bits) must be >= 3072 bits"),
        ));
    }

    #[cfg(windows)]
    {
        let mut fp_hasher = Sha256::new();
        fp_hasher.update(soc_rsa_pub_blob);
        let soc_key_fingerprint = hex_encode(&fp_hasher.finalize()[..16]);
        let alg_rsa = to_wide("RSA");
        let pub_type = to_wide("RSAPUBLICBLOB");
        let alg_sha256 = to_wide("SHA256");

        let mut h_alg: usize = 0;
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_rsa.as_ptr(), core::ptr::null(), 0)
        };
        if status != 0 || h_alg == 0 {
            return encrypt_kek_for_soc_escrow_software(kek, soc_rsa_pub_blob, kek_id);
        }

        let mut h_key: usize = 0;
        let imp_status = unsafe {
            BCryptImportKeyPair(
                h_alg,
                0,
                pub_type.as_ptr(),
                &mut h_key,
                soc_rsa_pub_blob.as_ptr(),
                soc_rsa_pub_blob.len() as u32,
                0,
            )
        };
        if imp_status != 0 || h_key == 0 {
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return encrypt_kek_for_soc_escrow_software(kek, soc_rsa_pub_blob, kek_id);
        }

        let label = format!("SOC-OFFLINE-ESCROW-RECOVERY-V2:{kek_id}");
        let padding = BcryptOaepPaddingInfo {
            psz_alg_id: alg_sha256.as_ptr(),
            pb_label: label.as_ptr(),
            cb_label: label.len() as u32,
        };

        let mut cb_cipher: u32 = 0;
        let q_status = unsafe {
            BCryptEncrypt(
                h_key,
                kek.as_ptr(),
                kek.len() as u32,
                &padding as *const _ as *const core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
                &mut cb_cipher,
                BCRYPT_PAD_OAEP,
            )
        };
        if q_status != 0 || cb_cipher == 0 {
            unsafe {
                let _ = BCryptDestroyKey(h_key);
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return encrypt_kek_for_soc_escrow_software(kek, soc_rsa_pub_blob, kek_id);
        }

        let mut ciphertext = vec![0u8; cb_cipher as usize];
        let enc_status = unsafe {
            BCryptEncrypt(
                h_key,
                kek.as_ptr(),
                kek.len() as u32,
                &padding as *const _ as *const core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                ciphertext.as_mut_ptr(),
                cb_cipher,
                &mut cb_cipher,
                BCRYPT_PAD_OAEP,
            )
        };
        unsafe {
            let _ = BCryptDestroyKey(h_key);
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        }
        if enc_status != 0 {
            return encrypt_kek_for_soc_escrow_software(kek, soc_rsa_pub_blob, kek_id);
        }
        ciphertext.truncate(cb_cipher as usize);

        Ok(SocEscrowBlob {
            version: 2,
            algorithm: format!("RSA-{rsa_bits}-OAEP-SHA256"),
            kek_id: kek_id.to_string(),
            soc_key_fingerprint,
            rsa_oaep_ciphertext: ciphertext,
        })
    }

    #[cfg(not(windows))]
    {
        encrypt_kek_for_soc_escrow_software(kek, soc_rsa_pub_blob, kek_id)
    }
}

/// Decrypts an offline `SocEscrowBlob` back into the 32-byte Master KEK using the offline SOC
/// RSA-3072+ private key (`BCryptImportKeyPair("RSAPRIVATEBLOB")` + `BCryptDecrypt(BCRYPT_PAD_OAEP)`).
pub fn decrypt_kek_from_soc_escrow(
    escrow: &SocEscrowBlob,
    soc_rsa_priv_blob: &[u8],
) -> io::Result<[u8; 32]> {
    use rsa::traits::PublicKeyParts;

    if escrow.version != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unsupported SocEscrowBlob version {} (expected 2)",
                escrow.version
            ),
        ));
    }
    let priv_key = parse_rsa_private_key(soc_rsa_priv_blob)?;
    let rsa_bits = priv_key.n().bit_width();
    if rsa_bits < 3072 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SOC RSA private key strength ({rsa_bits} bits) must be >= 3072 bits"),
        ));
    }
    let expected_alg = format!("RSA-{rsa_bits}-OAEP-SHA256");
    if escrow.algorithm != expected_alg {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unsupported SocEscrowBlob algorithm '{}' (expected '{expected_alg}')",
                escrow.algorithm
            ),
        ));
    }
    if escrow.rsa_oaep_ciphertext.len() < 384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "RSA-OAEP ciphertext length {} is below 3072-bit minimum (384 bytes)",
                escrow.rsa_oaep_ciphertext.len()
            ),
        ));
    }

    #[cfg(windows)]
    {
        let alg_rsa = to_wide("RSA");
        let priv_type = to_wide("RSAPRIVATEBLOB");
        let alg_sha256 = to_wide("SHA256");

        let mut h_alg: usize = 0;
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_rsa.as_ptr(), core::ptr::null(), 0)
        };
        if status != 0 || h_alg == 0 {
            return decrypt_kek_from_soc_escrow_software(escrow, soc_rsa_priv_blob);
        }

        let mut h_key: usize = 0;
        let imp_status = unsafe {
            BCryptImportKeyPair(
                h_alg,
                0,
                priv_type.as_ptr(),
                &mut h_key,
                soc_rsa_priv_blob.as_ptr(),
                soc_rsa_priv_blob.len() as u32,
                0,
            )
        };
        if imp_status != 0 || h_key == 0 {
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return decrypt_kek_from_soc_escrow_software(escrow, soc_rsa_priv_blob);
        }

        let label = format!("SOC-OFFLINE-ESCROW-RECOVERY-V2:{}", escrow.kek_id);
        let padding = BcryptOaepPaddingInfo {
            psz_alg_id: alg_sha256.as_ptr(),
            pb_label: label.as_ptr(),
            cb_label: label.len() as u32,
        };

        let mut plain = vec![0u8; escrow.rsa_oaep_ciphertext.len().max(384)];
        let mut cb_plain: u32 = 0;
        let dec_status = unsafe {
            BCryptDecrypt(
                h_key,
                escrow.rsa_oaep_ciphertext.as_ptr(),
                escrow.rsa_oaep_ciphertext.len() as u32,
                &padding as *const _ as *const core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                plain.as_mut_ptr(),
                plain.len() as u32,
                &mut cb_plain,
                BCRYPT_PAD_OAEP,
            )
        };
        unsafe {
            let _ = BCryptDestroyKey(h_key);
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        }

        if dec_status != 0 || cb_plain != 32 {
            zeroize_slice(&mut plain);
            return decrypt_kek_from_soc_escrow_software(escrow, soc_rsa_priv_blob);
        }

        let mut kek = [0u8; 32];
        kek.copy_from_slice(&plain[..32]);
        zeroize_slice(&mut plain);
        Ok(kek)
    }

    #[cfg(not(windows))]
    {
        decrypt_kek_from_soc_escrow_software(escrow, soc_rsa_priv_blob)
    }
}

/// Generates or opens a hardware-backed (TPM 2.0 PCP `ECDSA_P256`) or DPAPI-sealed (`BCRYPT_ECDSA_P256_ALGORITHM`)
/// asymmetric ECDSA P-256 signing keypair (`Master Plan v2 §4.2, §4.4, §4.5`).
pub fn create_sealed_ecdsa_p256_keypair(
    entropy_tag: &[u8],
    key_id: &str,
) -> io::Result<SealedEcdsaKeyPair> {
    #[cfg(windows)]
    {
        // 1. Try TPM 2.0 PCP native ECDSA_P256 persisted key first
        if let Ok(pub_blob) = tpm_pcp_ecdsa_create_or_open_pubkey(key_id) {
            let candidate = SealedEcdsaKeyPair {
                posture: KeyProtectionPosture::Tpm2Assisted,
                key_id: key_id.to_string(),
                public_key_blob: pub_blob,
                sealed_private_key: None,
                reduced_posture_event: None,
            };
            let probe_digest = [0x5Au8; 32];
            if let Ok(probe_sig) =
                sign_with_sealed_ecdsa_p256(&candidate, entropy_tag, &probe_digest)
            {
                if verify_ecdsa_p256_digest(&candidate.public_key_blob, &probe_digest, &probe_sig)
                    .unwrap_or(false)
                {
                    info!(
                        "ECDSA P-256 key '{}' provisioned and verified inside TPM 2.0 Platform Crypto Provider",
                        key_id
                    );
                    return Ok(candidate);
                }
            }
        }

        // 2. Fallback: Generate CNG ECDSA_P256 keypair and seal private blob with DPAPI LOCAL_MACHINE
        let (pub_blob, mut priv_blob) = generate_raw_ecdsa_p256_keypair()?;
        let sealed_priv = dpapi_local_machine_seal(&priv_blob, entropy_tag)?;
        zeroize_slice(&mut priv_blob);

        warn!(
            "POSTURE_REDUCED_NO_TPM: ECDSA P-256 key '{}' sealed with DPAPI CRYPTPROTECT_LOCAL_MACHINE fallback",
            key_id
        );
        Ok(SealedEcdsaKeyPair {
            posture: KeyProtectionPosture::DpapiLocalMachine,
            key_id: key_id.to_string(),
            public_key_blob: pub_blob,
            sealed_private_key: Some(SealedKeyBlob {
                posture: KeyProtectionPosture::DpapiLocalMachine,
                kek_id: key_id.to_string(),
                sealed_bytes: sealed_priv,
                reduced_posture_event: Some("POSTURE_REDUCED_NO_TPM".to_string()),
            }),
            reduced_posture_event: Some("POSTURE_REDUCED_NO_TPM".to_string()),
        })
    }

    #[cfg(not(windows))]
    {
        let (pub_blob, mut priv_blob) = generate_raw_ecdsa_p256_keypair()?;
        let sealed_priv = seal_key_bytes(&priv_blob, entropy_tag, key_id)?;
        zeroize_slice(&mut priv_blob);
        let posture = sealed_priv.posture;
        let reduced_posture_event = sealed_priv.reduced_posture_event.clone();
        Ok(SealedEcdsaKeyPair {
            posture,
            key_id: key_id.to_string(),
            public_key_blob: pub_blob,
            sealed_private_key: Some(sealed_priv),
            reduced_posture_event,
        })
    }
}

/// Generates a raw ECDSA P-256 `(eccpublicblob, eccprivateblob)` pair via Windows CNG `BCryptGenerateKeyPair`.
pub fn generate_raw_ecdsa_p256_keypair() -> io::Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(windows)]
    {
        let alg_ecdsa = to_wide("ECDSA_P256");
        let pub_type = to_wide("ECCPUBLICBLOB");
        let priv_type = to_wide("ECCPRIVATEBLOB");

        let mut h_alg: usize = 0;
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_ecdsa.as_ptr(), core::ptr::null(), 0)
        };
        if status != 0 || h_alg == 0 {
            return Err(io::Error::other(format!(
                "BCryptOpenAlgorithmProvider(ECDSA_P256) failed: 0x{:08X}",
                status as u32
            )));
        }

        let mut h_key: usize = 0;
        let gen_status = unsafe { BCryptGenerateKeyPair(h_alg, &mut h_key, 256, 0) };
        if gen_status != 0 || h_key == 0 {
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return Err(io::Error::other(format!(
                "BCryptGenerateKeyPair(ECDSA_P256) failed: 0x{:08X}",
                gen_status as u32
            )));
        }

        let fin_status = unsafe { BCryptFinalizeKeyPair(h_key, 0) };
        if fin_status != 0 {
            unsafe {
                let _ = BCryptDestroyKey(h_key);
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return Err(io::Error::other(format!(
                "BCryptFinalizeKeyPair(ECDSA_P256) failed: 0x{:08X}",
                fin_status as u32
            )));
        }

        let mut pub_len: u32 = 0;
        let _ = unsafe {
            BCryptExportKey(
                h_key,
                0,
                pub_type.as_ptr(),
                core::ptr::null_mut(),
                0,
                &mut pub_len,
                0,
            )
        };
        let mut pub_blob = vec![0u8; pub_len as usize];
        let exp_pub = unsafe {
            BCryptExportKey(
                h_key,
                0,
                pub_type.as_ptr(),
                pub_blob.as_mut_ptr(),
                pub_len,
                &mut pub_len,
                0,
            )
        };

        let mut priv_len: u32 = 0;
        let _ = unsafe {
            BCryptExportKey(
                h_key,
                0,
                priv_type.as_ptr(),
                core::ptr::null_mut(),
                0,
                &mut priv_len,
                0,
            )
        };
        let mut priv_blob = vec![0u8; priv_len as usize];
        let exp_priv = unsafe {
            BCryptExportKey(
                h_key,
                0,
                priv_type.as_ptr(),
                priv_blob.as_mut_ptr(),
                priv_len,
                &mut priv_len,
                0,
            )
        };

        unsafe {
            let _ = BCryptDestroyKey(h_key);
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        }

        if exp_pub != 0 || exp_priv != 0 {
            zeroize_slice(&mut priv_blob);
            return Err(io::Error::other("BCryptExportKey(ECDSA_P256) failed"));
        }
        Ok((pub_blob, priv_blob))
    }

    #[cfg(not(windows))]
    {
        generate_ecdsa_p256_keypair_software()
    }
}

/// Pure-Rust constant-time ECDSA P-256 keypair generation (RFC 6979 / SEC1 / ECS1/ECS2 layout).
pub fn generate_ecdsa_p256_keypair_software() -> io::Result<(Vec<u8>, Vec<u8>)> {
    use crate::mem_guard::ZeroizingBytes;
    use p256::ecdsa::SigningKey;
    use rand::RngCore;

    let mut priv_scalar = ZeroizingBytes::<32>::new([0u8; 32]);
    let signing_key = loop {
        rand::rngs::OsRng.fill_bytes(&mut *priv_scalar);
        if let Ok(sk) = SigningKey::from_slice(&*priv_scalar) {
            break sk;
        }
    };

    let verifying_key = signing_key.verifying_key();
    let sec1_point = verifying_key.to_sec1_point(false);
    let sec1_bytes = sec1_point.as_bytes();
    if sec1_bytes.len() != 65 || sec1_bytes[0] != 0x04 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SEC1 point",
        ));
    }
    let x = &sec1_bytes[1..33];
    let y = &sec1_bytes[33..65];

    let mut pub_blob = Vec::with_capacity(72);
    pub_blob.extend_from_slice(b"ECS1");
    pub_blob.extend_from_slice(&32u32.to_le_bytes());
    pub_blob.extend_from_slice(x);
    pub_blob.extend_from_slice(y);

    let mut priv_blob = Vec::with_capacity(104);
    priv_blob.extend_from_slice(b"ECS2");
    priv_blob.extend_from_slice(&32u32.to_le_bytes());
    priv_blob.extend_from_slice(x);
    priv_blob.extend_from_slice(y);
    priv_blob.extend_from_slice(&*priv_scalar);

    Ok((pub_blob, priv_blob))
}

/// Deterministic ECDSA P-256 keypair derivation from a 32-byte scalar seed.
pub fn generate_ecdsa_p256_keypair_from_seed(seed: &[u8; 32]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    use crate::mem_guard::ZeroizingBytes;
    use p256::ecdsa::SigningKey;

    let priv_scalar = ZeroizingBytes::<32>::new(*seed);
    let signing_key = SigningKey::from_slice(&*priv_scalar).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid P-256 scalar seed: {e}"),
        )
    })?;

    let verifying_key = signing_key.verifying_key();
    let sec1_point = verifying_key.to_sec1_point(false);
    let sec1_bytes = sec1_point.as_bytes();
    if sec1_bytes.len() != 65 || sec1_bytes[0] != 0x04 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SEC1 point",
        ));
    }
    let x = &sec1_bytes[1..33];
    let y = &sec1_bytes[33..65];

    let mut pub_blob = Vec::with_capacity(72);
    pub_blob.extend_from_slice(b"ECS1");
    pub_blob.extend_from_slice(&32u32.to_le_bytes());
    pub_blob.extend_from_slice(x);
    pub_blob.extend_from_slice(y);

    let mut priv_blob = Vec::with_capacity(104);
    priv_blob.extend_from_slice(b"ECS2");
    priv_blob.extend_from_slice(&32u32.to_le_bytes());
    priv_blob.extend_from_slice(x);
    priv_blob.extend_from_slice(y);
    priv_blob.extend_from_slice(&*priv_scalar);

    Ok((pub_blob, priv_blob))
}

/// Pure-Rust constant-time RFC 6979 ECDSA P-256 prehash signing over a 32-byte digest.
pub fn sign_ecdsa_p256_digest_software(
    ecc_private_blob: &[u8],
    sha256_digest: &[u8; 32],
) -> io::Result<Vec<u8>> {
    if ecc_private_blob.len() < 104 || &ecc_private_blob[0..4] != b"ECS2" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid ECCPRIVATEBLOB (must start with ECS2 and be at least 104 bytes)",
        ));
    }
    let cb_key = u32::from_le_bytes([
        ecc_private_blob[4],
        ecc_private_blob[5],
        ecc_private_blob[6],
        ecc_private_blob[7],
    ]);
    if cb_key != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid ECDSA P-256 key length: {cb_key} (expected 32)"),
        ));
    }
    let scalar_bytes = &ecc_private_blob[72..104];
    let signing_key = p256::ecdsa::SigningKey::from_slice(scalar_bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid ECDSA P-256 private scalar: {e}"),
        )
    })?;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let signature: p256::ecdsa::Signature = signing_key
        .sign_prehash(sha256_digest)
        .map_err(|e| io::Error::other(format!("ECDSA P-256 prehash signing failed: {e}")))?;
    Ok(signature.normalize_s().to_bytes().to_vec())
}

/// Normalizes a 64-byte `(r || s)` ECDSA P-256 signature to canonical low-S (`s <= (n - 1) / 2`)
/// so `(r, n - s)` signature malleability is eliminated across TPM 2.0 PCP, Windows CNG, and pure-Rust paths.
#[cfg(windows)]
fn normalize_ecdsa_p256_signature_low_s(raw_sig: &[u8]) -> io::Result<Vec<u8>> {
    let sig = p256::ecdsa::Signature::from_slice(raw_sig).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid 64-byte ECDSA P-256 signature encoding: {e}"),
        )
    })?;
    Ok(sig.normalize_s().to_bytes().to_vec())
}

fn is_canonical_low_s_ecdsa_p256_signature(raw_sig: &[u8]) -> bool {
    use p256::elliptic_curve::subtle::ConstantTimeEq;
    match p256::ecdsa::Signature::from_slice(raw_sig) {
        Ok(sig) => bool::from(sig.normalize_s().to_bytes().as_slice().ct_eq(raw_sig)),
        Err(_) => false,
    }
}

/// Validates that a 65-byte uncompressed SEC1 (`0x04 || X[32] || Y[32]`) byte slice represents
/// a valid affine point on the NIST P-256 (`secp256r1`) curve.
pub fn validate_p256_uncompressed_point(sec1_65: &[u8]) -> io::Result<()> {
    if sec1_65.len() != 65 || sec1_65[0] != 0x04 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid P-256 uncompressed SEC1 length or prefix",
        ));
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1_65).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid secp256r1 curve point: {e}"),
        )
    })?;
    Ok(())
}

/// Pure-Rust constant-time ECDSA P-256 signature verification accepting canonical 72-byte ECS1 and 65-byte SEC1.
pub fn verify_ecdsa_p256_digest_software(
    ecc_public_blob: &[u8],
    sha256_digest: &[u8; 32],
    signature: &[u8],
) -> io::Result<bool> {
    if signature.len() != 64 || !is_canonical_low_s_ecdsa_p256_signature(signature) {
        return Ok(false);
    }
    let verifying_key = if ecc_public_blob.len() == 72 && &ecc_public_blob[0..4] == b"ECS1" {
        let cb_key = u32::from_le_bytes([
            ecc_public_blob[4],
            ecc_public_blob[5],
            ecc_public_blob[6],
            ecc_public_blob[7],
        ]);
        if cb_key != 32 {
            return Ok(false);
        }
        let x = &ecc_public_blob[8..40];
        let y = &ecc_public_blob[40..72];
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(x);
        sec1[33..65].copy_from_slice(y);
        match p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) {
            Ok(vk) => vk,
            Err(_) => return Ok(false),
        }
    } else if ecc_public_blob.len() == 65 && ecc_public_blob[0] == 0x04 {
        match p256::ecdsa::VerifyingKey::from_sec1_bytes(ecc_public_blob) {
            Ok(vk) => vk,
            Err(_) => return Ok(false),
        }
    } else {
        return Ok(false);
    };

    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let sig = match p256::ecdsa::Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    Ok(verifying_key.verify_prehash(sha256_digest, &sig).is_ok())
}

#[cfg(windows)]
fn tpm_pcp_ecdsa_create_or_open_pubkey(key_id: &str) -> io::Result<Vec<u8>> {
    let _tpm_guard = TPM_PCP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let provider_name = to_wide("Microsoft Platform Crypto Provider");
    let mut h_prov: usize = 0;
    let status = unsafe { NCryptOpenStorageProvider(&mut h_prov, provider_name.as_ptr(), 0) };
    if status != 0 || h_prov == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TPM PCP provider unavailable",
        ));
    }

    let key_name = to_wide(&format!("OmniConnectSentinelEcdsaP256_{key_id}"));
    let alg_ecdsa = to_wide("ECDSA_P256");
    let pub_type = to_wide("ECCPUBLICBLOB");
    let mut h_key: usize = 0;

    let open_status = unsafe {
        NCryptOpenKey(
            h_prov,
            &mut h_key,
            key_name.as_ptr(),
            0,
            NCRYPT_MACHINE_KEY_FLAG,
        )
    };
    if open_status != 0 || h_key == 0 {
        let create_status = unsafe {
            NCryptCreatePersistedKey(
                h_prov,
                &mut h_key,
                alg_ecdsa.as_ptr(),
                key_name.as_ptr(),
                0,
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        if create_status != 0 || h_key == 0 {
            unsafe {
                let _ = NCryptFreeObject(h_prov);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "NCryptCreatePersistedKey(ECDSA_P256, NCRYPT_MACHINE_KEY_FLAG) failed on TPM PCP",
            ));
        }
        let fin_status = unsafe { NCryptFinalizeKey(h_key, NCRYPT_SILENT_FLAG) };
        if fin_status != 0 {
            unsafe {
                let _ = NCryptFreeObject(h_key);
                let _ = NCryptFreeObject(h_prov);
            }
            return Err(io::Error::other(
                "NCryptFinalizeKey(ECDSA_P256) failed on TPM PCP",
            ));
        }

        // Verify machine-scoped key was persisted and can be reopened with NCRYPT_MACHINE_KEY_FLAG
        unsafe {
            let _ = NCryptFreeObject(h_key);
        }
        let mut reopen_key: usize = 0;
        let reopen_status = unsafe {
            NCryptOpenKey(
                h_prov,
                &mut reopen_key,
                key_name.as_ptr(),
                0,
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        if reopen_status != 0 || reopen_key == 0 {
            unsafe {
                let _ = NCryptFreeObject(h_prov);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "TPM PCP key was not persisted to persistent key store (insufficient privileges or ephemeral provider)",
            ));
        }
        h_key = reopen_key;
    }

    let mut cb_pub: u32 = 0;
    let q_status = unsafe {
        NCryptExportKey(
            h_key,
            0,
            pub_type.as_ptr(),
            core::ptr::null(),
            core::ptr::null_mut(),
            0,
            &mut cb_pub,
            NCRYPT_SILENT_FLAG,
        )
    };
    if q_status != 0 || cb_pub == 0 {
        unsafe {
            let _ = NCryptFreeObject(h_key);
            let _ = NCryptFreeObject(h_prov);
        }
        return Err(io::Error::other(
            "NCryptExportKey(ECCPUBLICBLOB) failed on TPM PCP",
        ));
    }

    let mut pub_blob = vec![0u8; cb_pub as usize];
    let exp_status = unsafe {
        NCryptExportKey(
            h_key,
            0,
            pub_type.as_ptr(),
            core::ptr::null(),
            pub_blob.as_mut_ptr(),
            cb_pub,
            &mut cb_pub,
            NCRYPT_SILENT_FLAG,
        )
    };

    // Also test signing a 32-byte dummy digest right now to confirm silent signing works without UI
    let dummy_hash = [0xAAu8; 32];
    let mut dummy_sig = [0u8; 64];
    let mut cb_sig: u32 = 0;
    let sign_test = unsafe {
        NCryptSignHash(
            h_key,
            core::ptr::null(),
            dummy_hash.as_ptr(),
            32,
            dummy_sig.as_mut_ptr(),
            64,
            &mut cb_sig,
            NCRYPT_SILENT_FLAG,
        )
    };

    unsafe {
        let _ = NCryptFreeObject(h_key);
        let _ = NCryptFreeObject(h_prov);
    }

    if exp_status != 0 || sign_test != 0 || cb_sig == 0 {
        return Err(io::Error::other(
            "TPM PCP ECDSA_P256 key export or silent sign probe failed",
        ));
    }
    pub_blob.truncate(cb_pub as usize);
    Ok(pub_blob)
}

/// Signs a 32-byte SHA-256 digest using a `SealedEcdsaKeyPair` (TPM 2.0 PCP `NCryptSignHash` or
/// unsealed CNG `BCryptSignHash` over `BCRYPT_ECDSA_P256_ALGORITHM`).
pub fn sign_with_sealed_ecdsa_p256(
    keypair: &SealedEcdsaKeyPair,
    entropy_tag: &[u8],
    sha256_digest: &[u8; 32],
) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        if keypair.posture == KeyProtectionPosture::Tpm2Assisted
            && keypair.sealed_private_key.is_none()
        {
            let _tpm_guard = TPM_PCP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let provider_name = to_wide("Microsoft Platform Crypto Provider");
            let mut h_prov: usize = 0;
            let status =
                unsafe { NCryptOpenStorageProvider(&mut h_prov, provider_name.as_ptr(), 0) };
            if status != 0 || h_prov == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TPM PCP unavailable for ECDSA P-256 signing",
                ));
            }
            let key_name = to_wide(&format!("OmniConnectSentinelEcdsaP256_{}", keypair.key_id));
            let mut h_key: usize = 0;
            let mut open_status = unsafe {
                NCryptOpenKey(
                    h_prov,
                    &mut h_key,
                    key_name.as_ptr(),
                    0,
                    NCRYPT_MACHINE_KEY_FLAG,
                )
            };
            if open_status != 0 || h_key == 0 {
                open_status = unsafe { NCryptOpenKey(h_prov, &mut h_key, key_name.as_ptr(), 0, 0) };
            }
            if open_status != 0 || h_key == 0 {
                unsafe {
                    let _ = NCryptFreeObject(h_prov);
                }
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Failed opening persisted TPM PCP ECDSA_P256 key",
                ));
            }
            let mut sig = vec![0u8; 64];
            let mut cb_sig: u32 = 0;
            let sign_status = unsafe {
                NCryptSignHash(
                    h_key,
                    core::ptr::null(),
                    sha256_digest.as_ptr(),
                    32,
                    sig.as_mut_ptr(),
                    64,
                    &mut cb_sig,
                    NCRYPT_SILENT_FLAG,
                )
            };
            unsafe {
                let _ = NCryptFreeObject(h_key);
                let _ = NCryptFreeObject(h_prov);
            }
            if sign_status != 0 || cb_sig == 0 {
                return Err(io::Error::other(format!(
                    "NCryptSignHash(ECDSA_P256) failed: 0x{:08X}",
                    sign_status as u32
                )));
            }
            sig.truncate(cb_sig as usize);
            return normalize_ecdsa_p256_signature_low_s(&sig);
        }
    }

    let sealed_priv = keypair.sealed_private_key.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Sealed ECDSA private key blob is missing",
        )
    })?;
    let mut priv_blob = unseal_key_bytes(sealed_priv, entropy_tag)?;
    let res = sign_ecdsa_p256_with_private_blob(&priv_blob, sha256_digest);
    zeroize_slice(&mut priv_blob);
    res
}

/// Signs a 32-byte SHA-256 digest with a raw CNG `ECCPRIVATEBLOB` (`BCRYPT_ECDSA_P256_ALGORITHM`).
pub fn sign_ecdsa_p256_with_private_blob(
    ecc_private_blob: &[u8],
    sha256_digest: &[u8; 32],
) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        let alg_ecdsa = to_wide("ECDSA_P256");
        let priv_type = to_wide("ECCPRIVATEBLOB");

        let mut h_alg: usize = 0;
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_ecdsa.as_ptr(), core::ptr::null(), 0)
        };
        if status != 0 || h_alg == 0 {
            return Err(io::Error::other(format!(
                "BCryptOpenAlgorithmProvider(ECDSA_P256) failed: 0x{:08X}",
                status as u32
            )));
        }

        let mut h_key: usize = 0;
        let imp_status = unsafe {
            BCryptImportKeyPair(
                h_alg,
                0,
                priv_type.as_ptr(),
                &mut h_key,
                ecc_private_blob.as_ptr(),
                ecc_private_blob.len() as u32,
                0,
            )
        };
        if imp_status != 0 || h_key == 0 {
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "BCryptImportKeyPair(ECCPRIVATEBLOB) failed: 0x{:08X}",
                    imp_status as u32
                ),
            ));
        }

        let mut sig = vec![0u8; 64];
        let mut cb_sig: u32 = 0;
        let sign_status = unsafe {
            BCryptSignHash(
                h_key,
                core::ptr::null(),
                sha256_digest.as_ptr(),
                32,
                sig.as_mut_ptr(),
                64,
                &mut cb_sig,
                0,
            )
        };
        unsafe {
            let _ = BCryptDestroyKey(h_key);
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        }
        if sign_status != 0 || cb_sig == 0 {
            return Err(io::Error::other(format!(
                "BCryptSignHash(ECDSA_P256) failed: 0x{:08X}",
                sign_status as u32
            )));
        }
        sig.truncate(cb_sig as usize);
        normalize_ecdsa_p256_signature_low_s(&sig)
    }

    #[cfg(not(windows))]
    {
        sign_ecdsa_p256_digest_software(ecc_private_blob, sha256_digest)
    }
}

/// Verifies a 64-byte ECDSA P-256 signature over a 32-byte SHA-256 digest using ONLY the
/// 72-byte `ECCPUBLICBLOB` or 65-byte uncompressed SEC1 key (`Master Plan v2 §4 Sub-Phase 0.1`).
pub fn verify_ecdsa_p256_digest(
    ecc_public_blob: &[u8],
    sha256_digest: &[u8; 32],
    signature: &[u8],
) -> io::Result<bool> {
    if signature.len() != 64 || !is_canonical_low_s_ecdsa_p256_signature(signature) {
        return Ok(false);
    }
    if ecc_public_blob.len() != 65 && ecc_public_blob.len() != 72 {
        return Ok(false);
    }
    if ecc_public_blob.len() == 72 && &ecc_public_blob[0..8] != b"ECS1\x20\x00\x00\x00" {
        return Ok(false);
    }

    #[cfg(windows)]
    {
        if ecc_public_blob.len() == 65 && ecc_public_blob[0] == 0x04 {
            return verify_ecdsa_p256_digest_software(ecc_public_blob, sha256_digest, signature);
        }

        let alg_ecdsa = to_wide("ECDSA_P256");
        let pub_type = to_wide("ECCPUBLICBLOB");

        let mut h_alg: usize = 0;
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut h_alg, alg_ecdsa.as_ptr(), core::ptr::null(), 0)
        };
        if status != 0 || h_alg == 0 {
            return verify_ecdsa_p256_digest_software(ecc_public_blob, sha256_digest, signature);
        }

        let mut h_key: usize = 0;
        let imp_status = unsafe {
            BCryptImportKeyPair(
                h_alg,
                0,
                pub_type.as_ptr(),
                &mut h_key,
                ecc_public_blob.as_ptr(),
                ecc_public_blob.len() as u32,
                0,
            )
        };
        if imp_status != 0 || h_key == 0 {
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return verify_ecdsa_p256_digest_software(ecc_public_blob, sha256_digest, signature);
        }

        let verify_status = unsafe {
            BCryptVerifySignature(
                h_key,
                core::ptr::null(),
                sha256_digest.as_ptr(),
                32,
                signature.as_ptr(),
                signature.len() as u32,
                0,
            )
        };
        unsafe {
            let _ = BCryptDestroyKey(h_key);
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        }
        Ok(verify_status == 0)
    }

    #[cfg(not(windows))]
    {
        verify_ecdsa_p256_digest_software(ecc_public_blob, sha256_digest, signature)
    }
}

/// Writes a key file atomically (`tmp` -> `sync_all` -> `rename` -> `sync_directory`)
/// with atomic creation-time SYSTEM/Admin DACL / 0o600 permissions, completely eliminating
/// DACL race windows, and propagating all I/O and ACL errors (`High #15`, `Row 44, 45, 225`).
pub fn write_protected_key_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            crate::fs_lowlevel::create_restricted_dir_atomic(parent)?;
        }
    }
    let tmp_path = path.with_extension("tmp_key_write");
    crate::fs_lowlevel::create_restricted_file_atomic(&tmp_path, contents)?;
    std::fs::rename(&tmp_path, path)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            crate::fs_lowlevel::sync_directory(parent)?;
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

struct RsaRngAdapter;

impl rsa::rand_core::TryRng for RsaRngAdapter {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand::RngCore::next_u32(&mut rand::rngs::OsRng))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand::RngCore::next_u64(&mut rand::rngs::OsRng))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, dst);
        Ok(())
    }
}
impl rsa::rand_core::TryCryptoRng for RsaRngAdapter {}

/// Exports an RSA public key into Windows CNG `BCRYPT_RSAKEY_BLOB` (`RSAPUBLICBLOB`) format.
pub fn export_rsa_public_key_to_cng(pub_key: &rsa::PublicKey) -> Vec<u8> {
    use rsa::traits::PublicKeyParts;
    let n_bytes = pub_key.n().to_be_bytes();
    let e_bytes = pub_key.e().to_be_bytes();
    let mut e_slice = &e_bytes[..];
    while e_slice.len() > 3 && e_slice[0] == 0 {
        e_slice = &e_slice[1..];
    }

    let cb_mod = n_bytes.len() as u32;
    let bit_len = cb_mod * 8;
    let cb_exp = e_slice.len() as u32;

    let mut blob = Vec::with_capacity(24 + e_slice.len() + n_bytes.len());
    blob.extend_from_slice(&0x3141_5352u32.to_le_bytes()); // "RSA1"
    blob.extend_from_slice(&bit_len.to_le_bytes());
    blob.extend_from_slice(&cb_exp.to_le_bytes());
    blob.extend_from_slice(&cb_mod.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes()); // cbPrime1 = 0
    blob.extend_from_slice(&0u32.to_le_bytes()); // cbPrime2 = 0
    blob.extend_from_slice(e_slice);
    blob.extend_from_slice(&n_bytes);
    blob
}

/// Exports an RSA private key into Windows CNG `BCRYPT_RSAKEY_BLOB` (`RSAPRIVATEBLOB`) format.
pub fn export_rsa_private_key_to_cng(priv_key: &rsa::PrivateKey) -> io::Result<Vec<u8>> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let n_bytes = priv_key.n().to_be_bytes();
    let e_bytes = priv_key.e().to_be_bytes();
    let mut e_slice = &e_bytes[..];
    while e_slice.len() > 3 && e_slice[0] == 0 {
        e_slice = &e_slice[1..];
    }

    let primes = priv_key.primes();
    if primes.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RSA private key must have at least 2 primes",
        ));
    }
    let p_bytes = primes[0].to_be_bytes();
    let q_bytes = primes[1].to_be_bytes();

    let cb_mod = n_bytes.len() as u32;
    let bit_len = cb_mod * 8;
    let cb_exp = e_slice.len() as u32;
    let target_prime_len = (cb_mod / 2) as usize;

    let mut p_padded = vec![0u8; target_prime_len];
    if p_bytes.len() <= target_prime_len {
        let offset = target_prime_len - p_bytes.len();
        p_padded[offset..].copy_from_slice(&p_bytes);
    } else {
        p_padded.copy_from_slice(&p_bytes[p_bytes.len() - target_prime_len..]);
    }

    let mut q_padded = vec![0u8; target_prime_len];
    if q_bytes.len() <= target_prime_len {
        let offset = target_prime_len - q_bytes.len();
        q_padded[offset..].copy_from_slice(&q_bytes);
    } else {
        q_padded.copy_from_slice(&q_bytes[q_bytes.len() - target_prime_len..]);
    }

    let cb_p1 = target_prime_len as u32;
    let cb_p2 = target_prime_len as u32;

    let mut blob = Vec::with_capacity(24 + e_slice.len() + n_bytes.len() + target_prime_len * 2);
    blob.extend_from_slice(&0x3241_5352u32.to_le_bytes()); // "RSA2"
    blob.extend_from_slice(&bit_len.to_le_bytes());
    blob.extend_from_slice(&cb_exp.to_le_bytes());
    blob.extend_from_slice(&cb_mod.to_le_bytes());
    blob.extend_from_slice(&cb_p1.to_le_bytes());
    blob.extend_from_slice(&cb_p2.to_le_bytes());
    blob.extend_from_slice(e_slice);
    blob.extend_from_slice(&n_bytes);
    blob.extend_from_slice(&p_padded);
    blob.extend_from_slice(&q_padded);
    Ok(blob)
}

/// Parses an RSA public key from Windows CNG `RSAPUBLICBLOB` format.
pub fn parse_rsa_public_key(blob: &[u8]) -> io::Result<rsa::PublicKey> {
    use rsa::traits::PublicKeyParts;
    use rsa::BoxedUint;
    if blob.len() >= 24 && &blob[0..4] == b"RSA1" {
        let bit_len = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        let cb_exp = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
        let cb_mod = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
        let cb_p1 = u32::from_le_bytes([blob[16], blob[17], blob[18], blob[19]]) as usize;
        let cb_p2 = u32::from_le_bytes([blob[20], blob[21], blob[22], blob[23]]) as usize;

        if cb_p1 != 0 || cb_p2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Malformed RSAPUBLICBLOB: non-zero prime lengths in public blob header",
            ));
        }
        if !(1..=8).contains(&cb_exp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid RSA public exponent byte length: {cb_exp}"),
            ));
        }
        if !(384..=1024).contains(&cb_mod) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Insecure or unsupported RSA modulus byte length: {cb_mod} (must be 384..=1024 bytes / 3072..=8192 bits)"),
            ));
        }
        if bit_len < 3072 || bit_len != cb_mod * 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid RSAPUBLICBLOB bit_len header: bit_len={bit_len}, cb_mod={cb_mod} (expected {} bits >= 3072)",
                    cb_mod * 8
                ),
            ));
        }
        let total_required = 24 + cb_exp + cb_mod;
        if blob.len() != total_required {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Malformed RSAPUBLICBLOB length: expected {total_required} bytes, got {}",
                    blob.len()
                ),
            ));
        }
        let exp_bytes = &blob[24..24 + cb_exp];
        let mod_bytes = &blob[24 + cb_exp..24 + cb_exp + cb_mod];

        let n = BoxedUint::from_be_slice(mod_bytes, (cb_mod * 8) as u32).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid modulus: {e}"))
        })?;
        let e = BoxedUint::from_be_slice(exp_bytes, (cb_exp * 8) as u32).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid exponent: {e}"),
            )
        })?;

        let pub_key = rsa::PublicKey::new(n, e).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid RSA public key: {err}"),
            )
        })?;
        let actual_bits = pub_key.n().bit_width() as usize;
        if actual_bits < 3072 || actual_bits <= (cb_mod - 1) * 8 || actual_bits > cb_mod * 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "RSA public key mathematical modulus width ({actual_bits} bits) fails >= 3072-bit floor or mismatches declared {bit_len}-bit strength"
                ),
            ));
        }
        Ok(pub_key)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unsupported RSA public key format (expected RSAPUBLICBLOB with RSA1 magic)",
        ))
    }
}

/// Parses an RSA private key from Windows CNG `RSAPRIVATEBLOB` format.
pub fn parse_rsa_private_key(blob: &[u8]) -> io::Result<rsa::PrivateKey> {
    use rsa::traits::PublicKeyParts;
    use rsa::BoxedUint;
    if blob.len() >= 24 && &blob[0..4] == b"RSA2" {
        let bit_len = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        let cb_exp = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
        let cb_mod = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
        let cb_p1 = u32::from_le_bytes([blob[16], blob[17], blob[18], blob[19]]) as usize;
        let cb_p2 = u32::from_le_bytes([blob[20], blob[21], blob[22], blob[23]]) as usize;

        if !(1..=8).contains(&cb_exp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid RSA exponent byte length: {cb_exp}"),
            ));
        }
        if !(384..=1024).contains(&cb_mod) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Insecure or unsupported RSA private modulus byte length: {cb_mod} (must be 384..=1024 bytes / >= 3072 bits)"),
            ));
        }
        if bit_len < 3072 || bit_len != cb_mod * 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid RSAPRIVATEBLOB bit_len header: bit_len={bit_len}, cb_mod={cb_mod} (must be >= 3072 bits)"
                ),
            ));
        }
        if cb_p1 < 192 || cb_p2 < 192 || cb_p1 + cb_p2 != cb_mod {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid RSAPRIVATEBLOB prime lengths: cb_p1={cb_p1}, cb_p2={cb_p2}, cb_mod={cb_mod}"),
            ));
        }

        let total_required = 24 + cb_exp + cb_mod + cb_p1 + cb_p2;
        if blob.len() != total_required {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Malformed RSAPRIVATEBLOB length: expected {total_required} bytes, got {}",
                    blob.len()
                ),
            ));
        }

        let exp_bytes = &blob[24..24 + cb_exp];
        let mod_bytes = &blob[24 + cb_exp..24 + cb_exp + cb_mod];
        let p1_bytes = &blob[24 + cb_exp + cb_mod..24 + cb_exp + cb_mod + cb_p1];
        let p2_bytes = &blob[24 + cb_exp + cb_mod + cb_p1..24 + cb_exp + cb_mod + cb_p1 + cb_p2];

        let declared_n =
            BoxedUint::from_be_slice(mod_bytes, (cb_mod * 8) as u32).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid modulus in RSAPRIVATEBLOB: {err}"),
                )
            })?;
        let e = BoxedUint::from_be_slice(exp_bytes, (cb_exp * 8) as u32).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid exponent: {err}"),
            )
        })?;
        let p = BoxedUint::from_be_slice(p1_bytes, (cb_p1 * 8) as u32).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid prime1: {err}"),
            )
        })?;
        let q = BoxedUint::from_be_slice(p2_bytes, (cb_p2 * 8) as u32).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid prime2: {err}"),
            )
        })?;

        let priv_key = rsa::PrivateKey::from_primes(vec![p, q], e).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid RSA private key: {err}"),
            )
        })?;
        let actual_bits = priv_key.n().bit_width() as usize;
        if **priv_key.n() != declared_n
            || actual_bits < 3072
            || actual_bits <= (cb_mod - 1) * 8
            || actual_bits > cb_mod * 8
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "RSAPRIVATEBLOB modulus consistency/strength check failed ({actual_bits} bits < 3072)"
                ),
            ));
        }
        Ok(priv_key)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unsupported RSA private key format (expected RSAPRIVATEBLOB with RSA2 magic)",
        ))
    }
}

/// Pure-Rust software RSA keypair generator producing genuine 3072-bit keys in CNG layout (`CNSA 2.0`).
pub fn generate_soc_rsa_keypair_software() -> io::Result<(Vec<u8>, Vec<u8>)> {
    generate_soc_rsa_3072_keypair_software()
}

/// Pure-Rust software RSA-OAEP-SHA256 encryption (enforces RSA >= 3072 bits).
pub fn encrypt_kek_for_soc_escrow_software(
    kek: &[u8; 32],
    soc_rsa_pub_blob: &[u8],
    kek_id: &str,
) -> io::Result<SocEscrowBlob> {
    use rsa::traits::PublicKeyParts;

    let mut fp_hasher = Sha256::new();
    fp_hasher.update(soc_rsa_pub_blob);
    let soc_key_fingerprint = hex_encode(&fp_hasher.finalize()[..16]);

    let pub_key = parse_rsa_public_key(soc_rsa_pub_blob)?;
    let rsa_bits = pub_key.n().bit_width();
    if rsa_bits < 3072 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SOC RSA public key strength ({rsa_bits} bits) must be >= 3072 bits"),
        ));
    }
    let label = format!("SOC-OFFLINE-ESCROW-RECOVERY-V2:{kek_id}")
        .into_bytes()
        .into_boxed_slice();
    let padding =
        rsa::Oaep::<rsa::sha2::Sha256, rsa::sha2::Sha256>::new_with_mgf_hash_and_label(label);

    let mut rng = RsaRngAdapter;
    let ciphertext = pub_key.encrypt(&mut rng, padding, kek).map_err(|e| {
        io::Error::other(format!("RSA-OAEP-SHA256 software encryption failed: {e}"))
    })?;

    Ok(SocEscrowBlob {
        version: 2,
        algorithm: format!("RSA-{rsa_bits}-OAEP-SHA256"),
        kek_id: kek_id.to_string(),
        soc_key_fingerprint,
        rsa_oaep_ciphertext: ciphertext,
    })
}

/// Pure-Rust software RSA-OAEP-SHA256 decryption (enforces RSA >= 3072 bits).
pub fn decrypt_kek_from_soc_escrow_software(
    escrow: &SocEscrowBlob,
    soc_rsa_priv_blob: &[u8],
) -> io::Result<[u8; 32]> {
    use rsa::traits::PublicKeyParts;

    if escrow.version != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unsupported SocEscrowBlob version {} (expected 2)",
                escrow.version
            ),
        ));
    }
    let priv_key = parse_rsa_private_key(soc_rsa_priv_blob)?;
    let rsa_bits = priv_key.n().bit_width();
    if rsa_bits < 3072 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SOC RSA private key strength ({rsa_bits} bits) must be >= 3072 bits"),
        ));
    }
    let expected_alg = format!("RSA-{rsa_bits}-OAEP-SHA256");
    if escrow.algorithm != expected_alg {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unsupported SocEscrowBlob algorithm '{}' (expected '{expected_alg}')",
                escrow.algorithm
            ),
        ));
    }
    if escrow.rsa_oaep_ciphertext.len() < 384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "RSA-OAEP ciphertext length {} is below 3072-bit minimum (384 bytes)",
                escrow.rsa_oaep_ciphertext.len()
            ),
        ));
    }
    let label = format!("SOC-OFFLINE-ESCROW-RECOVERY-V2:{}", escrow.kek_id)
        .into_bytes()
        .into_boxed_slice();
    let padding =
        rsa::Oaep::<rsa::sha2::Sha256, rsa::sha2::Sha256>::new_with_mgf_hash_and_label(label);

    let mut plaintext = priv_key
        .decrypt(padding, &escrow.rsa_oaep_ciphertext)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("RSA-OAEP-SHA256 software decryption failed: {e}"),
            )
        })?;

    if plaintext.len() != 32 {
        zeroize_slice(&mut plaintext);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Decrypted KEK length is {} bytes, expected 32",
                plaintext.len()
            ),
        ));
    }

    let mut kek = [0u8; 32];
    kek.copy_from_slice(&plaintext);
    zeroize_slice(&mut plaintext);
    Ok(kek)
}

/// Generates a genuine 3072-bit RSA keypair in CNG `RSAPUBLICBLOB` / `RSAPRIVATEBLOB` format (`CNSA 2.0` / `Sub-Phase 2.2`).
pub fn generate_soc_rsa_3072_keypair_software() -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = RsaRngAdapter;
    let priv_key = rsa::PrivateKey::new(&mut rng, 3072)
        .map_err(|e| io::Error::other(format!("RSA 3072-bit keypair generation failed: {e}")))?;
    let pub_key = rsa::PublicKey::from(&priv_key);
    let pub_blob = export_rsa_public_key_to_cng(&pub_key);
    let priv_blob = export_rsa_private_key_to_cng(&priv_key)?;
    Ok((pub_blob, priv_blob))
}

/// Generates a NIST FIPS 203 `ML-KEM-768` `(encapsulation_key_1184, decapsulation_key_2400)` pair using `OsRng`.
pub fn generate_mlkem768_keypair() -> (Vec<u8>, Vec<u8>) {
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    type MlKem768Dk = <MlKem768 as KemCore>::DecapsulationKey;
    type MlKem768Ek = <MlKem768 as KemCore>::EncapsulationKey;

    let (dk, ek): (MlKem768Dk, MlKem768Ek) = MlKem768::generate(&mut rand::rngs::OsRng);
    let ek_bytes = ek.as_bytes().as_slice().to_vec();
    let dk_bytes = dk.as_bytes().as_slice().to_vec();
    (ek_bytes, dk_bytes)
}

/// Generates an offline SOC Hybrid Post-Quantum Keypair (`RSA-3072` + `FIPS 203 ML-KEM-768`) for `OCESCROW3`.
pub fn generate_hybrid_soc_keypair_v3(
) -> io::Result<(HybridSocPublicKeyBundle, HybridSocPrivateKeyBundle)> {
    generate_hybrid_soc_keypair_with_bits(3072)
}

/// Generates an offline SOC Hybrid Post-Quantum Keypair with configurable RSA modulus size (`>= 3072` bits) + `ML-KEM-768`.
pub fn generate_hybrid_soc_keypair_with_bits(
    rsa_bits: usize,
) -> io::Result<(HybridSocPublicKeyBundle, HybridSocPrivateKeyBundle)> {
    if rsa_bits < 3072 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Insecure RSA bit length {rsa_bits}: must be >= 3072 bits (CNSA 2.0 / CEA-DEFECT-03)"),
        ));
    }
    let mut rng = RsaRngAdapter;
    let priv_key = rsa::PrivateKey::new(&mut rng, rsa_bits).map_err(|e| {
        io::Error::other(format!("RSA {rsa_bits}-bit keypair generation failed: {e}"))
    })?;
    let pub_key = rsa::PublicKey::from(&priv_key);
    let rsa_public_blob = export_rsa_public_key_to_cng(&pub_key);
    let rsa_private_blob = export_rsa_private_key_to_cng(&priv_key)?;
    let (mlkem768_encapsulation_key, mlkem768_decapsulation_key) = generate_mlkem768_keypair();

    Ok((
        HybridSocPublicKeyBundle {
            version: 3,
            rsa_public_blob,
            mlkem768_encapsulation_key,
        },
        HybridSocPrivateKeyBundle {
            rsa_private_blob,
            mlkem768_decapsulation_key,
        },
    ))
}

fn derive_ocescrow3_wrap_key(
    ss_rsa: &[u8; 32],
    ss_mlkem768: &[u8; 32],
    hkdf_salt: &[u8; 16],
    kek_id: &str,
    ct_rsa: &[u8],
    ct_mlkem768: &[u8],
) -> io::Result<crate::mem_guard::ZeroizingBytes<32>> {
    use hkdf::Hkdf;

    // Concatenate classical + post-quantum shared secrets in pinned zeroizing memory:
    // IKM = ss_rsa (32B) || ss_mlkem768 (32B)
    let mut ikm_raw = [0u8; 64];
    ikm_raw[..32].copy_from_slice(ss_rsa);
    ikm_raw[32..64].copy_from_slice(ss_mlkem768);
    let ikm = crate::mem_guard::ZeroizingBytes::new(ikm_raw);
    zeroize_slice(&mut ikm_raw);

    // Bind both ciphertexts and kek_id into HKDF info for IND-CCA2 hybrid KEM security
    let ct_rsa_hash = Sha256::digest(ct_rsa);
    let ct_mlkem_hash = Sha256::digest(ct_mlkem768);
    let mut info = Vec::with_capacity(32 + kek_id.len() + 64);
    info.extend_from_slice(b"OMNICONNECT-HYBRID-ESCROW-V3|");
    info.extend_from_slice(kek_id.as_bytes());
    info.push(b'|');
    info.extend_from_slice(&ct_rsa_hash);
    info.extend_from_slice(&ct_mlkem_hash);

    let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), ikm.as_slice());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|_| io::Error::other("HKDF-SHA256 expand failed in OCESCROW3 combiner"))?;
    let wrap_key = crate::mem_guard::ZeroizingBytes::new(okm);
    zeroize_slice(&mut okm);
    Ok(wrap_key)
}

/// Encodes an `OCESCROW3` binary wire envelope:
/// `b"OCESCROW3" (9B) || version_u16_le (2B) || hkdf_salt (16B) || aes_nonce (12B) || ct_rsa_len_u32_le (4B) || ct_rsa || ct_mlkem768 (1088B) || wrapped_kek_tag (48B)`.
pub fn encode_ocescrow3_wire(
    hkdf_salt: &[u8; 16],
    aes_nonce: &[u8; 12],
    ct_rsa: &[u8],
    ct_mlkem768: &[u8],
    wrapped_kek_ct: &[u8],
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(
        9 + 2 + 16 + 12 + 4 + ct_rsa.len() + ct_mlkem768.len() + wrapped_kek_ct.len(),
    );
    wire.extend_from_slice(OCESCROW3_MAGIC);
    wire.extend_from_slice(&3u16.to_le_bytes());
    wire.extend_from_slice(hkdf_salt);
    wire.extend_from_slice(aes_nonce);
    wire.extend_from_slice(&(ct_rsa.len() as u32).to_le_bytes());
    wire.extend_from_slice(ct_rsa);
    wire.extend_from_slice(ct_mlkem768);
    wire.extend_from_slice(wrapped_kek_ct);
    wire
}

/// NIST FIPS 202 SHA3-256 (`sha3::Sha3_256` audited RustCrypto primitive, `CSE-28`)
/// for NIST FIPS 203 §7.3 `H(ek)` decapsulation key verification.
pub fn fips202_sha3_256(msg: &[u8]) -> [u8; 32] {
    use sha3::{Digest as _, Sha3_256};
    Sha3_256::digest(msg).into()
}

fn validate_mlkem768_12bit_poly_vec(encoded_1152: &[u8], label: &str) -> io::Result<()> {
    const MLKEM_Q: u16 = 3329;
    if encoded_1152.len() != 1152 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid {label} polynomial vector length: {}",
                encoded_1152.len()
            ),
        ));
    }
    for triple in encoded_1152.as_chunks::<3>().0 {
        let c0 = u16::from(triple[0]) | (u16::from(triple[1] & 0x0F) << 8);
        let c1 = (u16::from(triple[1]) >> 4) | (u16::from(triple[2]) << 4);
        if c0 >= MLKEM_Q || c1 >= MLKEM_Q {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "NIST FIPS 203 modulus check failed on {label}: non-canonical 12-bit coefficient >= q ({MLKEM_Q})"
                ),
            ));
        }
    }
    Ok(())
}

/// Validates a 1184-byte `ML-KEM-768` encapsulation key per **NIST FIPS 203 §7.2**
/// (exact length + 12-bit NTT polynomial coefficients strictly `< q = 3329`).
pub fn validate_fips203_mlkem768_encapsulation_key(ek_bytes: &[u8]) -> io::Result<()> {
    if ek_bytes.len() != MLKEM768_EK_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid ML-KEM-768 encapsulation key length: expected {MLKEM768_EK_LEN}, got {}",
                ek_bytes.len()
            ),
        ));
    }
    validate_mlkem768_12bit_poly_vec(&ek_bytes[0..1152], "ML-KEM-768 encapsulation key")
}

/// Validates a 2400-byte `ML-KEM-768` decapsulation key per **NIST FIPS 203 §7.3**
/// (`dk_pke` 12-bit modulus check, embedded `ek` §7.2 modulus check, and `SHA3-256(ek) == H(ek)` hash check),
/// returning the canonical 1184-byte encapsulation key slice.
pub fn validate_fips203_mlkem768_decapsulation_key(dk_bytes: &[u8]) -> io::Result<Vec<u8>> {
    use p256::elliptic_curve::subtle::ConstantTimeEq;
    if dk_bytes.len() != MLKEM768_DK_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid ML-KEM-768 decapsulation key length: expected {MLKEM768_DK_LEN}, got {}",
                dk_bytes.len()
            ),
        ));
    }
    validate_mlkem768_12bit_poly_vec(&dk_bytes[0..1152], "ML-KEM-768 secret key vector")?;
    let ek_slice = &dk_bytes[1152..2336];
    validate_fips203_mlkem768_encapsulation_key(ek_slice)?;
    let expected_h_ek = fips202_sha3_256(ek_slice);
    let h_matches: bool = dk_bytes[2336..2368].ct_eq(&expected_h_ek).into();
    if !h_matches {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NIST FIPS 203 §7.3 decapsulation key check failed: H(ek) != SHA3-256(ek)",
        ));
    }
    Ok(ek_slice.to_vec())
}

/// Wraps a 32-byte Vault Master KEK into a Hybrid Post-Quantum `OCESCROW3` (`v3`) envelope combining
/// `RSA-OAEP-SHA256` (`>= 2048` / `3072` bits) + `FIPS 203 ML-KEM-768` via `HKDF-SHA256` + `AES-256-GCM`.
pub fn encrypt_kek_for_soc_escrow_hybrid_v3(
    kek: &[u8; 32],
    pub_bundle: &HybridSocPublicKeyBundle,
    kek_id: &str,
) -> io::Result<HybridSocEscrowBlobV3> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Key, Nonce,
    };
    use ml_kem::kem::Encapsulate;
    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
    use rand::RngCore;
    use rsa::traits::PublicKeyParts;

    if pub_bundle.version != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Unsupported HybridSocPublicKeyBundle version {} (expected 3)",
                pub_bundle.version
            ),
        ));
    }
    if kek_id.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "OCESCROW3 kek_id must not be empty",
        ));
    }
    validate_fips203_mlkem768_encapsulation_key(&pub_bundle.mlkem768_encapsulation_key)?;

    // 1. Classical KEM leg: generate fresh 32-byte `ss_rsa` via `OsRng` and encrypt with RSA-OAEP-SHA256
    let rsa_pub = parse_rsa_public_key(&pub_bundle.rsa_public_blob)?;
    let rsa_bits = rsa_pub.n().bit_width();
    if rsa_bits < 3072 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("OCESCROW3 RSA public key strength ({rsa_bits} bits) must be >= 3072 bits"),
        ));
    }
    let mut ss_rsa_raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ss_rsa_raw);
    let ss_rsa = crate::mem_guard::ZeroizingBytes::new(ss_rsa_raw);
    zeroize_slice(&mut ss_rsa_raw);

    let oaep_label = format!("SOC-OFFLINE-ESCROW-HYBRID-V3-RSA:{kek_id}")
        .into_bytes()
        .into_boxed_slice();
    let padding =
        rsa::Oaep::<rsa::sha2::Sha256, rsa::sha2::Sha256>::new_with_mgf_hash_and_label(oaep_label);
    let mut rsa_rng = RsaRngAdapter;
    let ct_rsa = rsa_pub
        .encrypt(&mut rsa_rng, padding, ss_rsa.as_slice())
        .map_err(|e| io::Error::other(format!("OCESCROW3 RSA-OAEP encapsulation failed: {e}")))?;
    if !(384..=1024).contains(&ct_rsa.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "OCESCROW3 RSA ciphertext length {} outside recoverable wire range 384..=1024",
                ct_rsa.len()
            ),
        ));
    }

    // 2. Post-Quantum KEM leg: encapsulate with FIPS 203 ML-KEM-768
    type MlKem768Ek = <MlKem768 as KemCore>::EncapsulationKey;
    let ek_encoded = Encoded::<MlKem768Ek>::try_from(
        pub_bundle.mlkem768_encapsulation_key.as_slice(),
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Failed decoding ML-KEM-768 encapsulation key array",
        )
    })?;
    let ek = MlKem768Ek::from_bytes(&ek_encoded);
    let (ct_mlkem_arr, ss_mlkem_arr) = ek
        .encapsulate(&mut rand::rngs::OsRng)
        .map_err(|_| io::Error::other("ML-KEM-768 encapsulation failed"))?;

    let mut ss_mlkem_raw = [0u8; 32];
    ss_mlkem_raw.copy_from_slice(ss_mlkem_arr.as_slice());
    let ss_mlkem = crate::mem_guard::ZeroizingBytes::new(ss_mlkem_raw);
    zeroize_slice(&mut ss_mlkem_raw);
    let ct_mlkem768 = ct_mlkem_arr.as_slice().to_vec();

    // 3. Hybrid KEM Combiner: K_wrap = HKDF-SHA256(salt, ss_rsa || ss_mlkem768, transcript_info)
    let mut hkdf_salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut hkdf_salt);
    let wrap_key = derive_ocescrow3_wrap_key(
        &ss_rsa,
        &ss_mlkem,
        &hkdf_salt,
        kek_id,
        &ct_rsa,
        &ct_mlkem768,
    )?;

    // 4. Authenticated KEK Wrapping: AES-256-GCM with AAD = "OCESCROW3|<kek_id>"
    let mut aes_nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut aes_nonce);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap_key.as_slice()));
    let aad = format!("OCESCROW3|{kek_id}");
    let wrapped_kek_ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&aes_nonce),
            Payload {
                msg: kek,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| io::Error::other("OCESCROW3 AES-256-GCM KEK wrapping failed"))?;

    let ocescrow3_wire_bytes = encode_ocescrow3_wire(
        &hkdf_salt,
        &aes_nonce,
        &ct_rsa,
        &ct_mlkem768,
        &wrapped_kek_ciphertext,
    );

    let soc_rsa_fingerprint = hex_encode(&Sha256::digest(&pub_bundle.rsa_public_blob)[..16]);
    let soc_mlkem768_fingerprint =
        hex_encode(&Sha256::digest(&pub_bundle.mlkem768_encapsulation_key)[..16]);

    Ok(HybridSocEscrowBlobV3 {
        magic: "OCESCROW3".to_string(),
        version: 3,
        algorithm: format!("OCESCROW3-RSA-{rsa_bits}-OAEP-ML-KEM-768-HKDF-SHA256-AES256GCM"),
        kek_id: kek_id.to_string(),
        soc_rsa_fingerprint,
        soc_mlkem768_fingerprint,
        hkdf_salt: hkdf_salt.to_vec(),
        aes_gcm_nonce: aes_nonce.to_vec(),
        rsa_oaep_ciphertext: ct_rsa,
        mlkem768_ciphertext: ct_mlkem768,
        wrapped_kek_ciphertext,
        ocescrow3_wire_bytes,
    })
}

/// Decrypts a binary `OCESCROW3` wire envelope back into the 32-byte Master KEK using BOTH the
/// offline SOC RSA private key AND the `ML-KEM-768` decapsulation key. Fails closed if either key
/// is wrong or any byte of the envelope/AAD is tampered.
pub fn decrypt_ocescrow3_wire_envelope(
    wire: &[u8],
    kek_id: &str,
    priv_bundle: &HybridSocPrivateKeyBundle,
) -> io::Result<[u8; 32]> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Key, Nonce,
    };
    use ml_kem::kem::Decapsulate;
    use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};

    const HEADER_FIXED: usize = 9 + 2 + 16 + 12 + 4;
    const TRAILER_FIXED: usize = MLKEM768_CT_LEN + 48; // 1088B ML-KEM ct + (32B KEK + 16B GCM tag)
    if wire.len() < HEADER_FIXED + 384 + TRAILER_FIXED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Truncated or sub-3072-bit OCESCROW3 wire envelope ({} bytes)",
                wire.len()
            ),
        ));
    }
    if &wire[0..9] != OCESCROW3_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid OCESCROW3 magic header",
        ));
    }
    let version = u16::from_le_bytes([wire[9], wire[10]]);
    if version != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported OCESCROW3 version {version} (expected 3)"),
        ));
    }

    let mut hkdf_salt = [0u8; 16];
    hkdf_salt.copy_from_slice(&wire[11..27]);
    let mut aes_nonce = [0u8; 12];
    aes_nonce.copy_from_slice(&wire[27..39]);
    let ct_rsa_len = u32::from_le_bytes([wire[39], wire[40], wire[41], wire[42]]) as usize;
    if !(384..=1024).contains(&ct_rsa_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid or sub-3072-bit RSA ciphertext length {ct_rsa_len} in OCESCROW3"),
        ));
    }
    let expected_total = HEADER_FIXED + ct_rsa_len + TRAILER_FIXED;
    if wire.len() != expected_total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "OCESCROW3 envelope length mismatch: expected {expected_total}, got {}",
                wire.len()
            ),
        ));
    }

    let rsa_end = HEADER_FIXED + ct_rsa_len;
    let mlkem_end = rsa_end + MLKEM768_CT_LEN;
    let ct_rsa = &wire[HEADER_FIXED..rsa_end];
    let ct_mlkem = &wire[rsa_end..mlkem_end];
    let wrapped_kek_ct = &wire[mlkem_end..];

    let _ = validate_fips203_mlkem768_decapsulation_key(&priv_bundle.mlkem768_decapsulation_key)?;

    // 1. Classical RSA-OAEP decapsulation
    let rsa_priv = parse_rsa_private_key(&priv_bundle.rsa_private_blob)?;
    let oaep_label = format!("SOC-OFFLINE-ESCROW-HYBRID-V3-RSA:{kek_id}")
        .into_bytes()
        .into_boxed_slice();
    let padding =
        rsa::Oaep::<rsa::sha2::Sha256, rsa::sha2::Sha256>::new_with_mgf_hash_and_label(oaep_label);
    let mut ss_rsa_vec = rsa_priv.decrypt(padding, ct_rsa).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("OCESCROW3 RSA-OAEP decapsulation failed: {e}"),
        )
    })?;
    if ss_rsa_vec.len() != 32 {
        zeroize_slice(&mut ss_rsa_vec);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OCESCROW3 RSA shared secret length mismatch",
        ));
    }
    let mut ss_rsa_arr = [0u8; 32];
    ss_rsa_arr.copy_from_slice(&ss_rsa_vec);
    zeroize_slice(&mut ss_rsa_vec);
    let ss_rsa = crate::mem_guard::ZeroizingBytes::new(ss_rsa_arr);
    zeroize_slice(&mut ss_rsa_arr);

    // 2. Post-Quantum ML-KEM-768 decapsulation
    type MlKem768Dk = <MlKem768 as KemCore>::DecapsulationKey;
    let dk_encoded =
        Encoded::<MlKem768Dk>::try_from(priv_bundle.mlkem768_decapsulation_key.as_slice())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Failed decoding ML-KEM-768 decapsulation key",
                )
            })?;
    let dk = MlKem768Dk::from_bytes(&dk_encoded);
    let ct_mlkem_arr = Ciphertext::<MlKem768>::try_from(ct_mlkem).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid ML-KEM-768 ciphertext slice",
        )
    })?;
    let ss_mlkem_shared = dk.decapsulate(&ct_mlkem_arr).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "ML-KEM-768 decapsulation failed",
        )
    })?;
    let mut ss_mlkem_arr = [0u8; 32];
    ss_mlkem_arr.copy_from_slice(ss_mlkem_shared.as_slice());
    let ss_mlkem = crate::mem_guard::ZeroizingBytes::new(ss_mlkem_arr);
    zeroize_slice(&mut ss_mlkem_arr);

    // 3. Hybrid HKDF-SHA256 combiner
    let wrap_key =
        derive_ocescrow3_wrap_key(&ss_rsa, &ss_mlkem, &hkdf_salt, kek_id, ct_rsa, ct_mlkem)?;

    // 4. AES-256-GCM authenticated unwrap
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap_key.as_slice()));
    let aad = format!("OCESCROW3|{kek_id}");
    let mut plain = cipher
        .decrypt(
            Nonce::from_slice(&aes_nonce),
            Payload {
                msg: wrapped_kek_ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OCESCROW3 AES-256-GCM authentication tag verification failed (key mismatch or tampered ciphertext)",
            )
        })?;

    if plain.len() != 32 {
        zeroize_slice(&mut plain);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OCESCROW3 unwrapped KEK length != 32",
        ));
    }
    let mut out_kek = [0u8; 32];
    out_kek.copy_from_slice(&plain);
    zeroize_slice(&mut plain);
    Ok(out_kek)
}

/// Decrypts a structured `HybridSocEscrowBlobV3` after cross-checking consistency between its
/// JSON fields and its canonical `OCESCROW3` binary wire envelope (`fail-closed` on any mismatch).
pub fn decrypt_kek_from_soc_escrow_hybrid_v3(
    escrow: &HybridSocEscrowBlobV3,
    priv_bundle: &HybridSocPrivateKeyBundle,
) -> io::Result<[u8; 32]> {
    use p256::elliptic_curve::subtle::ConstantTimeEq;
    use rsa::traits::PublicKeyParts;

    if escrow.magic != "OCESCROW3" || escrow.version != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid HybridSocEscrowBlobV3 header: magic='{}', version={}",
                escrow.magic, escrow.version
            ),
        ));
    }
    if escrow.hkdf_salt.len() != 16 || escrow.aes_gcm_nonce.len() != 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid salt or nonce length in HybridSocEscrowBlobV3",
        ));
    }

    // Authenticate `algorithm`, `soc_rsa_fingerprint`, and `soc_mlkem768_fingerprint` against `priv_bundle`
    let rsa_priv = parse_rsa_private_key(&priv_bundle.rsa_private_blob)?;
    let rsa_pub = rsa::PublicKey::from(&rsa_priv);
    let rsa_bits = rsa_pub.n().bit_width();
    let expected_algorithm =
        format!("OCESCROW3-RSA-{rsa_bits}-OAEP-ML-KEM-768-HKDF-SHA256-AES256GCM");
    if escrow.algorithm != expected_algorithm {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "HybridSocEscrowBlobV3 algorithm metadata mismatch: expected '{expected_algorithm}', found '{}'",
                escrow.algorithm
            ),
        ));
    }
    let expected_rsa_pub_blob = export_rsa_public_key_to_cng(&rsa_pub);
    let expected_rsa_fp = hex_encode(&Sha256::digest(&expected_rsa_pub_blob)[..16]);
    let ek_bytes =
        validate_fips203_mlkem768_decapsulation_key(&priv_bundle.mlkem768_decapsulation_key)?;
    let expected_mlkem_fp = hex_encode(&Sha256::digest(&ek_bytes)[..16]);

    let rsa_fp_ok = escrow.soc_rsa_fingerprint.len() == expected_rsa_fp.len()
        && bool::from(
            escrow
                .soc_rsa_fingerprint
                .as_bytes()
                .ct_eq(expected_rsa_fp.as_bytes()),
        );
    let mlkem_fp_ok = escrow.soc_mlkem768_fingerprint.len() == expected_mlkem_fp.len()
        && bool::from(
            escrow
                .soc_mlkem768_fingerprint
                .as_bytes()
                .ct_eq(expected_mlkem_fp.as_bytes()),
        );
    if !rsa_fp_ok || !mlkem_fp_ok {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HybridSocEscrowBlobV3 key fingerprint metadata mismatch (tampered or wrong key bundle)",
        ));
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&escrow.hkdf_salt);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&escrow.aes_gcm_nonce);
    let expected_wire = encode_ocescrow3_wire(
        &salt,
        &nonce,
        &escrow.rsa_oaep_ciphertext,
        &escrow.mlkem768_ciphertext,
        &escrow.wrapped_kek_ciphertext,
    );
    if escrow.ocescrow3_wire_bytes != expected_wire {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HybridSocEscrowBlobV3 field-to-wire integrity mismatch (empty or tampered wire envelope)",
        ));
    }
    decrypt_ocescrow3_wire_envelope(&expected_wire, &escrow.kek_id, priv_bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_t26a_ecdsa_p256_genuine_asymmetric_and_adversarial_rejection(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (pub_blob, priv_blob) = generate_ecdsa_p256_keypair_software()?;
        assert_eq!(pub_blob.len(), 72);
        assert_eq!(&pub_blob[0..4], b"ECS1");
        assert_eq!(priv_blob.len(), 104);
        assert_eq!(&priv_blob[0..4], b"ECS2");

        let msg = b"OmniConnect Sentinel Audit Record #42: USB Insertion Detected";
        let digest: [u8; 32] = Sha256::digest(msg).into();

        // 1. Genuine signing and verification
        let sig = sign_ecdsa_p256_digest_software(&priv_blob, &digest)?;
        assert_eq!(sig.len(), 64);

        // Verification with 72-byte ECS1 public blob
        let verified = verify_ecdsa_p256_digest(&pub_blob, &digest, &sig)?;
        assert!(
            verified,
            "genuine signature must verify with ECS1 public key"
        );

        // Verification with 65-byte uncompressed SEC1 public key
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&pub_blob[8..40]);
        sec1[33..65].copy_from_slice(&pub_blob[40..72]);
        let verified_sec1 = verify_ecdsa_p256_digest(&sec1, &digest, &sig)?;
        assert!(
            verified_sec1,
            "genuine signature must verify with SEC1 public key"
        );

        // 2. Adversarial Test: Fake Unix signature shortcut from CSE-01 MUST BE REJECTED
        let pub_x = &pub_blob[8..40];
        let mut fake_hasher = Sha256::new();
        fake_hasher.update(b"ECDSA-P256-UNIX-SIG:");
        fake_hasher.update(pub_x);
        fake_hasher.update(digest);
        let fake_d = fake_hasher.finalize();
        let mut fake_sig = [0u8; 64];
        fake_sig[..32].copy_from_slice(&fake_d);
        fake_sig[32..].copy_from_slice(&fake_d);

        let fake_verified = verify_ecdsa_p256_digest(&pub_blob, &digest, &fake_sig)?;
        assert!(
            !fake_verified,
            "CRITICAL: fake SHA256 signature shortcut must be rejected!"
        );

        // 3. Adversarial Test: 1-bit mutation in signature must fail verification
        for bit_pos in [0, 15, 31, 32, 47, 63] {
            let mut tampered_sig = sig.clone();
            tampered_sig[bit_pos] ^= 0x01;
            let res = verify_ecdsa_p256_digest(&pub_blob, &digest, &tampered_sig).unwrap_or(false);
            assert!(
                !res,
                "Tampered signature at byte {bit_pos} must be rejected"
            );
        }

        // 4. Adversarial Test: 1-bit mutation in digest must fail verification
        for bit_pos in [0, 7, 15, 23, 31] {
            let mut tampered_digest = digest;
            tampered_digest[bit_pos] ^= 0x01;
            let res = verify_ecdsa_p256_digest(&pub_blob, &tampered_digest, &sig).unwrap_or(false);
            assert!(!res, "Tampered digest at byte {bit_pos} must be rejected");
        }

        // 5. Adversarial Test: Wrong public key must fail verification
        let (other_pub, _) = generate_ecdsa_p256_keypair_software()?;
        let wrong_key_verified =
            verify_ecdsa_p256_digest(&other_pub, &digest, &sig).unwrap_or(false);
        assert!(
            !wrong_key_verified,
            "Signature must not verify under a different public key"
        );
        Ok(())
    }

    #[test]
    fn test_rsa_imports() -> Result<(), Box<dyn std::error::Error>> {
        use rsa::sha2::Sha256;
        use rsa::{Oaep, PrivateKey, PublicKey};

        let mut rng = RsaRngAdapter;
        let priv_key = PrivateKey::new(&mut rng, 3072)?;
        let pub_key = PublicKey::from(&priv_key);
        let label = b"SOC-OFFLINE-ESCROW-RECOVERY-V2:test-kek"
            .to_vec()
            .into_boxed_slice();
        let padding = Oaep::<Sha256, Sha256>::new_with_mgf_hash_and_label(label.clone());
        let msg = [42u8; 32];
        let ct = pub_key.encrypt(&mut rng, padding, &msg)?;
        let padding_dec = Oaep::<Sha256, Sha256>::new_with_mgf_hash_and_label(label);
        let pt = priv_key.decrypt(padding_dec, &ct)?;
        assert_eq!(pt, msg);

        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        let n_bytes = priv_key.n().to_be_bytes();
        let _e_bytes = priv_key.e().to_be_bytes();
        let _d_bytes = priv_key.d().to_be_bytes();
        let primes = priv_key.primes();
        assert_eq!(n_bytes.len(), 384);
        assert_eq!(primes.len(), 2);
        Ok(())
    }

    #[test]
    fn test_t26b_unix_ocsl2_aead_adversarial() -> Result<(), Box<dyn std::error::Error>> {
        let master_secret = [0x5Au8; 32];
        let raw_key = [0x42u8; 32];
        let entropy = b"EntropyTag-NonceBinding-2026";
        let kek_id = "test-kek-ledger-01";

        // 1. Legitimate seal and unseal
        let sealed =
            unix_authenticated_seal_with_secret(&raw_key, &master_secret, entropy, kek_id)?;
        assert!(sealed.starts_with(b"OCSL2"));
        assert!(sealed.len() >= 5 + 16 + 12 + 32 + 16);

        let unsealed =
            unix_authenticated_unseal_with_secret(&sealed, &master_secret, entropy, kek_id)?;
        assert_eq!(unsealed, raw_key);

        // 2. Tampered ciphertext (AEAD authentication tag failure)
        let mut tampered_ct = sealed.clone();
        let last_idx = tampered_ct.len() - 1;
        tampered_ct[last_idx] ^= 0x01;
        assert!(
            unix_authenticated_unseal_with_secret(&tampered_ct, &master_secret, entropy, kek_id)
                .is_err(),
            "Tampered ciphertext or tag must fail AEAD verification"
        );

        // 3. Tampered salt
        let mut tampered_salt = sealed.clone();
        tampered_salt[5] ^= 0x01;
        assert!(
            unix_authenticated_unseal_with_secret(&tampered_salt, &master_secret, entropy, kek_id)
                .is_err(),
            "Tampered salt must fail AEAD verification"
        );

        // 4. Tampered nonce
        let mut tampered_nonce = sealed.clone();
        tampered_nonce[21] ^= 0x01;
        assert!(
            unix_authenticated_unseal_with_secret(&tampered_nonce, &master_secret, entropy, kek_id)
                .is_err(),
            "Tampered nonce must fail AEAD verification"
        );

        // 5. Wrong entropy (AAD mismatch)
        assert!(
            unix_authenticated_unseal_with_secret(&sealed, &master_secret, b"WrongEntropy", kek_id)
                .is_err(),
            "Mismatched entropy tag in AAD must fail unseal"
        );

        // 6. Wrong kek_id (AAD mismatch)
        assert!(
            unix_authenticated_unseal_with_secret(&sealed, &master_secret, entropy, "wrong-kek-id")
                .is_err(),
            "Mismatched kek_id in AAD must fail unseal"
        );

        // 7. Wrong master secret
        let wrong_secret = [0x6Bu8; 32];
        assert!(
            unix_authenticated_unseal_with_secret(&sealed, &wrong_secret, entropy, kek_id).is_err(),
            "Wrong master secret must fail unseal"
        );
        Ok(())
    }

    #[test]
    fn test_cse28_audited_sha3_hkdf_no_sha1_oaep_and_linux_key_posture(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. SHA-1 RSA-OAEP fallback MUST be absent from TPM OAEP candidate list
        assert!(!TPM_OAEP_ALLOWED_ALGORITHMS.is_empty());
        assert!(
            TPM_OAEP_ALLOWED_ALGORITHMS
                .iter()
                .all(|(alg, _)| *alg == "SHA256"),
            "TPM OAEP must permit SHA-256 exclusively (zero SHA-1 fallback)"
        );

        // 2. Audited sha3::Sha3_256 matches official NIST FIPS 202 KAT vectors
        assert_eq!(
            hex_encode(&fips202_sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex_encode(&fips202_sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );

        // 3. Audited hkdf::Hkdf<Sha256> matches official RFC 5869 Appendix A.1 Test Case 1 (first 32 bytes)
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = hkdf_sha256_derive_32(&ikm, &salt, &info)?;
        assert_eq!(
            hex_encode(okm.as_slice()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );

        // Empty-salt RFC 5869 equivalence (`None` == 32 zero bytes)
        let okm_empty = hkdf_sha256_derive_32(&ikm, &[], &info)?;
        let okm_zero32 = hkdf_sha256_derive_32(&ikm, &[0u8; 32], &info)?;
        assert_eq!(okm_empty.as_slice(), okm_zero32.as_slice());

        // 4. Linux key sealing priority: TPM2 -> LinuxKernelKeyring -> UnixLocalKeyring (file fallback)
        assert_eq!(
            resolve_linux_key_sealing_backend(true, true),
            (KeyProtectionPosture::Tpm2Assisted, None)
        );
        assert_eq!(
            resolve_linux_key_sealing_backend(false, true),
            (
                KeyProtectionPosture::LinuxKernelKeyring,
                Some("POSTURE_REDUCED_NO_TPM")
            )
        );
        assert_eq!(
            resolve_linux_key_sealing_backend(false, false),
            (
                KeyProtectionPosture::UnixLocalKeyring,
                Some("POSTURE_REDUCED_NO_TPM")
            )
        );

        // 5. Strict kiosk key posture enforcement: refuses file-backed UnixLocalKeyring fail-closed
        assert!(evaluate_strict_kiosk_key_posture(KeyProtectionPosture::Tpm2Assisted).is_ok());
        assert!(evaluate_strict_kiosk_key_posture(KeyProtectionPosture::DpapiLocalMachine).is_ok());
        assert!(
            evaluate_strict_kiosk_key_posture(KeyProtectionPosture::LinuxKernelKeyring).is_ok()
        );
        let refused = evaluate_strict_kiosk_key_posture(KeyProtectionPosture::UnixLocalKeyring);
        assert!(
            refused.is_err(),
            "File-backed UnixLocalKeyring must be refused in strict kiosk mode"
        );
        assert!(refused
            .err()
            .unwrap_or_default()
            .contains("POSTURE_REDUCED_NO_TPM"));
        Ok(())
    }
}
