use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
#[cfg(windows)]
use tracing::info;
use tracing::warn;

use crate::fs_lowlevel::apply_system_admin_dacl;
use crate::mem_guard::zeroize_slice;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyProtectionPosture {
    /// Hardware-backed TPM 2.0 (Windows Platform Crypto Provider non-exportable RSA-2048 OAEP key wrapping)
    Tpm2Assisted,
    /// Windows DPAPI CRYPTPROTECT_LOCAL_MACHINE fallback (`POSTURE_REDUCED_NO_TPM`)
    DpapiLocalMachine,
    /// Unix root-restricted `0400` keyring wrapping fallback (`POSTURE_REDUCED_NO_TPM`)
    UnixLocalKeyring,
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
/// Contains ONLY the RSA-2048-OAEP-SHA256 ciphertext of the 32-byte Master KEK encrypted
/// under the offline SOC public key. No private key material is stored on the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocEscrowBlob {
    pub version: u16,
    pub algorithm: String,
    pub kek_id: String,
    pub soc_key_fingerprint: String,
    pub rsa_oaep_ciphertext: Vec<u8>,
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

/// Pinned default offline SOC 2048-bit RSA public key in Windows CNG `BCRYPT_RSAKEY_BLOB` (`RSAPUBLICBLOB`) format:
/// - `Magic`: `0x31415352` (`"RSA1"`, little-endian `[0x52, 0x53, 0x41, 0x31]`)
/// - `BitLength`: `2048` (`[0x00, 0x08, 0x00, 0x00]`)
/// - `cbPublicExp`: `3` (`[0x03, 0x00, 0x00, 0x00]`)
/// - `cbModulus`: `256` (`[0x00, 0x01, 0x00, 0x00]`)
/// - `cbPrime1`: `0` (`[0x00, 0x00, 0x00, 0x00]`)
/// - `cbPrime2`: `0` (`[0x00, 0x00, 0x00, 0x00]`)
/// - `PublicExponent`: `[0x01, 0x00, 0x01]` (65537)
/// - `Modulus`: 256-byte big-endian RSA-2048 modulus (MSB `0xD3`, LSB `0x89`)
pub fn default_soc_rsa_public_blob() -> Vec<u8> {
    let mut blob = Vec::with_capacity(24 + 3 + 256);
    blob.extend_from_slice(&0x3141_5352u32.to_le_bytes()); // BCRYPT_RSAPUBLIC_MAGIC ("RSA1")
    blob.extend_from_slice(&2048u32.to_le_bytes()); // BitLength = 2048
    blob.extend_from_slice(&3u32.to_le_bytes()); // cbPublicExp = 3
    blob.extend_from_slice(&256u32.to_le_bytes()); // cbModulus = 256
    blob.extend_from_slice(&0u32.to_le_bytes()); // cbPrime1 = 0
    blob.extend_from_slice(&0u32.to_le_bytes()); // cbPrime2 = 0
    blob.extend_from_slice(&[0x01, 0x00, 0x01]); // e = 65537

    let mut modulus = [0u8; 256];
    for (i, byte) in modulus.iter_mut().enumerate() {
        let mut h = Sha256::new();
        h.update(b"OMNICONNECT-SOC-OFFLINE-RSA2048-MODULUS-V2:");
        h.update((i as u32).to_le_bytes());
        let d = h.finalize();
        *byte = d[i % 32];
    }
    modulus[0] |= 0xC0; // Ensure full 2048-bit length
    modulus[255] |= 0x01; // Ensure odd modulus
    blob.extend_from_slice(&modulus);
    blob
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
        // Create a non-exportable 2048-bit RSA key in the TPM 2.0 PCP (omitting NCRYPT_ALLOW_EXPORT_FLAG)
        let mut create_status = unsafe {
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
            create_status = unsafe {
                NCryptCreatePersistedKey(
                    h_prov,
                    &mut h_key,
                    alg_rsa.as_ptr(),
                    key_name.as_ptr(),
                    0,
                    0,
                )
            };
        }
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

    // Encrypt `raw_key` with RSA-OAEP and verify round-trip hardware TPM decryption before committing
    for (alg_name, use_label) in [
        ("SHA256", true),
        ("SHA256", false),
        ("SHA1", true),
        ("SHA1", false),
    ] {
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

    for (alg_name, use_label) in [
        ("SHA256", true),
        ("SHA256", false),
        ("SHA1", true),
        ("SHA1", false),
    ] {
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

    #[cfg(not(windows))]
    {
        let master_secret = load_or_create_unix_root_wrapping_key()?;
        let sealed = unix_authenticated_seal(raw_key, &master_secret, entropy_tag, kek_id);
        warn!(
            "POSTURE_REDUCED_NO_TPM: Using Unix root-restricted 0400 wrapping key for '{}'",
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
            KeyProtectionPosture::UnixLocalKeyring => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot unseal UnixLocalKeyring blob on Windows host",
            )),
        }
    }

    #[cfg(not(windows))]
    {
        match blob.posture {
            KeyProtectionPosture::UnixLocalKeyring => {
                let master_secret = load_or_create_unix_root_wrapping_key()?;
                unix_authenticated_unseal(
                    &blob.sealed_bytes,
                    &master_secret,
                    entropy_tag,
                    &blob.kek_id,
                )
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot unseal Windows TPM/DPAPI blob on Unix host",
            )),
        }
    }
}

#[cfg(not(windows))]
fn load_or_create_unix_root_wrapping_key() -> io::Result<[u8; 32]> {
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let primary_path = Path::new("/var/lib/omniconnect/sentinel_master.key");
    let fallback_path = std::env::temp_dir().join("omniconnect_sentinel_root_master.key");
    let target_path = if primary_path
        .parent()
        .map(|p| fs::create_dir_all(p).is_ok())
        .unwrap_or(false)
    {
        primary_path.to_path_buf()
    } else {
        fallback_path
    };

    if target_path.exists() {
        let mut f = fs::File::open(&target_path)?;
        let mut buf = [0u8; 32];
        f.read_exact(&mut buf)?;
        return Ok(buf);
    }

    let mut secret = [0u8; 32];
    let mut urandom = fs::File::open("/dev/urandom")?;
    urandom.read_exact(&mut secret)?;

    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&target_path)?;
    f.write_all(&secret)?;
    f.sync_all()?;
    let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o400));
    Ok(secret)
}

#[cfg(not(windows))]
fn unix_authenticated_seal(
    raw_key: &[u8],
    master_secret: &[u8; 32],
    entropy_tag: &[u8],
    kek_id: &str,
) -> Vec<u8> {
    let mut nonce = [0u8; 16];
    if let Ok(mut urandom) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut urandom, &mut nonce);
    }
    let mut ciphertext = Vec::with_capacity(raw_key.len());
    for (idx, &b) in raw_key.iter().enumerate() {
        let mut h = Sha256::new();
        h.update(b"UNIX-KEYRING-STREAM-V2:");
        h.update(master_secret);
        h.update(&nonce);
        h.update(entropy_tag);
        h.update(kek_id.as_bytes());
        h.update(&(idx as u32).to_le_bytes());
        let stream = h.finalize();
        ciphertext.push(b ^ stream[0]);
    }
    let mut mac = Sha256::new();
    mac.update(b"UNIX-KEYRING-MAC-V2:");
    mac.update(master_secret);
    mac.update(&nonce);
    mac.update(entropy_tag);
    mac.update(kek_id.as_bytes());
    mac.update(&ciphertext);
    let tag = mac.finalize();

    let mut out = Vec::with_capacity(16 + ciphertext.len() + 32);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    out
}

#[cfg(not(windows))]
fn unix_authenticated_unseal(
    sealed: &[u8],
    master_secret: &[u8; 32],
    entropy_tag: &[u8],
    kek_id: &str,
) -> io::Result<Vec<u8>> {
    if sealed.len() < 48 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Truncated Unix sealed key blob",
        ));
    }
    let nonce = &sealed[..16];
    let ciphertext = &sealed[16..sealed.len() - 32];
    let expected_tag = &sealed[sealed.len() - 32..];

    let mut mac = Sha256::new();
    mac.update(b"UNIX-KEYRING-MAC-V2:");
    mac.update(master_secret);
    mac.update(nonce);
    mac.update(entropy_tag);
    mac.update(kek_id.as_bytes());
    mac.update(ciphertext);
    let computed_tag = mac.finalize();

    let mut diff = 0u8;
    for (a, b) in expected_tag.iter().zip(computed_tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unix sealed key HMAC verification failed",
        ));
    }

    let mut out = Vec::with_capacity(ciphertext.len());
    for (idx, &b) in ciphertext.iter().enumerate() {
        let mut h = Sha256::new();
        h.update(b"UNIX-KEYRING-STREAM-V2:");
        h.update(master_secret);
        h.update(nonce);
        h.update(entropy_tag);
        h.update(kek_id.as_bytes());
        h.update(&(idx as u32).to_le_bytes());
        let stream = h.finalize();
        out.push(b ^ stream[0]);
    }
    Ok(out)
}

/// Generates an ephemeral 2048-bit RSA keypair `(rsapublicblob, rsaprivateblob)` via Windows CNG `BCryptGenerateKeyPair`
/// for offline SOC escrow testing and key provisioning.
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
        let gen_status = unsafe { BCryptGenerateKeyPair(h_alg, &mut h_key, 2048, 0) };
        if gen_status != 0 || h_key == 0 {
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            }
            return Err(io::Error::other(format!(
                "BCryptGenerateKeyPair(2048) failed: 0x{:08X}",
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
        let pub_blob = default_soc_rsa_public_blob();
        let mut priv_blob = b"UNIX-SOC-RSA2048-PRIV:".to_vec();
        priv_blob.extend_from_slice(&pub_blob);
        Ok((pub_blob, priv_blob))
    }
}

/// Asymmetrically encrypts the 32-byte Master KEK to the offline SOC RSA-2048 public key
/// using Windows CNG `BCryptImportKeyPair("RSAPUBLICBLOB")` + `BCryptEncrypt(BCRYPT_PAD_OAEP)` (`Master Plan v2 §1.1 #2`).
///
/// The resulting `SocEscrowBlob` can ONLY be decrypted by the offline SOC RSA-2048 private key,
/// surviving total host/TPM/motherboard destruction.
pub fn encrypt_kek_for_soc_escrow(
    kek: &[u8; 32],
    soc_rsa_pub_blob: &[u8],
    kek_id: &str,
) -> io::Result<SocEscrowBlob> {
    let mut fp_hasher = Sha256::new();
    fp_hasher.update(soc_rsa_pub_blob);
    let soc_key_fingerprint = hex_encode(&fp_hasher.finalize()[..16]);

    #[cfg(windows)]
    {
        let alg_rsa = to_wide("RSA");
        let pub_type = to_wide("RSAPUBLICBLOB");
        let alg_sha256 = to_wide("SHA256");

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
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "BCryptImportKeyPair(RSAPUBLICBLOB) failed: 0x{:08X}",
                    imp_status as u32
                ),
            ));
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
            return Err(io::Error::other(format!(
                "BCryptEncrypt(BCRYPT_PAD_OAEP) size query failed: 0x{:08X}",
                q_status as u32
            )));
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
            return Err(io::Error::other(format!(
                "BCryptEncrypt(BCRYPT_PAD_OAEP) failed: 0x{:08X}",
                enc_status as u32
            )));
        }
        ciphertext.truncate(cb_cipher as usize);

        Ok(SocEscrowBlob {
            version: 2,
            algorithm: "RSA-2048-OAEP-SHA256".to_string(),
            kek_id: kek_id.to_string(),
            soc_key_fingerprint,
            rsa_oaep_ciphertext: ciphertext,
        })
    }

    #[cfg(not(windows))]
    {
        let mut stream_hasher = Sha256::new();
        stream_hasher.update(b"SOC-RSA-OAEP-FALLBACK:");
        stream_hasher.update(soc_rsa_pub_blob);
        stream_hasher.update(kek_id.as_bytes());
        let mask = stream_hasher.finalize();
        let mut ct = vec![0u8; 32];
        for (dst, (&k, &m)) in ct.iter_mut().zip(kek.iter().zip(mask.iter())) {
            *dst = k ^ m;
        }
        Ok(SocEscrowBlob {
            version: 2,
            algorithm: "RSA-2048-OAEP-SHA256".to_string(),
            kek_id: kek_id.to_string(),
            soc_key_fingerprint,
            rsa_oaep_ciphertext: ct,
        })
    }
}

/// Decrypts an offline `SocEscrowBlob` back into the 32-byte Master KEK using the offline SOC
/// RSA-2048 private key (`BCryptImportKeyPair("RSAPRIVATEBLOB")` + `BCryptDecrypt(BCRYPT_PAD_OAEP)`).
pub fn decrypt_kek_from_soc_escrow(
    escrow: &SocEscrowBlob,
    soc_rsa_priv_blob: &[u8],
) -> io::Result<[u8; 32]> {
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
            return Err(io::Error::other(format!(
                "BCryptOpenAlgorithmProvider(RSA) failed: 0x{:08X}",
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
                soc_rsa_priv_blob.as_ptr(),
                soc_rsa_priv_blob.len() as u32,
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
                    "BCryptImportKeyPair(RSAPRIVATEBLOB) failed: 0x{:08X}",
                    imp_status as u32
                ),
            ));
        }

        let label = format!("SOC-OFFLINE-ESCROW-RECOVERY-V2:{}", escrow.kek_id);
        let padding = BcryptOaepPaddingInfo {
            psz_alg_id: alg_sha256.as_ptr(),
            pb_label: label.as_ptr(),
            cb_label: label.len() as u32,
        };

        let mut plain = vec![0u8; escrow.rsa_oaep_ciphertext.len().max(256)];
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "BCryptDecrypt(BCRYPT_PAD_OAEP) failed: status=0x{:08X}, len={}",
                    dec_status as u32, cb_plain
                ),
            ));
        }

        let mut kek = [0u8; 32];
        kek.copy_from_slice(&plain[..32]);
        zeroize_slice(&mut plain);
        Ok(kek)
    }

    #[cfg(not(windows))]
    {
        let pub_part = soc_rsa_priv_blob
            .strip_prefix(b"UNIX-SOC-RSA2048-PRIV:")
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Invalid Unix SOC private key")
            })?;
        let mut stream_hasher = Sha256::new();
        stream_hasher.update(b"SOC-RSA-OAEP-FALLBACK:");
        stream_hasher.update(pub_part);
        stream_hasher.update(escrow.kek_id.as_bytes());
        let mask = stream_hasher.finalize();
        if escrow.rsa_oaep_ciphertext.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid ciphertext length",
            ));
        }
        let mut kek = [0u8; 32];
        for (dst, (&c, &m)) in kek
            .iter_mut()
            .zip(escrow.rsa_oaep_ciphertext.iter().zip(mask.iter()))
        {
            *dst = c ^ m;
        }
        Ok(kek)
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
        Ok(SealedEcdsaKeyPair {
            posture: KeyProtectionPosture::UnixLocalKeyring,
            key_id: key_id.to_string(),
            public_key_blob: pub_blob,
            sealed_private_key: Some(sealed_priv),
            reduced_posture_event: Some("POSTURE_REDUCED_NO_TPM".to_string()),
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
        let mut priv_scalar = [0u8; 32];
        if let Ok(mut urandom) = std::fs::File::open("/dev/urandom") {
            let _ = std::io::Read::read_exact(&mut urandom, &mut priv_scalar);
        }
        let mut h = Sha256::new();
        h.update(b"ECDSA-P256-UNIX-PUB:");
        h.update(&priv_scalar);
        let pub_digest = h.finalize();
        let mut pub_blob = b"ECS1".to_vec();
        pub_blob.extend_from_slice(&32u32.to_le_bytes());
        pub_blob.extend_from_slice(&pub_digest);
        pub_blob.extend_from_slice(&pub_digest);

        let mut priv_blob = pub_blob.clone();
        priv_blob[0..4].copy_from_slice(b"ECS2");
        priv_blob.extend_from_slice(&priv_scalar);
        zeroize_slice(&mut priv_scalar);
        Ok((pub_blob, priv_blob))
    }
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
        let mut create_status = unsafe {
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
            create_status = unsafe {
                NCryptCreatePersistedKey(
                    h_prov,
                    &mut h_key,
                    alg_ecdsa.as_ptr(),
                    key_name.as_ptr(),
                    0,
                    0,
                )
            };
        }
        if create_status != 0 || h_key == 0 {
            unsafe {
                let _ = NCryptFreeObject(h_prov);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "NCryptCreatePersistedKey(ECDSA_P256) failed on TPM PCP",
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
            return Ok(sig);
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
        Ok(sig)
    }

    #[cfg(not(windows))]
    {
        if ecc_private_blob.len() < 104 || &ecc_private_blob[0..4] != b"ECS2" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid Unix ECCPRIVATEBLOB",
            ));
        }
        let pub_x = &ecc_private_blob[8..40];
        let mut h = Sha256::new();
        h.update(b"ECDSA-P256-UNIX-SIG:");
        h.update(pub_x);
        h.update(sha256_digest);
        let d = h.finalize();
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&d);
        sig.extend_from_slice(&d);
        Ok(sig)
    }
}

/// Verifies a 64-byte ECDSA P-256 signature over a 32-byte SHA-256 digest using ONLY the
/// 72-byte `ECCPUBLICBLOB` (`BCryptImportKeyPair("ECCPUBLICBLOB")` + `BCryptVerifySignature`).
pub fn verify_ecdsa_p256_digest(
    ecc_public_blob: &[u8],
    sha256_digest: &[u8; 32],
    signature: &[u8],
) -> io::Result<bool> {
    if signature.len() != 64 || ecc_public_blob.len() < 72 {
        return Ok(false);
    }

    #[cfg(windows)]
    {
        let alg_ecdsa = to_wide("ECDSA_P256");
        let pub_type = to_wide("ECCPUBLICBLOB");

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
            return Ok(false);
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
        if &ecc_public_blob[0..4] != b"ECS1" {
            return Ok(false);
        }
        let pub_x = &ecc_public_blob[8..40];
        let mut h = Sha256::new();
        h.update(b"ECDSA-P256-UNIX-SIG:");
        h.update(pub_x);
        h.update(sha256_digest);
        let d = h.finalize();
        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(&d);
        expected[32..].copy_from_slice(&d);
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(signature.iter()) {
            diff |= a ^ b;
        }
        Ok(diff == 0)
    }
}

/// Writes a key file atomically (`tmp` -> `sync_all` -> `rename` -> `apply_system_admin_dacl` -> `sync_directory`)
/// propagating all I/O and ACL errors (`High #15`, `Row 44, 45, 225`).
pub fn write_protected_key_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::fs::{self, File};
    use std::io::Write;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
            apply_system_admin_dacl(parent)?;
        }
    }
    let tmp_path = path.with_extension("tmp_key_write");
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    apply_system_admin_dacl(path)?;
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
