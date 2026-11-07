use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use thiserror::Error;

use sentinel_sys::{sign_ecdsa_p256_with_private_blob, verify_ecdsa_p256_digest};

/// Typed Enterprise Error with Stable Codes (Master Plan v2 §0.3, Row 33)
#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("[SNTL-ERR-001] Mount posture violation (MOUNT_POSTURE_VIOLATION): {0}")]
    MountPostureViolation(String),

    #[error("[SNTL-ERR-002] Quarantine vault integrity failure (VAULT_INTEGRITY_FAIL): {0}")]
    QuarantineIntegrityFail(String),

    #[error("[SNTL-ERR-003] Secure shred operation failed (SHRED_OPERATION_FAILED): {0}")]
    ShredOperationFailed(String),

    #[error("[SNTL-ERR-004] Directory walk / file access error (WALK_ACCESS_DENIED): {0}")]
    WalkAccessDenied(String),

    #[error("[SNTL-ERR-005] Isolated CDR worker failure (CDR_WORKER_FAILED): {0}")]
    CdrWorkerFailed(String),

    #[error("[SNTL-ERR-006] Shadow cache quota exceeded (CACHE_QUOTA_EXCEEDED): {0}")]
    CacheQuotaExceeded(String),

    #[error(
        "[SNTL-ERR-007] Policy signature or monotonic version rejected (POLICY_REJECTED): {0}"
    )]
    PolicySignatureInvalid(String),

    #[error("[SNTL-ERR-008] Audit ledger hash chain tampered (LEDGER_TAMPERED): {0}")]
    LedgerTampered(String),

    #[error("[SNTL-ERR-009] I/O error (IO_ERROR): {0}")]
    IoError(#[from] std::io::Error),
}

impl SentinelError {
    /// Stable numeric error code (`SNTL-ERR-001` .. `SNTL-ERR-009`) (`Row 33`).
    pub fn numeric_code(&self) -> &'static str {
        match self {
            SentinelError::MountPostureViolation(_) => "SNTL-ERR-001",
            SentinelError::QuarantineIntegrityFail(_) => "SNTL-ERR-002",
            SentinelError::ShredOperationFailed(_) => "SNTL-ERR-003",
            SentinelError::WalkAccessDenied(_) => "SNTL-ERR-004",
            SentinelError::CdrWorkerFailed(_) => "SNTL-ERR-005",
            SentinelError::CacheQuotaExceeded(_) => "SNTL-ERR-006",
            SentinelError::PolicySignatureInvalid(_) => "SNTL-ERR-007",
            SentinelError::LedgerTampered(_) => "SNTL-ERR-008",
            SentinelError::IoError(_) => "SNTL-ERR-009",
        }
    }

    /// Canonical degradation/audit event token for SIEM and structured logs (`Row 33`, Master Plan v2 §5.1).
    pub fn event_code(&self) -> &'static str {
        match self {
            SentinelError::MountPostureViolation(_) => "MOUNT_POSTURE_VIOLATION",
            SentinelError::QuarantineIntegrityFail(_) => "VAULT_INTEGRITY_FAIL",
            SentinelError::ShredOperationFailed(_) => "SHRED_OPERATION_FAILED",
            SentinelError::WalkAccessDenied(_) => "WALK_ACCESS_DENIED",
            SentinelError::CdrWorkerFailed(_) => "CDR_WORKER_FAILED",
            SentinelError::CacheQuotaExceeded(_) => "CACHE_QUOTA_EXCEEDED",
            SentinelError::PolicySignatureInvalid(_) => "POLICY_REJECTED",
            SentinelError::LedgerTampered(_) => "LEDGER_TAMPERED",
            SentinelError::IoError(_) => "IO_ERROR",
        }
    }

    /// Stable error code accessor returning the canonical `SNTL-ERR-xxx` identifier (`Row 33`).
    pub fn code(&self) -> &'static str {
        self.numeric_code()
    }
}

/// Phase 5.1 Degradation Matrix Events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegradationEvent {
    PostureReducedNoProjfs,
    PostureReducedNoTpm,
    CacheQuotaExceeded,
    CdrWorkerFailed,
    VaultIntegrityFail,
    PolicyRejected,
    SandboxOfflineEmulated,
}

impl DegradationEvent {
    pub fn event_code(&self) -> &'static str {
        match self {
            DegradationEvent::PostureReducedNoProjfs => "POSTURE_REDUCED_NO_PROJFS",
            DegradationEvent::PostureReducedNoTpm => "POSTURE_REDUCED_NO_TPM",
            DegradationEvent::CacheQuotaExceeded => "CACHE_QUOTA_EXCEEDED",
            DegradationEvent::CdrWorkerFailed => "CDR_WORKER_FAILED",
            DegradationEvent::VaultIntegrityFail => "VAULT_INTEGRITY_FAIL",
            DegradationEvent::PolicyRejected => "POLICY_REJECTED",
            DegradationEvent::SandboxOfflineEmulated => "SANDBOX_OFFLINE_EMULATED",
        }
    }
}

/// Phase 5.3 Structured Observability Metrics (`Row 206`)
#[derive(Debug, Default)]
pub struct SentinelMetrics {
    pub sentinel_active_workers: AtomicU64,
    pub sentinel_cdr_processed_total: AtomicU64,
    pub sentinel_cdr_duration_ms: AtomicU64,
    pub sentinel_threats_total: AtomicU64,
    pub sentinel_vault_ops_total: AtomicU64,
    pub sentinel_posture: AtomicU64,
    pub sentinel_policy_drift_total: AtomicU64,
    cdr_processed_by_label: Mutex<BTreeMap<(String, String), u64>>,
    cdr_duration_by_format: Mutex<BTreeMap<String, u64>>,
    threats_by_label: Mutex<BTreeMap<(String, String), u64>>,
    vault_ops_by_label: Mutex<BTreeMap<(String, String), u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub sentinel_active_workers: u64,
    pub sentinel_cdr_processed_total: u64,
    pub sentinel_cdr_duration_ms: u64,
    pub sentinel_threats_total: u64,
    pub sentinel_vault_ops_total: u64,
    pub sentinel_posture: u64,
    pub sentinel_policy_drift_total: u64,
}

static GLOBAL_SENTINEL_METRICS: OnceLock<SentinelMetrics> = OnceLock::new();

impl SentinelMetrics {
    /// Returns the process-wide `SentinelMetrics` registry (`Row 206`).
    pub fn global() -> &'static Self {
        GLOBAL_SENTINEL_METRICS.get_or_init(SentinelMetrics::default)
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            sentinel_active_workers: self.sentinel_active_workers.load(Ordering::Relaxed),
            sentinel_cdr_processed_total: self.sentinel_cdr_processed_total.load(Ordering::Relaxed),
            sentinel_cdr_duration_ms: self.sentinel_cdr_duration_ms.load(Ordering::Relaxed),
            sentinel_threats_total: self.sentinel_threats_total.load(Ordering::Relaxed),
            sentinel_vault_ops_total: self.sentinel_vault_ops_total.load(Ordering::Relaxed),
            sentinel_posture: self.sentinel_posture.load(Ordering::Relaxed),
            sentinel_policy_drift_total: self.sentinel_policy_drift_total.load(Ordering::Relaxed),
        }
    }

    pub fn record_cdr_processed(&self, format: &str, status: &str, duration_ms: u64) {
        self.sentinel_cdr_processed_total
            .fetch_add(1, Ordering::Relaxed);
        self.sentinel_cdr_duration_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
        if let Ok(mut guard) = self.cdr_processed_by_label.lock() {
            *guard
                .entry((format.to_string(), status.to_string()))
                .or_insert(0) += 1;
        }
        if let Ok(mut guard) = self.cdr_duration_by_format.lock() {
            *guard.entry(format.to_string()).or_insert(0) += duration_ms;
        }
    }

    pub fn record_threat(&self, category: &str, severity: &str) {
        self.sentinel_threats_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.threats_by_label.lock() {
            *guard
                .entry((category.to_string(), severity.to_string()))
                .or_insert(0) += 1;
        }
    }

    pub fn record_vault_op(&self, op: &str, status: &str) {
        self.sentinel_vault_ops_total
            .fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.vault_ops_by_label.lock() {
            *guard
                .entry((op.to_string(), status.to_string()))
                .or_insert(0) += 1;
        }
    }

    pub fn record_policy_drift(&self) {
        self.sentinel_policy_drift_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Exports all 7 labeled Prometheus metrics required by Plan v2 §5.3 (`Row 206`):
    /// - `sentinel_active_workers`
    /// - `sentinel_cdr_processed_total{format,status}`
    /// - `sentinel_cdr_duration_ms{format}`
    /// - `sentinel_threats_total{category,severity}`
    /// - `sentinel_vault_ops_total{op,status}`
    /// - `sentinel_posture{feature}`
    /// - `sentinel_policy_drift_total`
    pub fn render_prometheus(&self, posture: &sentinel_sys::PostureReport) -> String {
        let snap = self.snapshot();
        let mut out = String::new();

        // 1. sentinel_active_workers
        out.push_str(
            "# HELP sentinel_active_workers Currently active sandboxed CDR worker processes.\n",
        );
        out.push_str("# TYPE sentinel_active_workers gauge\n");
        out.push_str(&format!(
            "sentinel_active_workers {}\n",
            snap.sentinel_active_workers
        ));

        // 2. sentinel_cdr_processed_total{format,status}
        out.push_str(
            "# HELP sentinel_cdr_processed_total Total CDR operations by format and status.\n",
        );
        out.push_str("# TYPE sentinel_cdr_processed_total counter\n");
        if let Ok(guard) = self.cdr_processed_by_label.lock() {
            if guard.is_empty() {
                out.push_str(&format!(
                    "sentinel_cdr_processed_total{{format=\"all\",status=\"clean\"}} {}\n",
                    snap.sentinel_cdr_processed_total
                ));
            } else {
                for ((fmt, status), val) in guard.iter() {
                    out.push_str(&format!(
                        "sentinel_cdr_processed_total{{format=\"{}\",status=\"{}\"}} {}\n",
                        fmt, status, val
                    ));
                }
            }
        }

        // 3. sentinel_cdr_duration_ms{format}
        out.push_str("# HELP sentinel_cdr_duration_ms Cumulative CDR sanitization duration in milliseconds by format.\n");
        out.push_str("# TYPE sentinel_cdr_duration_ms counter\n");
        if let Ok(guard) = self.cdr_duration_by_format.lock() {
            if guard.is_empty() {
                out.push_str(&format!(
                    "sentinel_cdr_duration_ms{{format=\"all\"}} {}\n",
                    snap.sentinel_cdr_duration_ms
                ));
            } else {
                for (fmt, val) in guard.iter() {
                    out.push_str(&format!(
                        "sentinel_cdr_duration_ms{{format=\"{}\"}} {}\n",
                        fmt, val
                    ));
                }
            }
        }

        // 4. sentinel_threats_total{category,severity}
        out.push_str(
            "# HELP sentinel_threats_total Total detected threats by category and severity.\n",
        );
        out.push_str("# TYPE sentinel_threats_total counter\n");
        if let Ok(guard) = self.threats_by_label.lock() {
            if guard.is_empty() {
                out.push_str(&format!(
                    "sentinel_threats_total{{category=\"all\",severity=\"all\"}} {}\n",
                    snap.sentinel_threats_total
                ));
            } else {
                for ((cat, sev), val) in guard.iter() {
                    out.push_str(&format!(
                        "sentinel_threats_total{{category=\"{}\",severity=\"{}\"}} {}\n",
                        cat, sev, val
                    ));
                }
            }
        }

        // 5. sentinel_vault_ops_total{op,status}
        out.push_str(
            "# HELP sentinel_vault_ops_total Total QuarantineVault operations by op and status.\n",
        );
        out.push_str("# TYPE sentinel_vault_ops_total counter\n");
        if let Ok(guard) = self.vault_ops_by_label.lock() {
            if guard.is_empty() {
                out.push_str(&format!(
                    "sentinel_vault_ops_total{{op=\"all\",status=\"ok\"}} {}\n",
                    snap.sentinel_vault_ops_total
                ));
            } else {
                for ((op, status), val) in guard.iter() {
                    out.push_str(&format!(
                        "sentinel_vault_ops_total{{op=\"{}\",status=\"{}\"}} {}\n",
                        op, status, val
                    ));
                }
            }
        }

        // 6. sentinel_posture{feature}
        out.push_str("# HELP sentinel_posture System fail-closed posture feature states (1 = compliant, 0 = degraded).\n");
        out.push_str("# TYPE sentinel_posture gauge\n");
        out.push_str(&format!(
            "sentinel_posture{{feature=\"automount_disabled\"}} {}\n",
            u8::from(posture.automount_disabled)
        ));
        out.push_str(&format!(
            "sentinel_posture{{feature=\"user_deny_policy_present\"}} {}\n",
            u8::from(posture.user_deny_policy_present)
        ));
        out.push_str(&format!(
            "sentinel_posture{{feature=\"install_restrictions_active\"}} {}\n",
            u8::from(posture.install_restrictions_active)
        ));
        out.push_str(&format!(
            "sentinel_posture{{feature=\"write_protect_active\"}} {}\n",
            u8::from(posture.write_protect_active)
        ));
        out.push_str(&format!(
            "sentinel_posture{{feature=\"removable_volumes_offline\"}} {}\n",
            u8::from(
                posture
                    .removable_volumes_offline
                    .iter()
                    .all(|(_, off)| *off)
            )
        ));
        out.push_str(&format!(
            "sentinel_posture{{feature=\"is_compliant\"}} {}\n",
            u8::from(posture.is_compliant())
        ));

        // 7. sentinel_policy_drift_total
        out.push_str("# HELP sentinel_policy_drift_total Total MDM/Intune policy drift or rollback rejections.\n");
        out.push_str("# TYPE sentinel_policy_drift_total counter\n");
        out.push_str(&format!(
            "sentinel_policy_drift_total {}\n",
            snap.sentinel_policy_drift_total
        ));

        out
    }
}

/// Phase 4.5 Time-Limited Cryptographically Signed Break-Glass Maintenance Token (`Row 191`)
///
/// Requires a valid ECDSA P-256 signature over `SHA256("SENTINEL-BREAK-GLASS-V2:{token_id}|{reason}|{expires_at_unix}")`
/// and a future `expires_at_unix` timestamp. Every verification/use is recorded in the `AuditLedger`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakGlassToken {
    pub token_id: String,
    pub reason: String,
    pub expires_at_unix: u64,
    pub signature_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
}

impl BreakGlassToken {
    /// Computes the canonical 32-byte SHA-256 digest signed by the SOC Break-Glass ECDSA P-256 authority.
    pub fn signing_digest(token_id: &str, reason: &str, expires_at_unix: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"SENTINEL-BREAK-GLASS-V2:");
        hasher.update(token_id.as_bytes());
        hasher.update(b"|");
        hasher.update(reason.as_bytes());
        hasher.update(b"|");
        hasher.update(expires_at_unix.to_string().as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Issues a cryptographically signed `BreakGlassToken` using an ECDSA P-256 keypair.
    pub fn issue_signed(
        token_id: impl Into<String>,
        reason: impl Into<String>,
        expires_at_unix: u64,
        private_key_blob: &[u8],
        public_key_blob: &[u8],
    ) -> Result<Self, String> {
        let token_id = token_id.into();
        let reason = reason.into();
        if token_id.trim().is_empty() || reason.trim().is_empty() {
            return Err("Break-glass token_id and reason must be non-empty".to_string());
        }
        let digest = Self::signing_digest(&token_id, &reason, expires_at_unix);
        let sig_bytes = sign_ecdsa_p256_with_private_blob(private_key_blob, &digest)
            .map_err(|e| format!("Failed signing BreakGlassToken with ECDSA P-256: {}", e))?;
        Ok(Self {
            token_id,
            reason,
            expires_at_unix,
            signature_hex: hex::encode(sig_bytes),
            public_key_hex: hex::encode(public_key_blob),
        })
    }

    /// Verifies the token's expiration and asymmetric ECDSA P-256 signature against `trusted_public_key`.
    pub fn verify_with_public_key(
        &self,
        current_unix_secs: u64,
        trusted_public_key: &[u8],
    ) -> Result<(), String> {
        if self.token_id.trim().is_empty() || self.reason.trim().is_empty() {
            return Err("Break-glass token fields are empty".to_string());
        }
        if current_unix_secs >= self.expires_at_unix {
            return Err(format!(
                "Break-glass token '{}' expired at {} (current: {})",
                self.token_id, self.expires_at_unix, current_unix_secs
            ));
        }
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| format!("Invalid BreakGlassToken signature hex: {}", e))?;
        let digest = Self::signing_digest(&self.token_id, &self.reason, self.expires_at_unix);
        let verified = verify_ecdsa_p256_digest(trusted_public_key, &digest, &sig_bytes)
            .map_err(|e| format!("ECDSA P-256 break-glass verification error: {}", e))?;
        if !verified {
            return Err(format!(
                "Break-glass token '{}' failed ECDSA P-256 cryptographic signature verification",
                self.token_id
            ));
        }
        Ok(())
    }

    /// Verifies the token against `trusted_public_key` and appends a signed record to `ledger` (`Row 191`).
    pub fn verify_and_record(
        &self,
        current_unix_secs: u64,
        trusted_public_key: &[u8],
        ledger: &mut crate::enterprise::ledger::AuditLedger,
    ) -> Result<(), String> {
        match self.verify_with_public_key(current_unix_secs, trusted_public_key) {
            Ok(()) => {
                ledger.append_event(
                    "BREAK_GLASS_TOKEN_USED",
                    serde_json::json!({
                        "token_id": self.token_id,
                        "reason": self.reason,
                        "expires_at_unix": self.expires_at_unix,
                        "verified_at_unix": current_unix_secs,
                    }),
                )?;
                Ok(())
            }
            Err(err) => {
                let _ = ledger.append_event(
                    "BREAK_GLASS_TOKEN_REJECTED",
                    serde_json::json!({
                        "token_id": self.token_id,
                        "reason": self.reason,
                        "expires_at_unix": self.expires_at_unix,
                        "error": err,
                    }),
                );
                Err(err)
            }
        }
    }

    /// Checks token validity at `current_unix_secs`, verifying the embedded ECDSA P-256 public key
    /// signature rather than accepting arbitrary hex strings (`Row 191`).
    pub fn is_valid_at(&self, current_unix_secs: u64) -> bool {
        let Ok(pub_bytes) = hex::decode(&self.public_key_hex) else {
            return false;
        };
        if pub_bytes.is_empty() {
            return false;
        }
        self.verify_with_public_key(current_unix_secs, &pub_bytes)
            .is_ok()
    }
}
