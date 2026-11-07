use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Configurable sanitization policy per file type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizationPolicy {
    /// PDF: Remove all /JavaScript, /JS, /Launch actions
    pub strip_pdf_scripts: bool,
    /// PDF: Remove /EmbeddedFiles and file attachments
    pub strip_pdf_attachments: bool,
    /// PDF: Remove /URI or form submit actions
    pub strip_pdf_actions: bool,

    /// Office: Strip word/vbaProject.bin, xl/vbaProject.bin
    pub strip_office_macros: bool,
    /// Office: Strip embedded OLE objects and binaries
    pub strip_office_ole_objects: bool,
    /// Office: Block external template / relationship injection (CVE-2022-30190)
    pub sanitize_office_external_relationships: bool,
    /// Office: Also strip benign external hyperlinks (`Type=".../hyperlink" TargetMode="External"`)
    #[serde(default)]
    pub strip_external_hyperlinks: bool,
    /// Office: Neutralize DDE formulas (=cmd|...)
    pub strip_office_dde: bool,

    /// Images: Strip all EXIF, XMP, and metadata comments
    pub strip_image_metadata: bool,
    /// Images: Truncate trailing overlay bytes (polyglot / appended malware)
    pub truncate_image_overlays: bool,
    /// Images: Re-encode raw pixels to canonical bitstream
    pub reencode_images: bool,

    /// Default-deny allowlist opt-in: Allow SVG sanitization (default `false` per Plan v2 §2.6)
    #[serde(default)]
    pub allow_svg: bool,
    /// Default-deny allowlist opt-in: Allow legacy OLE2 CFB sanitization (default `false` per Plan v2 §2.6)
    #[serde(default)]
    pub allow_legacy_ole2: bool,
    /// Default-deny allowlist opt-in: Allow generic ZIP container sanitization (default `false` per Plan v2 §2.6)
    #[serde(default)]
    pub allow_generic_zip: bool,

    /// Maximum permitted recursion depth for nested archives/documents
    pub max_recursion_depth: u32,
    /// Maximum permitted decompressed size (in bytes) to prevent decompression bombs (e.g. 128 MB)
    pub max_decompressed_bytes: u64,
}

impl Default for SanitizationPolicy {
    fn default() -> Self {
        Self {
            strip_pdf_scripts: true,
            strip_pdf_attachments: true,
            strip_pdf_actions: true,
            strip_office_macros: true,
            strip_office_ole_objects: true,
            sanitize_office_external_relationships: true,
            strip_external_hyperlinks: false,
            strip_office_dde: true,
            strip_image_metadata: true,
            truncate_image_overlays: true,
            reencode_images: true,
            allow_svg: false,
            allow_legacy_ole2: false,
            allow_generic_zip: false,
            max_recursion_depth: 8,
            max_decompressed_bytes: 128 * 1024 * 1024, // 128 MB default decompressed budget inside 256 MB worker cap (R10, §2.1)
        }
    }
}

impl SanitizationPolicy {
    /// Returns a floor policy where numeric ceilings are enforced (`depth=8`, `bytes=128 MB`)
    /// while boolean strip flags default to `false` so caller-supplied `DisarmPolicy` flags
    /// selectively enable stripping (`test_policy_proto_respects_caller_overrides`).
    pub fn permissive_floor() -> Self {
        Self {
            strip_pdf_scripts: false,
            strip_pdf_attachments: false,
            strip_pdf_actions: false,
            strip_office_macros: false,
            strip_office_ole_objects: false,
            sanitize_office_external_relationships: false,
            strip_external_hyperlinks: false,
            strip_office_dde: false,
            strip_image_metadata: false,
            truncate_image_overlays: false,
            reencode_images: false,
            allow_svg: false,
            allow_legacy_ole2: false,
            allow_generic_zip: false,
            max_recursion_depth: 8,
            max_decompressed_bytes: 128 * 1024 * 1024,
        }
    }

    /// Maps a client protobuf `DisarmPolicy` onto a `SanitizationPolicy` (`BUG-CDR-03`, `High #16`, Row 102):
    /// - Enforces `server_ceiling` as a mandatory security floor (`server_ceiling.strip_* || p.strip_*`)
    ///   so untrusted callers cannot disable strip flags mandated by `server_ceiling`.
    /// - Clamps `max_recursion_depth` and `max_decompressed_bytes` to `server_ceiling`.
    pub fn from_proto(
        proto: Option<sentinel_proto::DisarmPolicy>,
        server_ceiling: &SanitizationPolicy,
    ) -> Self {
        match proto {
            Some(p) => {
                let max_depth = if p.max_recursion_depth == 0 {
                    server_ceiling.max_recursion_depth
                } else {
                    p.max_recursion_depth
                        .min(server_ceiling.max_recursion_depth)
                };
                let max_bytes = if p.max_decompressed_bytes == 0 {
                    server_ceiling.max_decompressed_bytes
                } else {
                    p.max_decompressed_bytes
                        .min(server_ceiling.max_decompressed_bytes)
                };
                Self {
                    strip_pdf_scripts: server_ceiling.strip_pdf_scripts || p.strip_javascript,
                    strip_pdf_attachments: server_ceiling.strip_pdf_attachments
                        || p.strip_embedded_files,
                    strip_pdf_actions: server_ceiling.strip_pdf_actions
                        || p.strip_pdf_actions
                        || p.strip_external_hyperlinks,
                    strip_office_macros: server_ceiling.strip_office_macros || p.strip_macros,
                    strip_office_ole_objects: server_ceiling.strip_office_ole_objects
                        || p.strip_embedded_files,
                    sanitize_office_external_relationships: server_ceiling
                        .sanitize_office_external_relationships
                        || p.strip_external_hyperlinks,
                    strip_external_hyperlinks: server_ceiling.strip_external_hyperlinks
                        || p.strip_external_hyperlinks,
                    strip_office_dde: server_ceiling.strip_office_dde
                        || p.strip_office_dde
                        || p.strip_macros,
                    strip_image_metadata: server_ceiling.strip_image_metadata
                        || p.strip_exif_metadata,
                    truncate_image_overlays: server_ceiling.truncate_image_overlays
                        || p.truncate_overlay_bytes,
                    reencode_images: server_ceiling.reencode_images || p.reencode_images,
                    allow_svg: server_ceiling.allow_svg,
                    allow_legacy_ole2: server_ceiling.allow_legacy_ole2,
                    allow_generic_zip: server_ceiling.allow_generic_zip,
                    max_recursion_depth: max_depth,
                    max_decompressed_bytes: max_bytes,
                }
            }
            None => server_ceiling.clone(),
        }
    }

    /// Maps a trusted parent-to-worker `DisarmPolicy` protobuf frame directly onto a `SanitizationPolicy`
    /// while still clamping numeric budgets to `128 MB` and `depth <= 16`.
    pub fn from_worker_proto(p: sentinel_proto::DisarmPolicy) -> Self {
        let ceiling = SanitizationPolicy::default();
        let max_depth = if p.max_recursion_depth == 0 {
            ceiling.max_recursion_depth
        } else {
            p.max_recursion_depth.min(16)
        };
        let max_bytes = if p.max_decompressed_bytes == 0 {
            ceiling.max_decompressed_bytes
        } else {
            p.max_decompressed_bytes.min(ceiling.max_decompressed_bytes)
        };
        Self {
            strip_pdf_scripts: p.strip_javascript,
            strip_pdf_attachments: p.strip_embedded_files,
            strip_pdf_actions: p.strip_pdf_actions,
            strip_office_macros: p.strip_macros,
            strip_office_ole_objects: p.strip_embedded_files,
            sanitize_office_external_relationships: p.strip_external_hyperlinks,
            strip_external_hyperlinks: false,
            strip_office_dde: p.strip_office_dde,
            strip_image_metadata: p.strip_exif_metadata,
            truncate_image_overlays: p.truncate_overlay_bytes,
            reencode_images: p.reencode_images,
            allow_svg: false,
            allow_legacy_ole2: false,
            allow_generic_zip: false,
            max_recursion_depth: max_depth,
            max_decompressed_bytes: max_bytes,
        }
    }

    pub fn to_proto(&self) -> sentinel_proto::DisarmPolicy {
        sentinel_proto::DisarmPolicy {
            strip_macros: self.strip_office_macros,
            strip_javascript: self.strip_pdf_scripts,
            strip_embedded_files: self.strip_pdf_attachments || self.strip_office_ole_objects,
            strip_external_hyperlinks: self.sanitize_office_external_relationships,
            strip_exif_metadata: self.strip_image_metadata,
            truncate_overlay_bytes: self.truncate_image_overlays,
            max_recursion_depth: self.max_recursion_depth,
            strip_pdf_actions: self.strip_pdf_actions,
            strip_office_dde: self.strip_office_dde,
            reencode_images: self.reencode_images,
            max_decompressed_bytes: self.max_decompressed_bytes,
        }
    }
}

/// Cross-format resource budget carried across nested containers (ZIP -> OOXML -> PDF -> Image) (Phase 2.2).
#[derive(Debug, Clone)]
pub struct ResourceBudget {
    pub bytes_remaining: u64,
    pub depth_remaining: u32,
    pub objects_remaining: usize,
    pub deadline: Instant,
}

impl ResourceBudget {
    pub fn from_policy(policy: &SanitizationPolicy) -> Self {
        Self {
            bytes_remaining: policy.max_decompressed_bytes,
            depth_remaining: policy.max_recursion_depth,
            objects_remaining: 50_000,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    pub fn check_deadline(&self) -> crate::error::Result<()> {
        if Instant::now() > self.deadline {
            return Err(crate::error::CdrError::ResourceLimitExceeded(
                "CDR wall-clock processing deadline exceeded".to_string(),
            ));
        }
        Ok(())
    }

    pub fn charge_bytes(&mut self, bytes: u64) -> crate::error::Result<()> {
        self.check_deadline()?;
        if bytes > self.bytes_remaining {
            self.bytes_remaining = 0;
            return Err(crate::error::CdrError::ResourceLimitExceeded(format!(
                "Cumulative decompressed byte budget exceeded (requested {bytes} bytes)"
            )));
        }
        self.bytes_remaining -= bytes;
        Ok(())
    }

    pub fn charge_object(&mut self) -> crate::error::Result<()> {
        self.check_deadline()?;
        if self.objects_remaining == 0 {
            return Err(crate::error::CdrError::ResourceLimitExceeded(
                "Maximum AST object traversal count exceeded".to_string(),
            ));
        }
        self.objects_remaining -= 1;
        Ok(())
    }

    pub fn enter_recursion(&mut self) -> crate::error::Result<()> {
        self.check_deadline()?;
        if self.depth_remaining == 0 {
            return Err(crate::error::CdrError::ResourceLimitExceeded(
                "Maximum container recursion depth exceeded".to_string(),
            ));
        }
        self.depth_remaining -= 1;
        Ok(())
    }

    pub fn exit_recursion(&mut self) {
        self.depth_remaining = self.depth_remaining.saturating_add(1);
    }

    pub fn descend(&self) -> crate::error::Result<Self> {
        self.check_deadline()?;
        if self.depth_remaining == 0 {
            return Err(crate::error::CdrError::ResourceLimitExceeded(
                "Maximum container recursion depth exceeded".to_string(),
            ));
        }
        Ok(Self {
            bytes_remaining: self.bytes_remaining,
            depth_remaining: self.depth_remaining - 1,
            objects_remaining: self.objects_remaining,
            deadline: self.deadline,
        })
    }
}
