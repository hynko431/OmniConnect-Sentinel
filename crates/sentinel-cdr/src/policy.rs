use serde::{Deserialize, Serialize};

/// Configurable sanitization policy per file type
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Office: Neutralize DDE formulas (=cmd|...)
    pub strip_office_dde: bool,

    /// Images: Strip all EXIF, XMP, and metadata comments
    pub strip_image_metadata: bool,
    /// Images: Truncate trailing overlay bytes (polyglot / appended malware)
    pub truncate_image_overlays: bool,
    /// Images: Re-encode raw pixels to canonical bitstream
    pub reencode_images: bool,

    /// Maximum permitted recursion depth for nested archives/documents
    pub max_recursion_depth: u32,
    /// Maximum permitted decompressed size (in bytes) to prevent decompression bombs (e.g. 500 MB)
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
            strip_office_dde: true,
            strip_image_metadata: true,
            truncate_image_overlays: true,
            reencode_images: true,
            max_recursion_depth: 8,
            max_decompressed_bytes: 512 * 1024 * 1024, // 512 MB safety bound
        }
    }
}
