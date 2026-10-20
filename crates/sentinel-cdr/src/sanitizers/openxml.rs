use crate::error::{CdrError, Result};
use crate::policy::SanitizationPolicy;
use crate::sanitizers::DisarmReportItem;
use std::io::{Cursor, Read, Write};
use tracing::{debug, info};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

pub struct OpenXmlSanitizer;

impl OpenXmlSanitizer {
    pub fn sanitize(input: &[u8], policy: &SanitizationPolicy) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        debug!("Beginning Office OpenXML deconstruction (input size: {} bytes)", input.len());

        let reader = Cursor::new(input);
        let mut archive = ZipArchive::new(reader)
            .map_err(|e| CdrError::ParserCorruption(format!("Invalid OpenXML ZIP container: {}", e)))?;

        let mut output_bytes = Vec::with_capacity(input.len());
        let mut writer = ZipWriter::new(Cursor::new(&mut output_bytes));

        let mut reports = Vec::new();
        let mut total_decompressed_bytes = 0u64;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_name = file.name().to_string();
            let uncompressed_size = file.size();

            total_decompressed_bytes += uncompressed_size;
            if total_decompressed_bytes > policy.max_decompressed_bytes {
                return Err(CdrError::ResourceLimitExceeded(format!(
                    "Decompressed size exceeded threshold ({} > {})",
                    total_decompressed_bytes, policy.max_decompressed_bytes
                )));
            }

            // Rule 1: Strip VBA Macros
            if policy.strip_office_macros {
                if file_name.ends_with("vbaProject.bin") || file_name.contains("vbaData") {
                    reports.push(DisarmReportItem::new("OFFICE_VBA_MACRO", &file_name, "STRIPPED"));
                    continue;
                }
            }

            // Rule 2: Strip Embedded OLE Objects & ActiveX
            if policy.strip_office_ole_objects {
                if file_name.contains("embeddings/") || file_name.contains("activeX/") || file_name.ends_with(".bin") {
                    reports.push(DisarmReportItem::new("OFFICE_OLE_OBJECT", &file_name, "DROPPED"));
                    continue;
                }
            }

            // Rule 3: Sanitize Relationships (.rels) for External Template Injection (CVE-2022-30190)
            if file_name.ends_with(".rels") && policy.sanitize_office_external_relationships {
                let mut content = String::new();
                file.read_to_string(&mut content)?;

                if content.contains("TargetMode=\"External\"") {
                    let sanitized_rels = content.replace("TargetMode=\"External\"", "TargetMode=\"InternalBlocked\"");
                    reports.push(DisarmReportItem::new("EXTERNAL_RELATIONSHIP", &file_name, "BLOCKED"));

                    writer.start_file(&file_name, SimpleFileOptions::default())?;
                    writer.write_all(sanitized_rels.as_bytes())?;
                    continue;
                }
            }

            // Safe parts: Copy without modification
            writer.start_file(&file_name, SimpleFileOptions::default())?;
            std::io::copy(&mut file, &mut writer)?;
        }

        writer.finish()?;
        info!("OpenXML CDR completed. Elements stripped: {}, Output size: {} bytes", reports.len(), output_bytes.len());
        Ok((output_bytes, reports))
    }
}
