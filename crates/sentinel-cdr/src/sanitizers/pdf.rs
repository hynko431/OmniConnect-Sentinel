use crate::error::{CdrError, Result};
use crate::policy::SanitizationPolicy;
use crate::sanitizers::DisarmReportItem;
use lopdf::Document;
use std::collections::HashSet;
use tracing::{debug, info};

pub struct PdfSanitizer;

impl PdfSanitizer {
    pub fn sanitize(input: &[u8], policy: &SanitizationPolicy) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        debug!("Beginning PDF AST deconstruction (input size: {} bytes)", input.len());
        
        let mut doc = Document::load_mem(input)
            .map_err(|e| CdrError::ParserCorruption(format!("Invalid PDF syntax: {}", e)))?;

        let mut reports = Vec::new();

        // 1. Sanitize Document Catalog / Root
        if let Ok(catalog_id) = doc.trailer.get(b"Root").and_then(|obj| obj.as_reference()) {
            if let Ok(catalog) = doc.get_object_mut(catalog_id).and_then(|obj| obj.as_dict_mut()) {
                // Remove OpenAction (auto-execution on document open)
                if policy.strip_pdf_actions && catalog.has(b"OpenAction") {
                    catalog.remove(b"OpenAction");
                    reports.push(DisarmReportItem::new("PDF_OPEN_ACTION", "Root/OpenAction", "REMOVED"));
                }

                // Remove AA (Additional Actions dictionary)
                if policy.strip_pdf_actions && catalog.has(b"AA") {
                    catalog.remove(b"AA");
                    reports.push(DisarmReportItem::new("PDF_ADDITIONAL_ACTION", "Root/AA", "REMOVED"));
                }

                // Remove Names / JavaScript tree
                if policy.strip_pdf_scripts && catalog.has(b"Names") {
                    catalog.remove(b"Names");
                    reports.push(DisarmReportItem::new("PDF_JS_NAME_TREE", "Root/Names", "REMOVED"));
                }

                // Remove EmbeddedFiles
                if policy.strip_pdf_attachments && catalog.has(b"EmbeddedFiles") {
                    catalog.remove(b"EmbeddedFiles");
                    reports.push(DisarmReportItem::new("PDF_EMBEDDED_FILES", "Root/EmbeddedFiles", "REMOVED"));
                }
            }
        }

        // 2. Comprehensive Object Sweep
        let object_ids: Vec<_> = doc.objects.keys().copied().collect();
        let mut dangerous_objects = HashSet::new();

        for id in object_ids {
            if let Ok(obj) = doc.get_object_mut(id) {
                if let Ok(dict) = obj.as_dict_mut() {
                    // Check for JavaScript actions
                    if policy.strip_pdf_scripts {
                        if dict.has(b"JS") || dict.has(b"JavaScript") {
                            dict.remove(b"JS");
                            dict.remove(b"JavaScript");
                            reports.push(DisarmReportItem::new("PDF_EMBEDDED_JAVASCRIPT", format!("Object({:?})", id), "PURGED"));
                        }
                    }

                    // Check for Launch actions
                    if policy.strip_pdf_actions && dict.has(b"Launch") {
                        dict.remove(b"Launch");
                        reports.push(DisarmReportItem::new("PDF_LAUNCH_ACTION", format!("Object({:?})", id), "PURGED"));
                    }

                    // Check for RichMedia / 3D annotations
                    if let Ok(type_name) = dict.get(b"Subtype").and_then(|s| s.as_name()) {
                        if type_name == b"RichMedia" || type_name == b"3D" {
                            dangerous_objects.insert(id);
                            reports.push(DisarmReportItem::new("PDF_RICH_MEDIA", format!("Object({:?})", id), "DROPPED"));
                        }
                    }
                }
            }
        }

        // Purge completely dangerous objects
        for id in dangerous_objects {
            doc.objects.remove(&id);
        }

        // 3. Prune orphan objects and linearize / rebuild
        doc.prune_objects();

        let mut output = Vec::new();
        doc.save_to(&mut output)
            .map_err(|e| CdrError::ReconstructionFailure(format!("Failed to re-encode sanitized PDF: {}", e)))?;

        info!("PDF CDR completed. Elements stripped: {}, Output size: {} bytes", reports.len(), output.len());
        Ok((output, reports))
    }
}
