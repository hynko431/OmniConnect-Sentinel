use std::collections::HashSet;
use std::io::Cursor;
use lopdf::{Dictionary, Document, Object, ObjectId};
use tracing::info;

use crate::error::CdrError;
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::DisarmReportItem;

const MAX_PDF_WALK_DEPTH: u32 = 64;

/// Structural PDF Sanitizer (`BUG-CDR-06`, Phase 2.4)
///
/// Parses the PDF Object AST via `lopdf`, selectively cleans `/Root -> /Names`
/// (preserving `/Dests` and internal navigation), recursively walks both
/// dictionaries and arrays (catching inline `/Annots` and `/Next` chains),
/// and inspects `/S` action subtype values rather than blindly deleting `/S`.
pub struct PdfSanitizer;

impl PdfSanitizer {
    pub fn sanitize(
        input_bytes: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>), CdrError> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_with_budget(input_bytes, policy, &mut budget)
    }

    pub fn sanitize_with_budget(
        input_bytes: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>), CdrError> {
        let mut doc = Document::load_mem(input_bytes).map_err(|e| {
            CdrError::ParserCorruption(format!("PDF AST parse error: {}", e))
        })?;

        let mut disarm_report = Vec::new();

        // 1. Selectively clean `/Root -> /Names`, `/Root -> /AF`, and `/Root -> /AcroForm -> /XFA`
        Self::sanitize_catalog_structures(&mut doc, policy, &mut disarm_report);

        // 1b. Traverse indirect `/Next` chains with an explicit `visited: HashSet<ObjectId>`
        // cycle guard so circular `/Next` chains (`10 0 R -> 11 0 R -> 10 0 R`) terminate cleanly
        // and charge the cross-format object budget (Master Plan v2 §2.2, §2.4, §5).
        Self::break_indirect_next_cycles(&mut doc, budget, &mut disarm_report)?;

        // 2. Recursively walk all objects (both top-level dictionaries and arrays)
        let object_ids: Vec<ObjectId> = doc.objects.keys().copied().collect();
        for object_id in object_ids {
            budget.charge_object()?;

            let location = format!("Obj({},{})", object_id.0, object_id.1);
            if let Some(obj) = doc.objects.get_mut(&object_id) {
                Self::sanitize_pdf_object(
                    obj,
                    &location,
                    policy,
                    budget,
                    0,
                    &mut disarm_report,
                )?;
            }
        }

        // 3. Re-serialize clean AST into memory buffer
        let mut output_buffer = Cursor::new(Vec::with_capacity(input_bytes.len()));
        doc.save_to(&mut output_buffer).map_err(|e| {
            CdrError::ReconstructionFailure(format!("Failed saving disarmed PDF AST: {}", e))
        })?;

        Ok((output_buffer.into_inner(), disarm_report))
    }

    fn break_indirect_next_cycles(
        doc: &mut Document,
        budget: &mut ResourceBudget,
        reports: &mut Vec<DisarmReportItem>,
    ) -> Result<(), CdrError> {
        let object_ids: Vec<ObjectId> = doc.objects.keys().copied().collect();
        let mut globally_visited: HashSet<ObjectId> = HashSet::new();

        for start_id in object_ids {
            if globally_visited.contains(&start_id) {
                continue;
            }
            let mut chain_visited: HashSet<ObjectId> = HashSet::new();
            let mut cursor = Some(start_id);

            while let Some(curr_id) = cursor {
                budget.charge_object()?;
                if !chain_visited.insert(curr_id) {
                    // Cycle detected! Break `/Next` on `curr_id`
                    if let Some(Object::Dictionary(d)) = doc.objects.get_mut(&curr_id) {
                        d.remove(b"Next");
                    }
                    reports.push(DisarmReportItem::new(
                        "PDF_ACTION_NEXT_CYCLE",
                        format!("Obj({},{})[/Next]", curr_id.0, curr_id.1),
                        "Broke circular /Next reference chain in PDF action dictionary",
                    ));
                    break;
                }
                globally_visited.insert(curr_id);

                cursor = doc
                    .objects
                    .get(&curr_id)
                    .and_then(|o| o.as_dict().ok())
                    .and_then(|d| d.get(b"Next").ok())
                    .and_then(|n| n.as_reference().ok());
            }
        }
        Ok(())
    }

    fn sanitize_catalog_structures(
        doc: &mut Document,
        policy: &SanitizationPolicy,
        reports: &mut Vec<DisarmReportItem>,
    ) {
        let root_id = match doc.trailer.get(b"Root").ok().and_then(|o| o.as_reference().ok()) {
            Some(id) => id,
            None => return,
        };

        let mut names_ref_to_clean: Option<ObjectId> = None;
        let mut acroform_ref_to_clean: Option<ObjectId> = None;

        if let Some(Object::Dictionary(root_dict)) = doc.objects.get_mut(&root_id) {
            let root_loc = format!("Obj({},{})[/Root]", root_id.0, root_id.1);

            if policy.strip_pdf_attachments && root_dict.has(b"AF") {
                root_dict.remove(b"AF");
                reports.push(DisarmReportItem::new(
                    "PDF_CATALOG_AF",
                    root_loc.clone(),
                    "Removed Associated Files array from Catalog",
                ));
            }

            match root_dict.get_mut(b"Names") {
                Ok(Object::Dictionary(names_dict)) => {
                    Self::clean_names_dictionary(names_dict, &root_loc, policy, reports);
                }
                Ok(Object::Reference(ref_id)) => {
                    names_ref_to_clean = Some(*ref_id);
                }
                _ => {}
            }

            if policy.strip_pdf_scripts {
                match root_dict.get_mut(b"AcroForm") {
                    Ok(Object::Dictionary(acro_dict)) => {
                        if acro_dict.has(b"XFA") {
                            acro_dict.remove(b"XFA");
                            reports.push(DisarmReportItem::new(
                                "PDF_ACROFORM_XFA",
                                root_loc,
                                "Removed XFA form scripting payload from AcroForm",
                            ));
                        }
                    }
                    Ok(Object::Reference(ref_id)) => {
                        acroform_ref_to_clean = Some(*ref_id);
                    }
                    _ => {}
                }
            }
        }

        if let Some(names_id) = names_ref_to_clean {
            let loc = format!("Obj({},{})[/Names]", names_id.0, names_id.1);
            if let Some(Object::Dictionary(names_dict)) = doc.objects.get_mut(&names_id) {
                Self::clean_names_dictionary(names_dict, &loc, policy, reports);
            }
        }

        if let Some(acro_id) = acroform_ref_to_clean {
            let loc = format!("Obj({},{})[/AcroForm]", acro_id.0, acro_id.1);
            if let Some(Object::Dictionary(acro_dict)) = doc.objects.get_mut(&acro_id) {
                if acro_dict.has(b"XFA") {
                    acro_dict.remove(b"XFA");
                    reports.push(DisarmReportItem::new(
                        "PDF_ACROFORM_XFA",
                        loc,
                        "Removed XFA form scripting payload from indirect AcroForm",
                    ));
                }
            }
        }
    }

    fn clean_names_dictionary(
        names_dict: &mut Dictionary,
        location: &str,
        policy: &SanitizationPolicy,
        reports: &mut Vec<DisarmReportItem>,
    ) {
        if policy.strip_pdf_scripts && names_dict.has(b"JavaScript") {
            names_dict.remove(b"JavaScript");
            reports.push(DisarmReportItem::new(
                "PDF_NAMES_JAVASCRIPT",
                location.to_string(),
                "Removed /JavaScript name tree while preserving /Dests navigation",
            ));
        }

        if policy.strip_pdf_attachments && names_dict.has(b"EmbeddedFiles") {
            names_dict.remove(b"EmbeddedFiles");
            reports.push(DisarmReportItem::new(
                "PDF_NAMES_EMBEDDED_FILES",
                location.to_string(),
                "Removed /EmbeddedFiles name tree while preserving /Dests navigation",
            ));
        }
    }

    fn sanitize_pdf_object(
        obj: &mut Object,
        location: &str,
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
        depth: u32,
        reports: &mut Vec<DisarmReportItem>,
    ) -> Result<(), CdrError> {
        if depth > MAX_PDF_WALK_DEPTH {
            return Err(CdrError::ResourceLimitExceeded(format!(
                "PDF nested object depth exceeded {} at {}",
                MAX_PDF_WALK_DEPTH, location
            )));
        }

        match obj {
            Object::Dictionary(dict) => {
                let replace_with_null =
                    Self::sanitize_dictionary(dict, location, policy, budget, depth, reports)?;
                if replace_with_null {
                    *obj = Object::Null;
                }
            }
            Object::Array(arr) => {
                for (idx, item) in arr.iter_mut().enumerate() {
                    budget.charge_object()?;
                    let item_loc = format!("{}[{}]", location, idx);
                    Self::sanitize_pdf_object(
                        item,
                        &item_loc,
                        policy,
                        budget,
                        depth + 1,
                        reports,
                    )?;
                }
            }
            Object::Stream(stream) => {
                let _ = Self::sanitize_dictionary(
                    &mut stream.dict,
                    location,
                    policy,
                    budget,
                    depth,
                    reports,
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    fn sanitize_dictionary(
        dict: &mut Dictionary,
        location: &str,
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
        depth: u32,
        reports: &mut Vec<DisarmReportItem>,
    ) -> Result<bool, CdrError> {
        let mut neutralized_action_dict = false;
        let is_structural_node = dict
            .get(b"Type")
            .ok()
            .and_then(|o| o.as_name().ok())
            .map(|t| {
                t.eq_ignore_ascii_case(b"Catalog")
                    || t.eq_ignore_ascii_case(b"Page")
                    || t.eq_ignore_ascii_case(b"Pages")
                    || t.eq_ignore_ascii_case(b"Annot")
            })
            .unwrap_or(false);

        let s_subtype: Option<Vec<u8>> = dict
            .get(b"S")
            .ok()
            .and_then(|o| o.as_name().ok())
            .map(|n| n.to_vec());

        if let Some(subtype) = s_subtype {
            if policy.strip_pdf_scripts
                && (subtype.as_slice() == b"JavaScript" || subtype.as_slice() == b"JS")
            {
                dict.remove(b"S");
                dict.remove(b"JS");
                dict.remove(b"JavaScript");
                dict.remove(b"Next");
                neutralized_action_dict = !is_structural_node;
                info!(
                    "Disarmed PDF /S /{} script action at {}",
                    String::from_utf8_lossy(&subtype),
                    location
                );
                reports.push(DisarmReportItem::new(
                    format!("PDF_ACTION_S_{}", String::from_utf8_lossy(&subtype)),
                    location.to_string(),
                    "Neutralized JavaScript action dictionary (replaced with null)",
                ));
            } else if policy.strip_pdf_actions && Self::is_dangerous_action_subtype(&subtype) {
                let subtype_name = String::from_utf8_lossy(&subtype).into_owned();
                dict.remove(b"S");
                dict.remove(b"F");
                dict.remove(b"Win");
                dict.remove(b"Mac");
                dict.remove(b"Unix");
                dict.remove(b"URI");
                dict.remove(b"Next");
                neutralized_action_dict = !is_structural_node;
                info!("Disarmed PDF /S /{} action at {}", subtype_name, location);
                reports.push(DisarmReportItem::new(
                    format!("PDF_ACTION_S_{}", subtype_name),
                    location.to_string(),
                    "Neutralized active PDF action dictionary (replaced with null)",
                ));
            }
        }

        if policy.strip_pdf_scripts {
            for &key in &[b"JS".as_slice(), b"JavaScript".as_slice()] {
                if dict.has(key) {
                    dict.remove(key);
                    let key_name = String::from_utf8_lossy(key).into_owned();
                    reports.push(DisarmReportItem::new(
                        format!("PDF_{}", key_name.to_ascii_uppercase()),
                        location.to_string(),
                        "Removed embedded PDF JavaScript key",
                    ));
                }
            }
        }

        if policy.strip_pdf_actions {
            for &key in &[
                b"OpenAction".as_slice(),
                b"AA".as_slice(),
                b"Launch".as_slice(),
                b"RichMedia".as_slice(),
                b"SubmitForm".as_slice(),
                b"ImportData".as_slice(),
                b"GoToR".as_slice(),
                b"GoToE".as_slice(),
                b"URI".as_slice(),
            ] {
                if dict.has(key) {
                    dict.remove(key);
                    let key_name = String::from_utf8_lossy(key).into_owned();
                    reports.push(DisarmReportItem::new(
                        format!("PDF_{}", key_name.to_ascii_uppercase()),
                        location.to_string(),
                        "Removed automatic/external PDF trigger key",
                    ));
                }
            }
        }

        if policy.strip_pdf_attachments {
            let is_filespec = dict
                .get(b"Type")
                .ok()
                .and_then(|o| o.as_name().ok())
                .map(|n| n.eq_ignore_ascii_case(b"Filespec"))
                .unwrap_or(false);

            if is_filespec && dict.has(b"EF") {
                dict.remove(b"EF");
                reports.push(DisarmReportItem::new(
                    "PDF_FILESPEC_EF",
                    location.to_string(),
                    "Removed embedded file stream dictionary from Filespec",
                ));
            }

            if dict.has(b"EmbeddedFiles") {
                dict.remove(b"EmbeddedFiles");
                reports.push(DisarmReportItem::new(
                    "PDF_EMBEDDED_FILES",
                    location.to_string(),
                    "Removed embedded files dictionary entry",
                ));
            }
        }

        let keys: Vec<Vec<u8>> = dict.iter().map(|(k, _)| k.clone()).collect();
        for key in keys {
            let mut remove_empty_action = false;
            if let Ok(child_obj) = dict.get_mut(&key) {
                budget.charge_object()?;
                let child_loc = format!("{}/{}", location, String::from_utf8_lossy(&key));
                Self::sanitize_pdf_object(
                    child_obj,
                    &child_loc,
                    policy,
                    budget,
                    depth + 1,
                    reports,
                )?;
                if key.as_slice() == b"A" {
                    match child_obj {
                        Object::Null => {
                            remove_empty_action = true;
                        }
                        Object::Dictionary(child_dict) if child_dict.is_empty() => {
                            remove_empty_action = true;
                        }
                        _ => {}
                    }
                }
            }
            if remove_empty_action {
                dict.remove(&key);
            }
        }

        Ok(neutralized_action_dict)
    }

    pub fn is_dangerous_action_subtype(subtype: &[u8]) -> bool {
        matches!(
            subtype,
            b"Launch"
                | b"URI"
                | b"SubmitForm"
                | b"ImportData"
                | b"GoToR"
                | b"GoToE"
                | b"Movie"
                | b"Sound"
                | b"Rendition"
                | b"RichMedia"
        )
    }
}
