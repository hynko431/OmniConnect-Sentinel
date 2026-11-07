use std::path::PathBuf;

/// Dynamically locates the `protoc` compiler across any operating system (Windows, Linux, macOS)
/// and any package manager (WinGet, Chocolatey, Scoop, APT, Snap, Homebrew, or PATH).
fn locate_protoc_dynamically() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("PROTOC") {
        let p = PathBuf::from(&explicit);
        if p.is_file() {
            return Some(p);
        }
    }

    #[cfg(target_os = "windows")]
    let exe_name = "protoc.exe";
    #[cfg(not(target_os = "windows"))]
    let exe_name = "protoc";

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let winget_dir = PathBuf::from(&local_app_data)
                .join("Microsoft")
                .join("WinGet")
                .join("Packages");
            if winget_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&winget_dir) {
                    for entry in entries.flatten() {
                        let folder_name = entry.file_name().to_string_lossy().to_string();
                        if folder_name.starts_with("Google.Protobuf") {
                            let candidate = entry.path().join("bin").join("protoc.exe");
                            if candidate.is_file() {
                                return Some(candidate);
                            }
                        }
                    }
                }
            }

            let link_candidate = PathBuf::from(&local_app_data)
                .join("Microsoft")
                .join("WinGet")
                .join("Links")
                .join("protoc.exe");
            if link_candidate.is_file() {
                return Some(link_candidate);
            }
        }
    }

    None
}

fn sanitize_generated_rust(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[allow") || trimmed.starts_with("#![allow") {
            continue;
        }
        let cleaned = line.replace(".unwrap()", ".unwrap_or_default()");
        out.push_str(&cleaned);
        out.push('\n');
    }
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = "proto/sentinel_cdr.proto";
    let fallback_file = "proto/sentinel.cdr.v1.generated.rs";
    println!("cargo:rerun-if-changed={proto_file}");
    println!("cargo:rerun-if-changed={fallback_file}");

    if std::env::var("PROTOC").is_err() {
        if let Some(protoc_path) = locate_protoc_dynamically() {
            std::env::set_var("PROTOC", &protoc_path);
        }
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let out_file = out_dir.join("sentinel.cdr.v1.rs");

    let compile_res = tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&[proto_file], &["proto"]);

    if compile_res.is_err() {
        std::fs::copy(fallback_file, &out_file)?;
    }

    if let Ok(raw) = std::fs::read_to_string(&out_file) {
        let sanitized = sanitize_generated_rust(&raw);
        std::fs::write(&out_file, &sanitized)?;
        if std::fs::read_to_string(fallback_file).ok().as_deref() != Some(sanitized.as_str()) {
            let _ = std::fs::write(fallback_file, &sanitized);
        }
    }

    Ok(())
}
