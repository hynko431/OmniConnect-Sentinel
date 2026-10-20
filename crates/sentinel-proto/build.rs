use std::path::PathBuf;

/// Dynamically locates the `protoc` compiler across any operating system (Windows, Linux, macOS)
/// and any package manager (WinGet, Chocolatey, Scoop, APT, Snap, Homebrew, or PATH).
fn locate_protoc_dynamically() -> Option<PathBuf> {
    // 1. Honor explicit PROTOC environment variable if set by user or CI/CD
    if let Ok(explicit) = std::env::var("PROTOC") {
        let p = PathBuf::from(&explicit);
        if p.is_file() {
            return Some(p);
        }
    }

    // 2. Check if protoc is in system PATH
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

    // 3. Dynamic Windows Package Manager Detection (Any User, Any Drive)
    #[cfg(target_os = "windows")]
    {
        // 3a. Dynamic WinGet User Packages across any user profile
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let winget_dir = PathBuf::from(local_app_data)
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
        }

        // 3b. WinGet Links directory
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let candidate = PathBuf::from(local_app_data)
                .join("Microsoft")
                .join("WinGet")
                .join("Links")
                .join("protoc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        // 3c. Scoop user installation
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            let candidate = PathBuf::from(user_profile)
                .join("scoop")
                .join("shims")
                .join("protoc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        // 3d. Chocolatey & Program Files standard installation
        let standard_windows_paths = [
            r"C:\ProgramData\chocolatey\bin\protoc.exe",
            r"C:\tools\protoc\bin\protoc.exe",
            r"C:\Program Files\protoc\bin\protoc.exe",
            r"C:\Program Files (x86)\protoc\bin\protoc.exe",
        ];
        for path_str in standard_windows_paths {
            let candidate = PathBuf::from(path_str);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // 4. Linux standard locations (APT, Snap, Homebrew on Linux)
    #[cfg(target_os = "linux")]
    {
        let standard_linux_paths = [
            "/usr/bin/protoc",
            "/usr/local/bin/protoc",
            "/snap/bin/protoc",
            "/home/linuxbrew/.linuxbrew/bin/protoc",
        ];
        for path_str in standard_linux_paths {
            let candidate = PathBuf::from(path_str);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // 5. macOS standard locations (Homebrew Apple Silicon & Intel)
    #[cfg(target_os = "macos")]
    {
        let standard_macos_paths = [
            "/opt/homebrew/bin/protoc",
            "/usr/local/bin/protoc",
        ];
        for path_str in standard_macos_paths {
            let candidate = PathBuf::from(path_str);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = "proto/sentinel_cdr.proto";
    println!("cargo:rerun-if-changed={}", proto_file);

    // Dynamically locate protoc across any OS / user profile if not explicitly set
    if std::env::var("PROTOC").is_err() {
        if let Some(protoc_path) = locate_protoc_dynamically() {
            println!("cargo:warning=Dynamically resolved protoc: {}", protoc_path.display());
            std::env::set_var("PROTOC", &protoc_path);
        }
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&[proto_file], &["proto"])?;

    Ok(())
}
