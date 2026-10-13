use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

fn verify_sha256(path: &Path, expected: &str) {
    let mut file = fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("read pinned ICU asset");
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        expected,
        "pinned ICU asset changed: {}",
        path.display()
    );
}

fn run(mut command: Command, label: &str) {
    let output = command.output().unwrap_or_else(|e| panic!("{label}: {e}"));
    if !output.status.success() {
        let diagnostics = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let tail = diagnostics.chars().rev().take(4000).collect::<String>();
        let tail = tail.chars().rev().collect::<String>();
        panic!("{label} failed ({}):\n{tail}", output.status);
    }
}

fn with_pic_flag(name: &str) -> String {
    let existing = env::var(name).unwrap_or_else(|error| match error {
        env::VarError::NotPresent => String::new(),
        env::VarError::NotUnicode(_) => panic!("{name} must be UTF-8"),
    });
    format!("{existing} -fPIC")
}

fn replace_once(source: String, old: &str, new: &str, label: &str) -> String {
    assert_eq!(
        source.matches(old).count(),
        1,
        "unexpected pinned ICU {label} shape"
    );
    source.replacen(old, new, 1)
}

fn prepare_msvc_project(source: &Path, project: &str, library: &str) {
    let path = source.join(format!("icu/source/{project}/{project}.vcxproj"));
    let input = fs::read_to_string(&path).expect("read pinned ICU MSVC project");
    let patched = replace_once(
        input,
        "<ConfigurationType>DynamicLibrary</ConfigurationType>",
        "<ConfigurationType>StaticLibrary</ConfigurationType>",
        "MSVC library configuration",
    );
    let patched = replace_once(
        patched,
        "<_ProjectFileVersion>10.0.30319.1</_ProjectFileVersion>",
        &format!(
            "<_ProjectFileVersion>10.0.30319.1</_ProjectFileVersion><TargetName>{library}</TargetName>"
        ),
        "MSVC library name",
    );
    let (original_defines, patched_defines) = match project {
        "common" => (
            "<PreprocessorDefinitions>U_ATTRIBUTE_DEPRECATED=;U_COMMON_IMPLEMENTATION;U_PLATFORM_USES_ONLY_WIN32_API=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>",
            "<PreprocessorDefinitions>U_STATIC_IMPLEMENTATION;U_HAVE_LIB_SUFFIX=1;U_LIB_SUFFIX_C_NAME=_peerwork;U_ATTRIBUTE_DEPRECATED=;U_COMMON_IMPLEMENTATION;U_PLATFORM_USES_ONLY_WIN32_API=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>",
        ),
        "i18n" => (
            "<PreprocessorDefinitions>U_ATTRIBUTE_DEPRECATED=;U_I18N_IMPLEMENTATION;%(PreprocessorDefinitions)</PreprocessorDefinitions>",
            "<PreprocessorDefinitions>U_STATIC_IMPLEMENTATION;U_HAVE_LIB_SUFFIX=1;U_LIB_SUFFIX_C_NAME=_peerwork;U_ATTRIBUTE_DEPRECATED=;U_I18N_IMPLEMENTATION;%(PreprocessorDefinitions)</PreprocessorDefinitions>",
        ),
        "stubdata" => (
            "<AdditionalIncludeDirectories>..\\common;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>\n      <PreprocessorDefinitions>STUBDATA_BUILD;%(PreprocessorDefinitions)</PreprocessorDefinitions>",
            "<AdditionalIncludeDirectories>..\\common;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>\n      <PreprocessorDefinitions>U_STATIC_IMPLEMENTATION;U_HAVE_LIB_SUFFIX=1;U_LIB_SUFFIX_C_NAME=_peerwork;STUBDATA_BUILD;%(PreprocessorDefinitions)</PreprocessorDefinitions>",
        ),
        _ => panic!("unexpected ICU MSVC project"),
    };
    let patched = replace_once(
        patched,
        original_defines,
        patched_defines,
        "MSVC static/suffixed symbols",
    );
    // The solution target copies public headers for the dynamic distribution.
    // All three projects compile against the source tree directly instead.
    let patched = if project == "stubdata" {
        assert!(!patched.contains("Windows.CopyUnicodeHeaderFiles.targets"));
        patched
    } else {
        replace_once(
            patched,
            "  <Import Project=\"$(SolutionDir)\\Windows.CopyUnicodeHeaderFiles.targets\" />",
            "",
            "MSVC solution header-copy target",
        )
    };
    fs::write(&path, patched).expect("write patched ICU MSVC project");
}

fn find_msbuild() -> PathBuf {
    println!("cargo:rerun-if-env-changed=PEERWORK_MSBUILD");
    if let Some(path) = env::var_os("PEERWORK_MSBUILD") {
        return PathBuf::from(path);
    }
    if let Some(program_files) = env::var_os("ProgramFiles(x86)") {
        let vswhere =
            PathBuf::from(program_files).join("Microsoft Visual Studio/Installer/vswhere.exe");
        if vswhere.is_file() {
            let output = Command::new(vswhere)
                .args([
                    "-latest",
                    "-products",
                    "*",
                    "-requires",
                    "Microsoft.Component.MSBuild",
                    "-property",
                    "installationPath",
                ])
                .output()
                .expect("query Visual Studio MSBuild installation");
            assert!(
                output.status.success(),
                "Visual Studio MSBuild query failed"
            );
            let root = String::from_utf8(output.stdout).expect("MSBuild installation path UTF-8");
            let path = PathBuf::from(root.trim()).join("MSBuild/Current/Bin/MSBuild.exe");
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("MSBuild.exe")
}

fn build_msvc(source: &Path, target_triple: &str) {
    assert_eq!(
        target_triple, "x86_64-pc-windows-msvc",
        "bundled ICU4C MSVC build currently supports only Windows x64"
    );
    let msbuild = find_msbuild();
    for (project, library) in [
        ("stubdata", "icudatapeerwork"),
        ("common", "icuucpeerwork"),
        ("i18n", "icui18npeerwork"),
    ] {
        prepare_msvc_project(source, project, library);
        let path = source.join(format!("icu/source/{project}/{project}.vcxproj"));
        run(
            {
                let mut command = Command::new(&msbuild);
                command.arg(path).args([
                    "/nologo",
                    "/m",
                    "/p:Configuration=Release",
                    "/p:Platform=x64",
                ]);
                command
            },
            &format!("build pinned ICU4C {project} static library"),
        );
        let output = source.join(format!("icu/source/{project}/x64/Release/{library}.lib"));
        assert!(
            output.is_file(),
            "missing ICU4C static library: {}",
            output.display()
        );
        println!(
            "cargo:rustc-link-search=native={}",
            output.parent().unwrap().display()
        );
    }
    // MSVC's linker resolves static-library references in repeated passes.
    println!("cargo:rustc-link-lib=static=icui18npeerwork");
    println!("cargo:rustc-link-lib=static=icuucpeerwork");
    println!("cargo:rustc-link-lib=static=icudatapeerwork");
}

fn main() {
    println!("cargo:rerun-if-changed=../../third_party/icu4c-78.3/icu4c-78.3-sources.tgz");
    println!("cargo:rerun-if-changed=../../third_party/icu4c-78.3/icudt78l.dat");
    let source_asset = Path::new("../../third_party/icu4c-78.3/icu4c-78.3-sources.tgz");
    let data_asset = Path::new("../../third_party/icu4c-78.3/icudt78l.dat");
    verify_sha256(
        source_asset,
        "3a2e7a47604ba702f345878308e6fefeca612ee895cf4a5f222e7955fabfe0c0",
    );
    verify_sha256(
        data_asset,
        "790a1d07c4a9e4d7de4eab025cc97b54e0097de2ad94408d190ea55c37fcd7e5",
    );

    let target = env::var("CARGO_CFG_TARGET_OS").expect("target OS");
    let host_triple = env::var("HOST").expect("build host triple");
    let target_triple = env::var("TARGET").expect("target triple");
    let cross_arm64_musl = host_triple != target_triple;
    if cross_arm64_musl {
        assert_eq!(
            target_triple, "aarch64-unknown-linux-musl",
            "ICU4C cross-build is implemented only for ARM64 musl"
        );
    }
    if target != "linux" && target != "macos" && target != "windows" {
        panic!("bundled ICU4C build is not yet implemented for target OS {target}");
    }
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let source = out.join("source");
    let build = out.join("build");
    fs::create_dir_all(&source).expect("ICU source directory");
    fs::create_dir_all(&build).expect("ICU build directory");
    let mut extract = Command::new("tar");
    if target != "windows" {
        extract.arg("--no-same-owner");
    }
    extract.arg("-xzf").arg(source_asset).arg("-C").arg(&source);
    run(extract, "extract pinned ICU4C source");
    if target == "windows" {
        build_msvc(&source, &target_triple);
        return;
    }
    if cross_arm64_musl {
        println!("cargo:rerun-if-env-changed=PEERWORK_ICU_ARM64_CC");
        println!("cargo:rerun-if-env-changed=PEERWORK_ICU_ARM64_CXX");
        let cross_cc = PathBuf::from(
            env::var_os("PEERWORK_ICU_ARM64_CC")
                .expect("PEERWORK_ICU_ARM64_CC required for ARM64 ICU cross-build"),
        );
        let cross_cxx = PathBuf::from(
            env::var_os("PEERWORK_ICU_ARM64_CXX")
                .expect("PEERWORK_ICU_ARM64_CXX required for ARM64 ICU cross-build"),
        );
        assert!(
            cross_cc.is_absolute() && cross_cc.is_file(),
            "ARM64 ICU C compiler must be an absolute file"
        );
        assert!(
            cross_cxx.is_absolute() && cross_cxx.is_file(),
            "ARM64 ICU C++ compiler must be an absolute file"
        );
        let host_build = out.join("host-build");
        fs::create_dir_all(&host_build).expect("ICU host-tool build directory");
        run(
            {
                let mut command = Command::new(source.join("icu/source/runConfigureICU"));
                command.current_dir(&host_build).arg("Linux").args([
                    "--enable-static",
                    "--disable-shared",
                    "--with-data-packaging=archive",
                    "--with-library-suffix=peerwork",
                ]);
                command
                    .env_remove("CC")
                    .env_remove("CXX")
                    .env_remove("CFLAGS")
                    .env_remove("CXXFLAGS");
                command
            },
            "configure pinned native ICU host tools",
        );
        run(
            {
                let mut command = Command::new("make");
                command.current_dir(&host_build).arg("-j4");
                command
                    .env_remove("CC")
                    .env_remove("CXX")
                    .env_remove("CFLAGS")
                    .env_remove("CXXFLAGS");
                command
            },
            "build pinned native ICU host tools",
        );
        run(
            {
                let mut command = Command::new(source.join("icu/source/runConfigureICU"));
                command
                    .current_dir(&build)
                    .arg("Linux")
                    .args([
                        "--host=aarch64-alpine-linux-musl",
                        "--enable-static",
                        "--disable-shared",
                        "--with-data-packaging=archive",
                        "--with-library-suffix=peerwork",
                    ])
                    .arg(format!("--with-cross-build={}", host_build.display()));
                command
                    .env("CC", &cross_cc)
                    .env("CXX", &cross_cxx)
                    .env("CFLAGS", "-fPIC")
                    .env("CXXFLAGS", "-fPIC");
                command
            },
            "configure pinned ICU4C ARM64 cross-build",
        );
        run(
            {
                let mut command = Command::new("make");
                command.current_dir(&build).arg("-j4");
                command
            },
            "build pinned ICU4C ARM64 cross-build",
        );
    } else {
        let gnu_linux_pic = target == "linux" && !target_triple.ends_with("-musl");
        let pic_flags = gnu_linux_pic.then(|| {
            println!("cargo:rerun-if-env-changed=CFLAGS");
            println!("cargo:rerun-if-env-changed=CXXFLAGS");
            (with_pic_flag("CFLAGS"), with_pic_flag("CXXFLAGS"))
        });
        run(
            {
                let mut command = Command::new(source.join("icu/source/runConfigureICU"));
                if let Some((cflags, cxxflags)) = &pic_flags {
                    command.env("CFLAGS", cflags).env("CXXFLAGS", cxxflags);
                }
                if target_triple.ends_with("-musl") {
                    // Alpine's libstdc++ has initial-exec TLS and cannot be loaded
                    // with a Python extension after interpreter startup. libc++
                    // is late-loadable on the native musl runner.
                    command.env("CXX", "clang++-20");
                    command.env("CXXFLAGS", "-stdlib=libc++");
                }
                command.current_dir(&build).args([
                    if target == "macos" { "MacOSX" } else { "Linux" },
                    "--enable-static",
                    "--disable-shared",
                    "--with-data-packaging=archive",
                    "--with-library-suffix=peerwork",
                ]);
                command
            },
            "configure pinned ICU4C",
        );
        run(
            {
                let mut command = Command::new("make");
                if let Some((cflags, cxxflags)) = &pic_flags {
                    command.env("CFLAGS", cflags).env("CXXFLAGS", cxxflags);
                }
                command.current_dir(&build).arg("-j4");
                command
            },
            "build pinned ICU4C",
        );
    }

    println!(
        "cargo:rustc-link-search=native={}",
        build.join("lib").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        build.join("stubdata").display()
    );
    println!("cargo:rustc-link-lib=static=icui18npeerwork");
    println!("cargo:rustc-link-lib=static=icuucpeerwork");
    println!("cargo:rustc-link-lib=static=icudatapeerwork");
    if target == "macos" {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if target_triple.ends_with("-musl") {
        println!("cargo:rerun-if-env-changed=PEERWORK_MUSL_STATIC_CXX");
        match env::var("PEERWORK_MUSL_STATIC_CXX") {
            Ok(value) if value == "1" => {
                println!("cargo:rerun-if-env-changed=PEERWORK_MUSL_CXX_LIB_DIR");
                let library_dir =
                    env::var("PEERWORK_MUSL_CXX_LIB_DIR").unwrap_or_else(|_| "/usr/lib".to_owned());
                for name in ["libc++.a", "libc++abi.a", "libunwind.a"] {
                    assert!(
                        Path::new(&library_dir).join(name).is_file(),
                        "missing static musl C++ runtime archive: {name}"
                    );
                }
                println!("cargo:rustc-link-search=native={library_dir}");
                println!("cargo:rustc-link-lib=static=c++");
                println!("cargo:rustc-link-lib=static=c++abi");
                println!("cargo:rustc-link-lib=static=unwind");
            }
            Err(env::VarError::NotPresent) => println!("cargo:rustc-link-lib=dylib=c++"),
            _ => panic!("PEERWORK_MUSL_STATIC_CXX must be 1 when set"),
        }
        println!("cargo:rustc-link-lib=dylib=pthread");
        println!("cargo:rustc-link-lib=dylib=dl");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=dylib=pthread");
        println!("cargo:rustc-link-lib=dylib=dl");
    }
}
