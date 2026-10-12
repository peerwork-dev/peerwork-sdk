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
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail = stderr.chars().rev().take(4000).collect::<String>();
        let tail = tail.chars().rev().collect::<String>();
        panic!("{label} failed ({}):\n{tail}", output.status);
    }
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
    if target != "linux" && target != "macos" {
        panic!("bundled ICU4C build is not yet implemented for target OS {target}");
    }
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let source = out.join("source");
    let build = out.join("build");
    fs::create_dir_all(&source).expect("ICU source directory");
    fs::create_dir_all(&build).expect("ICU build directory");
    run(
        {
            let mut command = Command::new("tar");
            command
                .arg("--no-same-owner")
                .arg("-xzf")
                .arg(source_asset)
                .arg("-C")
                .arg(&source);
            command
        },
        "extract pinned ICU4C source",
    );
    run(
        {
            let mut command = Command::new(source.join("icu/source/runConfigureICU"));
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
            command.current_dir(&build).arg("-j4");
            command
        },
        "build pinned ICU4C",
    );

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
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=dylib=pthread");
        println!("cargo:rustc-link-lib=dylib=dl");
    }
}
