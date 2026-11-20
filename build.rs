use std::{env, path::PathBuf};

use libbpf_cargo::SkeletonBuilder;

fn main() {
    assert!(
        env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
            && env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64"),
        "Phase 1 builds on x86_64 Linux"
    );

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    SkeletonBuilder::new()
        .source("bpf/lnfr.bpf.c")
        .obj(out.join("lnfr.bpf.o"))
        .clang_args(["-I/usr/include/x86_64-linux-gnu", "-Wall", "-Werror"])
        .build_and_generate(out.join("lnfr.skel.rs"))
        .expect("compile the BPF probe and generate its skeleton");
    println!("cargo:rerun-if-changed=bpf/lnfr.bpf.c");
}
