#[rustfmt::skip]
use std::fs;

/// Copies the generated eBPF ELFs into loader-go/.ebpf/ (mirrors the
/// template's "$project-go/.ebpf/$project-name") so the Go loader can
/// load them:
///   - loader-go/.ebpf/test-broken
///   - loader-go/.ebpf/test-fixed
fn main() -> anyhow::Result<()> {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let ebpf_dir = manifest_dir.join("loader-go").join(".ebpf");
    fs::create_dir_all(&ebpf_dir)?;
    fs::copy(
        concat!(env!("OUT_DIR"), "/eBPF-broken"),
        ebpf_dir.join("test-broken"),
    )?;
    fs::copy(concat!(env!("OUT_DIR"), "/eBPF-fixed"), ebpf_dir.join("test-fixed"))?;
    Ok(())
}
