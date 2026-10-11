use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

/// Builds both eBPF crates (broken and fixed) for the BPF target, mirroring
/// the build.rs of the goya-template host crate.
fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let mut ebpf_packages = Vec::new();
    for wanted in ["eBPF-broken", "eBPF-fixed"] {
        let pkg = packages
            .iter()
            .find(|p| p.name.as_str() == wanted)
            .ok_or_else(|| anyhow!("{} package not found", wanted))?;
        let root = pkg
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {:?}", pkg.manifest_path))?;
        ebpf_packages.push(aya_build::Package {
            name: pkg.name.as_str(),
            root_dir: root.as_str(),
            ..Default::default()
        });
    }
    aya_build::build_ebpf(ebpf_packages, Toolchain::default())
}
