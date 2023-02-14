use rustc_version::version;

fn main() {
    let rustc_semver = version().expect("could not parse rustc version");
    println!("cargo:rustc-env=RUSTC_SEMVER={rustc_semver}");
}
