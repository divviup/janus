mod common;
mod daphne;
mod divviup_ts;
mod in_cluster;
mod janus;
mod simulation;

fn initialize_rustls() {
    // Choose aws-lc-rs as the default rustls crypto provider. This is what's currently enabled by
    // the default Cargo feature. Specifying a default provider here prevents runtime errors if
    // another dependency also enables the ring feature.
    let _ = trillium_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}
