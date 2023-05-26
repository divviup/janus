use std::{
    io::Write,
    process::{Command, Stdio},
};

pub fn save_zstd_compressed_docker_image<W: Write>(image_id: &str, writer: W) {
    let mut save_child = Command::new("docker")
        .args(["save", image_id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to execute `docker save`");
    let save_stdout = save_child.stdout.take().unwrap();
    zstd::stream::copy_encode(save_stdout, writer, 0)
        .expect("Couldn't write compressed image file");
    let save_child_status = save_child.wait().expect("Couldn't wait on `docker save`");
    assert!(save_child_status.success(), "`docker save` failed");
}
