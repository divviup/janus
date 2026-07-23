use std::{
    borrow::Cow,
    env::{self, VarError},
    error::Error,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Get the current git commit, and pass it to rustc via an environment variable.
///
/// This build script replaces our previous use of `git-version`, in order to conditionally reduce
/// spurious rebuilds when internal git files change.
///
/// The environment variable GIT_REVISION can be used to supply a revision when git is not
/// available, i.e. in container builds. The same environment variable name is used both for
/// communication from build tooling to this build script and from this build script to rustc.
fn main() {
    // Check for an environment variable input first. This is provided by a Dockerfile or CI build
    // script. This allows us to short-circuit running `git describe`, and lets us avoid file
    // dependencies.
    println!("cargo::rerun-if-env-changed=GIT_REVISION");
    match env::var("GIT_REVISION") {
        Ok(git_revision) => {
            println!("cargo::rustc-env=GIT_REVISION={git_revision}");
            return;
        }
        Err(VarError::NotPresent) => {}
        Err(VarError::NotUnicode(_)) => {
            panic!("invalid value of GIT_REVISION environment variable")
        }
    }

    // Get the path of the current package.
    //
    // We don't need to print "cargo::rerun-if-env-changed=CARGO_MANIFEST_DIR" because "it is not
    // possible to use this for environment variables like TARGET that Cargo sets for build
    // scripts." See
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-env-changed.
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by Cargo"),
    );

    // Run git describe.
    let revision = match git_describe(&manifest_dir) {
        Ok(output) => Cow::Owned(output),
        Err((message, error)) => {
            println!("cargo::warning=Could not determine git revision: {message}, {error}");
            // Use this fallback value if there is no environment variable and using git fails.
            Cow::Borrowed("unknown")
        }
    };

    // Set environment variable for rustc compilation.
    println!("cargo::rustc-env=GIT_REVISION={revision}");
}

/// Run git describe and return the result.
fn git_describe(manifest_dir: &Path) -> Result<String, (&'static str, Box<dyn Error>)> {
    // Locate the git directory.
    let git_dir = run_command(
        Command::new("git")
            .arg("-C")
            .arg(manifest_dir)
            .args(["rev-parse", "--git-dir"]),
    )?;

    // Print file dependencies for git describe.
    println!("cargo::rerun-if-changed={git_dir}/index");
    println!("cargo::rerun-if-changed={git_dir}/logs/HEAD");

    run_command(Command::new("git").arg("-C").arg(manifest_dir).args([
        "describe",
        "--always",
        "--dirty=-modified",
    ]))
}

/// Runs a git command, captures the output, and returns it.
///
/// This uses a tuple as the error type, instead of `anyhow::Error` and `anyhow::Context`, to keep
/// this build script dependency-light, since it is on the critical path.
fn run_command(command: &mut Command) -> Result<String, (&'static str, Box<dyn Error>)> {
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ("Failed to execute git", e.into()))?
        .wait_with_output()
        .map_err(|e| ("Failed to wait for git", e.into()))?;

    if !output.status.success() {
        return Err((
            "git subcommand failed",
            format!(
                "status code {}: {:?}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
            .into(),
        ));
    }

    let mut output = String::from_utf8(output.stdout)
        .map_err(|e| ("Output from git is invalid UTF-8", e.into()))?;
    output.truncate(output.trim_end().len());
    Ok(output)
}
