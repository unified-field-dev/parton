//! Docker CLI runner seam for templated exec (injectable in tests).

use std::process::{Command, Output, Stdio};

/// Output of one `docker …` invocation.
#[derive(Debug, Clone)]
pub(crate) struct CommandOutput {
    pub status_success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub(crate) fn from_output(output: &Output) -> Self {
        Self {
            status_success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }
    }

    pub(crate) fn combined(&self) -> String {
        let mut s = self.stdout.clone();
        if !self.stderr.is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(&self.stderr);
        }
        s
    }
}

/// Runs `docker` with the given argv (excluding the `docker` binary name).
pub(crate) trait DockerCliRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<CommandOutput>;
}

/// Production runner via the `docker` CLI.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ProcessDockerCliRunner;

impl DockerCliRunner for ProcessDockerCliRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<CommandOutput> {
        let output = Command::new("docker")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| anyhow::anyhow!("failed to spawn docker: {e}"))?;
        Ok(CommandOutput::from_output(&output))
    }
}
