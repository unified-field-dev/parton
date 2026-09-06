use super::diagnostic::run_diagnostic;
use super::docker_args::docker_args_for_action;
use super::docker_exec::{
    ensure_docker_image_with_runner, general_action_payload, normalize_docker_id,
    redact_env_var_values, run_docker_command_with_runner, DockerCommandRunner,
};
use super::wireguard::{
    validate_wireguard_peer_spec, wireguard_peer_response_with_runner, WgCommandRunner,
};
use super::*;
use base64::Engine;
use serde_json::json;
use serial_test::serial;
use std::collections::HashMap;
use std::process::Output;

fn clear_docker_policy_env() {
    std::env::remove_var("PARTON_ALLOW_HOST_NETWORK");
    std::env::remove_var("PARTON_ALLOW_HOST_MOUNTS");
    std::env::remove_var("PARTON_REQUIRE_IMAGE_DIGEST");
    std::env::remove_var("PARTON_ALLOW_MUTABLE_TAGS");
}

fn clear_cosign_env() {
    for k in [
        "PARTON_COSIGN_MODE",
        "PARTON_COSIGN_KEY",
        "PARTON_COSIGN_CERTIFICATE_IDENTITY",
        "PARTON_COSIGN_CERTIFICATE_OIDC_ISSUER",
        "PARTON_COSIGN_BIN",
    ] {
        std::env::remove_var(k);
    }
}

fn write_cosign_stub(exit_code: i32) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cosign-stub");
    std::fs::write(&path, format!("#!/bin/sh\nexit {exit_code}\n")).expect("write stub");
    let mut perms = std::fs::metadata(&path).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
    (dir, path)
}

const COSIGN_DIGEST_PINNED: &str =
    "ghcr.io/acme/svc@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Records whether the executor was invoked (for cosign gate tests).
struct RecordingCallExecutor {
    called: std::cell::Cell<bool>,
}

impl RecordingCallExecutor {
    fn new() -> Self {
        Self {
            called: std::cell::Cell::new(false),
        }
    }
}

impl ContainerActionExecutor for RecordingCallExecutor {
    fn execute_action(
        &self,
        request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        self.called.set(true);
        Ok(ContainerActionResponse {
            action: request.action,
            container_ref: request.container_ref.clone(),
            success: true,
            message: "stub ok".to_string(),
            payload: serde_json::json!({}),
        })
    }
}

#[test]
#[serial]
fn deploy_reaches_executor_when_cosign_stub_succeeds() {
    clear_docker_policy_env();
    clear_cosign_env();
    let (_dir, stub) = write_cosign_stub(0);
    std::env::set_var("PARTON_COSIGN_MODE", "key");
    std::env::set_var("PARTON_COSIGN_KEY", "/tmp/cosign.pub");
    std::env::set_var("PARTON_COSIGN_BIN", stub.to_str().expect("utf8"));
    let executor = RecordingCallExecutor::new();
    let req = deploy_request(COSIGN_DIGEST_PINNED);
    execute_container_action(&executor, &req).expect("cosign ok → deploy");
    assert!(executor.called.get(), "executor must run after cosign ok");
    clear_cosign_env();
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_never_reaches_executor_when_cosign_stub_fails() {
    clear_docker_policy_env();
    clear_cosign_env();
    let (_dir, stub) = write_cosign_stub(1);
    std::env::set_var("PARTON_COSIGN_MODE", "key");
    std::env::set_var("PARTON_COSIGN_KEY", "/tmp/cosign.pub");
    std::env::set_var("PARTON_COSIGN_BIN", stub.to_str().expect("utf8"));
    let executor = RecordingCallExecutor::new();
    let req = deploy_request(COSIGN_DIGEST_PINNED);
    let err = execute_container_action(&executor, &req).expect_err("cosign fail");
    assert!(
        err.to_string().contains("cosign verify failed"),
        "got: {err}"
    );
    assert!(
        !executor.called.get(),
        "executor must not run on cosign fail"
    );
    clear_cosign_env();
    clear_docker_policy_env();
}

fn deploy_request(image_ref: &str) -> ContainerActionRequest {
    ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "svc".to_string(),
        action: ContainerActionKind::Deploy,
        tail_lines: None,
        image_ref: Some(image_ref.to_string()),
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    }
}

struct NoopExecutor;
impl ContainerActionExecutor for NoopExecutor {
    fn execute_action(
        &self,
        _request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        unreachable!("policy validation should fail before executor call");
    }
}

/// Stub executor for the "policy allows this request" branch of these tests: returns success
/// without touching Docker, so reaching it (instead of failing validation) is the assertion.
struct AlwaysOkExecutor;
impl ContainerActionExecutor for AlwaysOkExecutor {
    fn execute_action(
        &self,
        request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        Ok(ContainerActionResponse {
            action: request.action,
            container_ref: request.container_ref.clone(),
            success: true,
            message: "stub ok".to_string(),
            payload: serde_json::json!({}),
        })
    }
}

#[test]
#[serial]
fn deploy_with_host_network_denied_by_default() {
    clear_docker_policy_env();
    let mut req = deploy_request(
        "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    req.network = Some("host".to_string());
    let err = execute_container_action(&NoopExecutor, &req).expect_err("host network denied");
    assert!(err.to_string().contains("PARTON_ALLOW_HOST_NETWORK"));
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_host_network_allowed_when_opted_in() {
    clear_docker_policy_env();
    std::env::set_var("PARTON_ALLOW_HOST_NETWORK", "1");
    let mut req = deploy_request(
        "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    req.network = Some("host".to_string());
    assert!(execute_container_action(&AlwaysOkExecutor, &req).is_ok());
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_non_host_network_is_unaffected() {
    clear_docker_policy_env();
    let mut req = deploy_request(
        "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    req.network = Some("bridge".to_string());
    assert!(execute_container_action(&AlwaysOkExecutor, &req).is_ok());
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_absolute_host_mount_denied_by_default() {
    clear_docker_policy_env();
    let mut req = deploy_request(
        "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    req.volume_mounts = vec![VolumeMount {
        host_path: "/home/user/data".to_string(),
        container_path: "/data".to_string(),
        read_only: false,
    }];
    let err = execute_container_action(&NoopExecutor, &req).expect_err("host mount denied");
    assert!(err.to_string().contains("PARTON_ALLOW_HOST_MOUNTS"));
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_docker_socket_mount_always_denied_even_when_opted_in() {
    clear_docker_policy_env();
    std::env::set_var("PARTON_ALLOW_HOST_MOUNTS", "1");
    let mut req = deploy_request(
        "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    req.volume_mounts = vec![VolumeMount {
        host_path: "/var/run/docker.sock".to_string(),
        container_path: "/var/run/docker.sock".to_string(),
        read_only: false,
    }];
    let err = execute_container_action(&NoopExecutor, &req).expect_err("docker.sock always denied");
    assert!(err.to_string().contains("always-denied"));
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_absolute_host_mount_allowed_when_opted_in() {
    clear_docker_policy_env();
    std::env::set_var("PARTON_ALLOW_HOST_MOUNTS", "1");
    let mut req = deploy_request(
        "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    req.volume_mounts = vec![VolumeMount {
        host_path: "/home/user/data".to_string(),
        container_path: "/data".to_string(),
        read_only: false,
    }];
    assert!(execute_container_action(&AlwaysOkExecutor, &req).is_ok());
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_named_volume_is_unaffected_by_host_mount_policy() {
    clear_docker_policy_env();
    let mut req = deploy_request(
        "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    req.volume_mounts = vec![VolumeMount {
        host_path: "my-named-volume".to_string(),
        container_path: "/data".to_string(),
        read_only: false,
    }];
    assert!(execute_container_action(&AlwaysOkExecutor, &req).is_ok());
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_mutable_tag_denied_by_default() {
    clear_docker_policy_env();
    let req = deploy_request("ghcr.io/acme/service-a:latest");
    let err = execute_container_action(&NoopExecutor, &req).expect_err("mutable tag denied");
    assert!(err.to_string().contains("PARTON_ALLOW_MUTABLE_TAGS"));
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_digest_pinned_image_allowed_by_default() {
    clear_docker_policy_env();
    let req = deploy_request("ghcr.io/acme/service-a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(execute_container_action(&AlwaysOkExecutor, &req).is_ok());
    clear_docker_policy_env();
}

#[test]
#[serial]
fn deploy_with_mutable_tag_allowed_when_opted_in() {
    clear_docker_policy_env();
    std::env::set_var("PARTON_ALLOW_MUTABLE_TAGS", "1");
    let req = deploy_request("ghcr.io/acme/service-a:latest");
    assert!(execute_container_action(&AlwaysOkExecutor, &req).is_ok());
    clear_docker_policy_env();
}

#[test]
#[serial]
fn require_image_digest_env_overrides_allow_mutable_tags() {
    clear_docker_policy_env();
    std::env::set_var("PARTON_ALLOW_MUTABLE_TAGS", "1");
    std::env::set_var("PARTON_REQUIRE_IMAGE_DIGEST", "1");
    let req = deploy_request("ghcr.io/acme/service-a:latest");
    let err = execute_container_action(&NoopExecutor, &req)
        .expect_err("explicit PARTON_REQUIRE_IMAGE_DIGEST=1 wins over PARTON_ALLOW_MUTABLE_TAGS");
    assert!(err.to_string().contains("sha256"));
    clear_docker_policy_env();
}

#[test]
#[serial]
fn ensure_docker_image_with_mutable_tag_denied_by_default() {
    clear_docker_policy_env();
    let req = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "registry-preload".to_string(),
        action: ContainerActionKind::EnsureDockerImage,
        tail_lines: None,
        image_ref: Some("ghcr.io/acme/service-a:latest".to_string()),
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let err = execute_container_action(&NoopExecutor, &req).expect_err("mutable tag denied");
    assert!(err.to_string().contains("PARTON_ALLOW_MUTABLE_TAGS"));
    clear_docker_policy_env();
}

struct StubRunner {
    output: Output,
}

impl DockerCommandRunner for StubRunner {
    fn run(&self, _args: &[String]) -> anyhow::Result<Output> {
        Ok(self.output.clone())
    }
}

fn output(status: i32, stdout: &str, stderr: &str) -> Output {
    use std::os::unix::process::ExitStatusExt;
    Output {
        status: std::process::ExitStatus::from_raw(status),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[test]
fn ensure_docker_image_inspect_hit_skips_pull() {
    use std::cell::Cell;
    struct HitCount {
        inspect: Output,
        calls: Cell<usize>,
    }
    impl DockerCommandRunner for HitCount {
        fn run(&self, _args: &[String]) -> anyhow::Result<Output> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.inspect.clone())
        }
    }
    let runner = HitCount {
        inspect: output(0, "{}", ""),
        calls: Cell::new(0),
    };
    let (mode, payload) = ensure_docker_image_with_runner("registry:3", &runner).expect("ok");
    assert_eq!(mode, "inspect");
    assert_eq!(runner.calls.get(), 1);
    assert_eq!(
        payload["registry_image_preflight"].as_str(),
        Some("inspect")
    );
}

#[test]
fn ensure_docker_image_pull_after_inspect_miss() {
    use std::cell::Cell;
    struct TwoShot {
        miss: Output,
        ok: Output,
        phase: Cell<u8>,
    }
    impl DockerCommandRunner for TwoShot {
        fn run(&self, _args: &[String]) -> anyhow::Result<Output> {
            let p = self.phase.get();
            self.phase.set(p + 1);
            Ok(if p == 0 {
                self.miss.clone()
            } else {
                self.ok.clone()
            })
        }
    }
    let runner = TwoShot {
        miss: output(1, "", "No such image"),
        ok: output(0, "pulled", ""),
        phase: Cell::new(0),
    };
    let (mode, _) = ensure_docker_image_with_runner("registry:3", &runner).expect("ok");
    assert_eq!(mode, "pull");
    assert_eq!(runner.phase.get(), 2);
}

#[test]
fn docker_args_for_logs_include_tail() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "service-a".to_string(),
        action: ContainerActionKind::Logs,
        tail_lines: Some(42),
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let args = docker_args_for_action(&request, None).expect("docker args");
    assert_eq!(
        args,
        vec![
            "logs".to_string(),
            "--tail".to_string(),
            "42".to_string(),
            "service-a".to_string()
        ]
    );
}

#[test]
fn docker_args_for_deploy_includes_network_when_set() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "svc".to_string(),
        action: ContainerActionKind::Deploy,
        tail_lines: None,
        image_ref: Some("img:latest".to_string()),
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: Some("nucleus-cell-a".to_string()),
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let args = docker_args_for_action(&request, None).expect("docker args");
    assert!(args.iter().position(|s| s == "--network").is_some());
    let pos = args.iter().position(|s| s == "--network").unwrap();
    assert_eq!(args.get(pos + 1), Some(&"nucleus-cell-a".to_string()));
}

#[test]
fn docker_args_for_deploy_include_name_env_ports_and_image() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "service-a".to_string(),
        action: ContainerActionKind::Deploy,
        tail_lines: None,
        image_ref: Some("ghcr.io/acme/service-a:latest".to_string()),
        env_vars: vec!["RUST_LOG=info".to_string()],
        secret_env_vars: vec![],
        port_mappings: vec!["8080:8080".to_string()],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let args = docker_args_for_action(&request, None).expect("docker args");
    assert_eq!(
        args,
        vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "service-a".to_string(),
            "-e".to_string(),
            "RUST_LOG=info".to_string(),
            "-p".to_string(),
            "8080:8080".to_string(),
            "ghcr.io/acme/service-a:latest".to_string()
        ]
    );
}

#[test]
fn docker_args_for_deploy_include_extra_hosts_before_env() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "cp".to_string(),
        action: ContainerActionKind::Deploy,
        tail_lines: None,
        image_ref: Some("cp:latest".to_string()),
        env_vars: vec!["FOO=1".to_string()],
        secret_env_vars: vec![],
        port_mappings: vec!["3002:3002".to_string()],
        extra_hosts: vec!["host.docker.internal:host-gateway".to_string()],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let args = docker_args_for_action(&request, None).expect("docker args");
    assert_eq!(
        args,
        vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "cp".to_string(),
            "--add-host".to_string(),
            "host.docker.internal:host-gateway".to_string(),
            "-e".to_string(),
            "FOO=1".to_string(),
            "-p".to_string(),
            "3002:3002".to_string(),
            "cp:latest".to_string(),
        ]
    );
}

#[test]
fn docker_args_for_deploy_include_entrypoint_and_command_after_image() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "reg".to_string(),
        action: ContainerActionKind::Deploy,
        tail_lines: None,
        image_ref: Some("registry:3".to_string()),
        env_vars: vec!["FOO=bar".to_string()],
        secret_env_vars: vec![],
        port_mappings: vec!["5000:5000".to_string()],
        entrypoint: Some("/bin/sh".to_string()),
        command: vec![
            json!("-c"),
            json!("mkdir -p /auth && exec /entrypoint.sh /etc/distribution/config.yml"),
        ],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let args = docker_args_for_action(&request, None).expect("docker args");
    assert_eq!(
        args,
        vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "reg".to_string(),
            "-e".to_string(),
            "FOO=bar".to_string(),
            "-p".to_string(),
            "5000:5000".to_string(),
            "--entrypoint".to_string(),
            "/bin/sh".to_string(),
            "registry:3".to_string(),
            "-c".to_string(),
            "mkdir -p /auth && exec /entrypoint.sh /etc/distribution/config.yml".to_string(),
        ]
    );
}

#[test]
fn normalize_docker_id_trims_lowercases_and_strips_sha256() {
    assert_eq!(normalize_docker_id("  AbC  "), "abc");
    assert_eq!(normalize_docker_id("sha256:DeAdBeEf"), "deadbeef");
}

#[test]
fn docker_args_for_deploy_includes_env_file_when_path_provided() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "parton-test-envfile-{}-{}.env",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::write(&path, "HANDOFF_BUNDLE_ROOT_SECRET=abc\n").unwrap();
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "svc".to_string(),
        action: ContainerActionKind::Deploy,
        tail_lines: None,
        image_ref: Some("img:1".to_string()),
        env_vars: vec!["PUBLIC=1".to_string()],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let args = docker_args_for_action(&request, Some(path.as_path())).expect("docker args");
    let pos = args
        .iter()
        .position(|s| s == "--env-file")
        .expect("env-file");
    assert_eq!(args.get(pos + 1).map(String::as_str), path.to_str());
    assert!(args.contains(&"-e".to_string()));
    assert!(args.contains(&"PUBLIC=1".to_string()));
    assert!(
        !args
            .iter()
            .any(|s| s.contains("HANDOFF_BUNDLE_ROOT_SECRET=")),
        "secret must not appear as -e payload: {args:?}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn run_docker_command_returns_stdout_when_present() {
    let runner = StubRunner {
        output: output(0, "ok\n", "warn\n"),
    };
    let result = run_docker_command_with_runner(&runner, &["ps".to_string()]).expect("ok");
    assert_eq!(result, "ok");
}

#[test]
fn run_docker_command_returns_stderr_when_stdout_empty() {
    let runner = StubRunner {
        output: output(0, "", "warning only\n"),
    };
    let result = run_docker_command_with_runner(&runner, &["ps".to_string()]).expect("ok");
    assert_eq!(result, "warning only");
}

#[test]
fn run_docker_command_formats_failure_message_with_both_streams() {
    let runner = StubRunner {
        output: output(1 << 8, "oops", "bad"),
    };
    let err = run_docker_command_with_runner(&runner, &["run".to_string()]).expect_err("fails");
    let msg = err.to_string();
    assert!(msg.contains("docker run failed"));
    assert!(msg.contains("oops | bad"));
}

#[test]
fn execute_container_action_rejects_blank_container_ref() {
    struct NoopExecutor;
    impl ContainerActionExecutor for NoopExecutor {
        fn execute_action(
            &self,
            _request: &ContainerActionRequest,
        ) -> anyhow::Result<ContainerActionResponse> {
            unreachable!("validation should fail before executor call");
        }
    }
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "  ".to_string(),
        action: ContainerActionKind::Start,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let err = execute_container_action(&NoopExecutor, &request).expect_err("blank ref");
    assert!(err.to_string().contains("container_ref is required"));
}

#[test]
fn run_diagnostic_rejects_metadata_ip_target() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "diag".to_string(),
        action: ContainerActionKind::Diagnostic,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: Some(DiagnosticSpec {
            target_host: "169.254.169.254".to_string(),
            port: 80,
            mode: DiagnosticMode::TcpProbe,
        }),
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let err = run_diagnostic(&request).expect_err("metadata target must be rejected");
    assert!(err.to_string().contains("link-local"));
}

#[test]
fn run_diagnostic_rejects_link_local_target() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "diag".to_string(),
        action: ContainerActionKind::Diagnostic,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: Some(DiagnosticSpec {
            target_host: "169.254.1.1".to_string(),
            port: 8080,
            mode: DiagnosticMode::TcpProbe,
        }),
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let err = run_diagnostic(&request).expect_err("link-local target must be rejected");
    assert!(err.to_string().contains("link-local"));
}

#[test]
fn redact_env_var_values_masks_values_keeps_names() {
    let redacted = redact_env_var_values(&[
        "PUBLIC=1".to_string(),
        "API_KEY=super-secret".to_string(),
        "NO_EQUALS_SIGN".to_string(),
    ]);
    assert_eq!(
        redacted,
        vec![
            "PUBLIC=[REDACTED]".to_string(),
            "API_KEY=[REDACTED]".to_string(),
            "NO_EQUALS_SIGN".to_string(),
        ]
    );
}

/// F11: deploy result payloads must never echo `env_vars` values back to the control plane.
#[test]
fn general_action_payload_for_deploy_redacts_env_var_values() {
    let mut request = deploy_request(
        "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    request.env_vars = vec!["DATABASE_URL=postgres://user:hunter2@host/db".to_string()];
    let payload = general_action_payload(&request, "container-id-123");
    let env_vars = payload["env_vars"].as_array().expect("env_vars array");
    assert_eq!(env_vars.len(), 1);
    assert_eq!(env_vars[0].as_str(), Some("DATABASE_URL=[REDACTED]"));
    let rendered = payload.to_string();
    assert!(
        !rendered.contains("hunter2"),
        "secret value leaked into payload: {rendered}"
    );
}

#[test]
fn execute_container_action_rejects_deploy_without_image_ref() {
    struct NoopExecutor;
    impl ContainerActionExecutor for NoopExecutor {
        fn execute_action(
            &self,
            _request: &ContainerActionRequest,
        ) -> anyhow::Result<ContainerActionResponse> {
            unreachable!("validation should fail before executor call");
        }
    }
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "service-a".to_string(),
        action: ContainerActionKind::Deploy,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let err = execute_container_action(&NoopExecutor, &request).expect_err("missing image_ref");
    assert!(err.to_string().contains("image_ref is required for deploy"));
}

fn wireguard_request(interface: &str, spec: Option<WireguardPeerSpec>) -> ContainerActionRequest {
    ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: interface.to_string(),
        action: ContainerActionKind::WireguardPeer,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: spec,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    }
}

/// A valid base64-encoded 32-byte Wireguard public key for tests.
fn valid_wg_pubkey() -> String {
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

fn valid_wireguard_spec() -> WireguardPeerSpec {
    WireguardPeerSpec {
        peer_public_key: valid_wg_pubkey(),
        endpoint: "203.0.113.5:51820".to_string(),
        allowed_ips: "10.10.0.2/32, fd00::2/128".to_string(),
    }
}

struct RecordingWgRunner {
    output: Output,
    seen_args: std::cell::RefCell<Option<Vec<String>>>,
}

impl WgCommandRunner for RecordingWgRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<Output> {
        *self.seen_args.borrow_mut() = Some(args.to_vec());
        Ok(self.output.clone())
    }
}

struct ErrRunner;
impl WgCommandRunner for ErrRunner {
    fn run(&self, _args: &[String]) -> anyhow::Result<Output> {
        anyhow::bail!("wg: command not found")
    }
}

#[test]
fn wireguard_peer_rejects_invalid_pubkey() {
    let mut spec = valid_wireguard_spec();
    spec.peer_public_key = "not-base64!!".to_string();
    let err = validate_wireguard_peer_spec(&spec).expect_err("invalid base64 rejected");
    assert!(err.to_string().contains("peer_public_key"));
}

#[test]
fn wireguard_peer_rejects_short_pubkey() {
    let mut spec = valid_wireguard_spec();
    spec.peer_public_key = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
    let err = validate_wireguard_peer_spec(&spec).expect_err("short key rejected");
    assert!(err.to_string().contains("32 bytes"));
}

#[test]
fn wireguard_peer_rejects_endpoint_without_port() {
    let mut spec = valid_wireguard_spec();
    spec.endpoint = "203.0.113.5".to_string();
    let err = validate_wireguard_peer_spec(&spec).expect_err("missing port rejected");
    assert!(err.to_string().contains("host:port"));
}

#[test]
fn wireguard_peer_rejects_endpoint_bad_port() {
    let mut spec = valid_wireguard_spec();
    spec.endpoint = "203.0.113.5:not-a-port".to_string();
    let err = validate_wireguard_peer_spec(&spec).expect_err("bad port rejected");
    assert!(err.to_string().contains("port"));
}

#[test]
fn wireguard_peer_rejects_empty_allowed_ips() {
    let mut spec = valid_wireguard_spec();
    spec.allowed_ips = "  ".to_string();
    let err = validate_wireguard_peer_spec(&spec).expect_err("empty allowed_ips rejected");
    assert!(err.to_string().contains("allowed_ips"));
}

#[test]
fn wireguard_peer_rejects_allowed_ips_without_prefix() {
    let mut spec = valid_wireguard_spec();
    spec.allowed_ips = "10.10.0.2".to_string();
    let err = validate_wireguard_peer_spec(&spec).expect_err("missing prefix rejected");
    assert!(err.to_string().contains("CIDR"));
}

#[test]
fn wireguard_peer_rejects_allowed_ips_prefix_out_of_range() {
    let mut spec = valid_wireguard_spec();
    spec.allowed_ips = "10.10.0.2/33".to_string();
    let err = validate_wireguard_peer_spec(&spec).expect_err("out-of-range prefix rejected");
    assert!(err.to_string().contains("prefix exceeds"));
}

#[test]
fn wireguard_peer_accepts_valid_spec() {
    validate_wireguard_peer_spec(&valid_wireguard_spec()).expect("valid spec passes");
}

#[test]
fn wireguard_peer_response_runs_wg_set_with_expected_args() {
    let request = wireguard_request("wg0", Some(valid_wireguard_spec()));
    let runner = RecordingWgRunner {
        output: output(0, "", ""),
        seen_args: std::cell::RefCell::new(None),
    };
    let response = wireguard_peer_response_with_runner(&request, &runner).expect("wg set succeeds");
    assert!(response.success);
    assert_eq!(response.message, "wireguard_peer applied");
    let args = runner.seen_args.borrow().clone().expect("runner invoked");
    assert_eq!(
        args,
        vec![
            "set".to_string(),
            "wg0".to_string(),
            "peer".to_string(),
            valid_wg_pubkey(),
            "endpoint".to_string(),
            "203.0.113.5:51820".to_string(),
            "allowed-ips".to_string(),
            "10.10.0.2/32, fd00::2/128".to_string(),
        ]
    );
}

#[test]
fn wireguard_peer_response_fails_closed_when_wg_missing() {
    let request = wireguard_request("wg0", Some(valid_wireguard_spec()));
    let err = wireguard_peer_response_with_runner(&request, &ErrRunner)
        .expect_err("missing wg binary must fail closed, never a synthetic success");
    assert!(err.to_string().contains("wg set failed to run"));
}

#[test]
fn wireguard_peer_response_fails_closed_on_nonzero_exit() {
    let request = wireguard_request("wg0", Some(valid_wireguard_spec()));
    let runner = RecordingWgRunner {
        output: output(1, "", "Unable to access interface: No such device"),
        seen_args: std::cell::RefCell::new(None),
    };
    let err = wireguard_peer_response_with_runner(&request, &runner)
        .expect_err("nonzero wg exit must fail closed");
    assert!(err.to_string().contains("No such device"));
}

#[test]
fn wireguard_peer_response_rejects_blank_interface() {
    let request = wireguard_request("   ", Some(valid_wireguard_spec()));
    let runner = RecordingWgRunner {
        output: output(0, "", ""),
        seen_args: std::cell::RefCell::new(None),
    };
    let err = wireguard_peer_response_with_runner(&request, &runner)
        .expect_err("blank interface rejected");
    assert!(err.to_string().contains("container_ref"));
    assert!(runner.seen_args.borrow().is_none(), "wg must not run");
}

#[test]
fn wireguard_peer_response_rejects_missing_spec() {
    let request = wireguard_request("wg0", None);
    let runner = RecordingWgRunner {
        output: output(0, "", ""),
        seen_args: std::cell::RefCell::new(None),
    };
    let err =
        wireguard_peer_response_with_runner(&request, &runner).expect_err("missing spec rejected");
    assert!(err.to_string().contains("wireguard_peer spec missing"));
}

#[test]
fn execute_container_action_wireguard_peer_end_to_end_via_executor() {
    struct WgExecutor;
    impl ContainerActionExecutor for WgExecutor {
        fn execute_action(
            &self,
            request: &ContainerActionRequest,
        ) -> anyhow::Result<ContainerActionResponse> {
            let runner = RecordingWgRunner {
                output: output(0, "", ""),
                seen_args: std::cell::RefCell::new(None),
            };
            wireguard_peer_response_with_runner(request, &runner)
        }
    }
    let request = wireguard_request("wg0", Some(valid_wireguard_spec()));
    let response = execute_container_action(&WgExecutor, &request).expect("action succeeds");
    assert!(response.success);
    assert_eq!(response.payload["interface"], json!("wg0"));
}

#[test]
fn execute_container_action_rejects_missing_grow_fs_spec() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "growfs-1".to_string(),
        action: ContainerActionKind::GrowFs,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let err = execute_container_action(&DockerCliActionExecutor, &request)
        .expect_err("missing grow_fs spec rejected");
    assert!(
        err.to_string().contains("grow_fs spec is required"),
        "got: {err}"
    );
}

#[test]
fn execute_container_action_rejects_unsafe_grow_fs_mount_path() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "growfs-1".to_string(),
        action: ContainerActionKind::GrowFs,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: Some(GrowFsSpec {
            mount_path: "../etc".to_string(),
        }),
        templated_exec: None,
        expected_container_id: None,
    };
    let err = execute_container_action(&DockerCliActionExecutor, &request)
        .expect_err("unsafe mount_path rejected");
    assert!(
        err.to_string().contains("absolute") || err.to_string().contains(".."),
        "got: {err}"
    );
}

#[test]
fn execute_container_action_rejects_missing_templated_exec_spec() {
    let request = ContainerActionRequest {
        node_id: "node-1".to_string(),
        container_ref: "pg-1".to_string(),
        action: ContainerActionKind::TemplatedExec,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let err = execute_container_action(&DockerCliActionExecutor, &request)
        .expect_err("missing templated_exec spec rejected");
    assert!(
        err.to_string().contains("templated_exec spec is required"),
        "got: {err}"
    );
}
