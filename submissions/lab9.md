# Lab 9 — Runtime Detection and Policy as Code

## Environment

I used macOS with Colima, the VZ VM backend, 4 CPUs and 6 GiB RAM. Docker used the `colima` context; the VM reported Ubuntu 24.04.4 LTS and kernel `6.8.0-117-generic`. `/sys/kernel/btf/vmlinux` was present (`BTF OK`). Falco used image `falcosecurity/falco:0.43.1` with the modern BPF probe and JSON output; the target was `lab9-target`, running `alpine:3.20`.

## Task 1

`Terminal shell in container` fired after spawning a shell with an attached terminal:

```bash
docker exec -t lab9-target sh -lc 'echo hello-from-shell'
```

```json
{
  "hostname": "42bb7a8e6adc",
  "output": "2026-10-12T00:34:27.707005415+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=00433af7e509 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "00433af7e509",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1791765267707005415,
    "evt.type": "execve",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "proc.exepath": "/bin/busybox",
    "proc.name": "sh",
    "proc.pname": "runc",
    "proc.tty": 34816,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": [
    "T1059",
    "container",
    "maturity_stable",
    "mitre_execution",
    "shell"
  ],
  "time": "2026-10-12T00:34:27.707005415Z"
}
```

`Read sensitive file untrusted` fired when `cat` opened `/etc/shadow`:

```bash
docker exec lab9-target sh -c 'cat /etc/shadow'
```

```json
{
  "hostname": "42bb7a8e6adc",
  "output": "2026-10-12T00:34:31.224871632+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=00433af7e509 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "00433af7e509",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791765271224871632,
    "evt.type": "openat",
    "fd.name": "/etc/shadow",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.aname[2]": "systemd",
    "proc.aname[3]": null,
    "proc.aname[4]": null,
    "proc.cmdline": "cat /etc/shadow",
    "proc.exepath": "/bin/busybox",
    "proc.name": "cat",
    "proc.pname": "containerd-shim",
    "proc.tty": 0,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": [
    "T1555",
    "container",
    "filesystem",
    "host",
    "maturity_stable",
    "mitre_credential_access"
  ],
  "time": "2026-10-12T00:34:31.224871632Z"
}
```

### Custom rule

The rule is stored: `labs/lab9/falco/rules/custom-rules.yaml`
It combines the shipped `open_write` macro, `container.id != host`, and `fd.name startswith /tmp/`. It checks a successful regular-file open for writing, so this detects opening a file for writing rather than proving that bytes were written.

```bash
docker kill --signal=SIGHUP falco
docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
```

```json
{
  "hostname": "42bb7a8e6adc",
  "output": "2026-10-12T00:35:38.292045553+0000: Warning Container /tmp write (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) container_id=00433af7e509 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "00433af7e509",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791765338292045553,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-10-12T00:35:38.292045553Z"
}
```

The top-level JSON field `hostname` is absent from the human-readable `output` string. Here it identifies the Falco sensor container (`42bb7a8e6adc`), not the physical Mac. During an incident this helps identify which sensor produced an alert when events from multiple sensors are collected together.

A legitimate image-processing service might open temporary files under `/tmp` for every uploaded image and trigger this rule repeatedly. I would identify its expected image, process, and dedicated temporary directory, then add a narrowly scoped exception combining those attributes. Writes by other processes or outside that directory would still alert. I would review the exception after workload changes instead of excluding every `/tmp` write from that container.

## Task 2


Before adding my extension, I ran:

```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies --all-namespaces
```

| Manifest | Tests | Passed | Warnings | Failures | Exceptions |
| --- | ---: | ---: | ---: | ---: | ---: |
| Kubernetes hardened | 30 | 30 | 0 | 0 | 0 |
| Kubernetes unhardened | 30 | 20 | 2 | 8 | 0 |
| Compose | 15 | 15 | 0 | 0 | 0 |

All eight failures on the unhardened Deployment map to `deny contains msg if` bodies in `labs/lab9/policies/k8s-security.rego`, package `k8s.security`:

| Failure | Rego condition in the corresponding deny body |
| --- | --- |
| Image uses `:latest` | `endswith(c.image, ":latest")` |
| Missing/false non-root setting | `not c.securityContext.runAsNonRoot` |
| Privilege escalation allowed or unspecified | `not c.securityContext.allowPrivilegeEscalation == false` |
| Writable root filesystem | `not c.securityContext.readOnlyRootFilesystem == true` |
| Missing CPU request | `not c.resources.requests.cpu` |
| Missing memory request | `not c.resources.requests.memory` |
| Missing CPU limit | `not c.resources.limits.cpu` |
| Missing memory limit | `not c.resources.limits.memory` |

The two warnings came from `not c.livenessProbe` and `not c.readinessProbe`. In particular, the `:latest` failure comes from the image-tag deny body, while the privilege-escalation failure comes from the deny body requiring an explicit `false` value.

The same requirement needs separate rules because Kubernetes stores containers under `input.spec.template.spec.containers`, whereas Compose stores services under `input.services` and uses different security-setting keys. Compose passing shows that the supplied Compose configuration satisfies its applicable policy checks; it does not prove that the deployed application is secure or that Kubernetes failures are irrelevant.

### policy and the manifest

My policy is `labs/lab9/policies/extra/hardening.rego`. The deny requires a SHA-256 image digest; the warn flags a Deployment sharing the host network. Both messages name the container, and `--all-namespaces` includes package `k8s.extra` alongside the shipped packages.

```rego
package k8s.extra

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not regex.match(`@sha256:[a-f0-9]{64}$`, c.image)
  msg := sprintf("container %q must pin its image by sha256 digest", [c.name])
}

warn contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.hostNetwork == true
  c := input.spec.template.spec.containers[_]
  msg := sprintf("container %q shares the host network; prefer pod networking", [c.name])
}
```

I copied the hardened manifest into `labs/lab9/policies/extra/violates-hardening.yaml`, replaced its digest reference with `bkimminich/juice-shop:v19.0.0`, and enabled `hostNetwork: true`. The file deliberately preserves the other hardened settings so that these two new checks explain the new findings. The original image-line comment about digest pinning was inherited from the source; the actual tag below intentionally violates that requirement.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juice-hardened
spec:
  replicas: 1
  selector:
    matchLabels: { app: juice }
  template:
    metadata:
      labels: { app: juice }
    spec:
      hostNetwork: true
      containers:
        - name: juice
          image: bkimminich/juice-shop:v19.0.0  # juice-shop v19.0.0, pinned by digest
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: "100m", memory: "256Mi" }
            limits:   { cpu: "500m", memory: "512Mi" }
          ports:
            - containerPort: 3000
          readinessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 10
            periodSeconds: 20
---
apiVersion: v1
kind: Service
metadata:
  name: juice-hardened
spec:
  selector: { app: juice }
  ports:
    - port: 80
      targetPort: 3000
```

Actual runs with the extension installed:

```text
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test labs/lab9/policies/extra/violates-hardening.yaml --policy labs/lab9/policies --all-namespaces
WARN - labs/lab9/policies/extra/violates-hardening.yaml - k8s.extra - container "juice" shares the host network; prefer pod networking
FAIL - labs/lab9/policies/extra/violates-hardening.yaml - k8s.extra - container "juice" must pin its image by sha256 digest
34 tests, 32 passed, 1 warning, 1 failure, 0 exceptions
```

If I could retain only one mechanism for image digest pinning, I would keep Conftest in CI because it rejects a mutable image reference before deployment. The digest requirement is a property of the manifest and is straightforward to check there. Runtime monitoring still helps detect behavior after a pinned image starts, including a compromised process writing files or attempting mining connections. A pinned image can contain vulnerable or malicious code, so passing the manifest check cannot replace observing what runs.

## Bonus

### Rule and alert it produced

```yaml
- rule: Write to /tmp by container
  desc: Detect a file opened for writing under /tmp inside a container
  condition: open_write and container.id != host and fd.name startswith /tmp/
  output: "Container /tmp write (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)"
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect miner-like processes or lab netcat attempting connections to common mining ports
  condition: >
    evt.type=connect and container.id != host
    and proc.name in (xmrig, ethminer, cgminer, nc)
    and (
      fd.sport in (3333, 4444, 5555, 7777, 14444)
      or evt.arg.addr endswith ":3333"
      or evt.arg.addr endswith ":4444"
      or evt.arg.addr endswith ":5555"
      or evt.arg.addr endswith ":7777"
      or evt.arg.addr endswith ":14444"
    )
  output: "Possible mining connection (container=%container.name process=%proc.name command=%proc.cmdline destination=%evt.arg.addr result=%evt.arg.res)"
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

Task combines a process-name signal and a mining-port signal within a container connection attempt. `nc` is included solely as a safe lab simulation; it is not evidence that netcat itself is a miner, and this inclusion can cause false positives. No real mining pool was contacted.

```bash
docker kill --signal=SIGHUP falco
docker exec lab9-target nc -w 2 127.0.0.1 3333
docker logs --since 1m falco > labs/lab9/falco/logs/bonus.log 2>&1
```

```json
{
  "hostname": "42bb7a8e6adc",
  "output": "2026-10-12T00:43:35.724517793+0000: Critical Possible mining connection (container=lab9-target process=nc command=nc -w 2 127.0.0.1 3333 destination=127.0.0.1:3333 result=ECONNREFUSED) container_id=00433af7e509 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "00433af7e509",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.addr": "127.0.0.1:3333",
    "evt.arg.res": "ECONNREFUSED",
    "evt.time.iso8601": 1791765815724517793,
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "proc.name": "nc"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "source": "syscall",
  "tags": [
    "container",
    "mitre_command_and_control",
    "mitre_execution"
  ],
  "time": "2026-10-12T00:43:35.724517793Z"
}
```

The refused connection still produced a `connect` syscall event with destination `127.0.0.1:3333` and result `ECONNREFUSED`. Falco observes kernel syscall events, so the attempt is visible even though no application connection was established. In this environment the diagnostic event showed `fd.sip` and `fd.sport` as null for the refused attempt, while `evt.arg.addr` retained the destination; the final rule therefore also checks that argument. I removed deprecated `evt.dir` and the temporary diagnostic rule before collecting this final alert.

Changing the pool port or executable name is cheap, so neither signal alone is expensive to evade. Avoiding the underlying need to execute mining code and use substantial compute resources while communicating with a pool is more expensive, although a proxy can conceal the pool endpoint. I would correlate unexpected sustained CPU consumption with process ancestry, executable provenance, and outbound destinations across ports. DNS and network-flow evidence could add coverage for renamed miners using TLS or proxies, with workload-specific baselines to control false positives.
