# Lab 7 - Container and Kubernetes Hardening

## Task 1 - Scan the artifact

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format json \
  --output labs/lab7/results/trivy-image.json
```

| Severity | Findings | Fix available | No fix available |
|---|---:|---:|---:|
| CRITICAL | 12 | 9 | 3 |
| HIGH | 75 | 70 | 5 |
| Total | 87 | 79 | 8 |

These counts represent vulnerability findings in installed packages, not unique CVE identifiers. A fix is considered available when FixedVersion is non-empty.

### Comparison with Lab 4

The Lab 4 Grype SBOM scan reported 183 findings: 14 Critical, 85 High, 65 Medium, 12 Low, and 7 Negligible. Its Critical and High subtotal was 99, compared with 87 in the Trivy scan.

| Severity | Count |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| **Total** | **183** |

The image digest matches the image used in Lab 4. The scans were performed at different times with different vulnerability databases and scanners. Database updates, package matching, and severity selection can explain differences; the totals alone do not establish which scanner is more accurate.

### Top 10 fixable findings

Ordered by severity, with CRITICAL first. Versions are reproduced from the Trivy report.

| Severity | Vulnerability | Package | Installed | Fixed |
|---|---|---|---|---|
| CRITICAL | CVE-2023-46233 | crypto-js | 3.3.0 | 4.2.0 |
| CRITICAL | CVE-2026-71851 | crypto-js | 3.3.0 | 4.0.0 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken | 0.1.0 | 4.2.2 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken | 0.4.0 | 4.2.2 |
| CRITICAL | CVE-2019-10744 | lodash | 2.4.2 | 4.17.12 |
| CRITICAL | CVE-2026-90711 | proxy-addr | 2.0.7 | 2.0.8 |
| CRITICAL | CVE-2026-59873 | tar | 4.4.19 | 7.5.19 |
| CRITICAL | CVE-2026-59873 | tar | 6.2.1 | 7.5.19 |
| CRITICAL | CVE-2026-59873 | tar | 7.5.15 | 7.5.19 |
| HIGH | CVE-2026-14456 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |

### Dockerfile findings

The following Dockerfile was scanned with `trivy config /tmp/df-demo` without a severity filter:

```dockerfile
FROM node:latest
USER root
EXPOSE 22
ADD https://example.com/app.tar /
```

Trivy reported 4 failed checks out of 27:

| Check | Severity | Finding and impact |
|---|---|---|
| DS-0001 | MEDIUM | The latest tag permits unexpected base-image changes and reduces build reproducibility. |
| DS-0002 | HIGH | Running as root increases the impact of a compromised container and can worsen container-escape consequences. |
| DS-0004 | MEDIUM | Exposing SSH advertises an unnecessary management port. EXPOSE alone does not publish the port or start an SSH server. |
| DS-0026 | LOW | No HEALTHCHECK is defined, making application health harder to assess through Docker. This is an operational weakness rather than a direct exploit. |

### Three or four sentences: your image has vulnerabilities with no fix available.

For the eight findings without an available fix, I would assess whether the affected functionality is reachable and disable unnecessary features where possible. Running as a non-root user, dropping capabilities, disabling privilege escalation, and restricting network access reduces the possible impact of exploitation. A read-only root filesystem and disabled ServiceAccount token mounting further restrict what a compromised application can modify or access. I would explain to a manager that these controls reduce risk but do not remove the vulnerable dependencies, so the remaining risk needs monitoring and reassessment when patches become available.


## Task 2 - Run it under restricted

The namespace enforces, warns, and audits the restricted Pod Security profile pinned to v1.33. The Deployment uses a dedicated ServiceAccount with token automount disabled both on the ServiceAccount and on the Pod.

Namespace labels:

```
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/enforce-version: v1.33
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/warn-version: v1.33
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/audit-version: v1.33
```

The Pod runs as UID/GID 65532 with runAsNonRoot enabled and the RuntimeDefault seccomp profile. Both the application and init container disable privilege escalation and drop ALL capabilities. CPU and memory requests and limits are configured, and both containers use the pinned image digest.

Pod securityContext:

```yaml
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
```

Container securityContext, used by both the application and init container:

```yaml
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
```

The command used to verify the running Pod was:

```bash
kubectl --context k3d-lab7 -n juice-shop get pods -o wide
```

It showed juice-shop-75c64b9d5d-7mvxj as 1/1 Running with zero restarts.


The NetworkPolicy selects app=juice-shop and restricts both ingress and egress. It permits TCP port 3000 from Pods labelled access=juice-shop in the same namespace, and DNS over TCP/UDP port 53 to kube-dns Pods in kube-system. NetworkPolicy traffic enforcement was not separately tested; the HTTP check used port-forward.

### Proof the pod is running, and the user id it runs as, with the command that told you.

A server-side dry-run of an unhardened Pod was rejected:

```bash
kubectl --context k3d-lab7 -n juice-shop run restricted-test \
  --image=bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 \
  --restart=Never --dry-run=server -o yaml
```

The rejection identified missing allowPrivilegeEscalation=false, capabilities.drop=["ALL"], runAsNonRoot=true, and an approved seccomp profile.

Disabling ServiceAccount token automount is an additional voluntary control beyond the restricted profile. The application does not need Kubernetes API credentials.

### The two Trivy summaries side by side.

All Kubernetes scans used the k3d-lab7 context, HIGH/CRITICAL filtering, and --disable-node-collector. Node configuration was outside the comparison scope.

| Configuration | CRITICAL vulnerabilities | HIGH vulnerabilities | HIGH misconfigurations | HIGH secret findings |
|---|---:|---:|---:|---:|
| Plain Deployment | 12 | 75 | 3 | 2 |
| Hardened, before read-only filesystem | 12 | 75 | 1 | 2 |
| Final Deployment, raw workload totals | 24 | 150 | 0 | 4 |

The remaining HIGH misconfiguration before the bonus change was KSV-0014: root filesystem is not read-only.

The final Deployment has two containers using the same image: the application and its init container. Trivy aggregates the image findings for both, doubling the raw vulnerability and secret totals. Deduplicating vulnerability findings by VulnerabilityID, PkgName, InstalledVersion, and PkgPath gives the original 12 CRITICAL and 75 HIGH findings.

Hardening removed the reported HIGH/CRITICAL misconfigurations while leaving the vulnerable image packages unchanged. Secret findings were not individually validated.


## Bonus - A read-only root filesystem

`docker diff lab7-writecheck` identified startup writes under:

- /juice-shop/data  -   Runtime SQLite database
- /juice-shop/logs  -   Access and audit logs
- /juice-shop/ftp   -   Generated legal.md
- /juice-shop/i18n  -   Generated translation files
- /juice-shop/frontend/dist/frontend    -   Modified index.html and generated frontend assets
- /juice-shop/.well-known/csaf  -   Updated provider-metadata.json

The final Deployment enables readOnlyRootFilesystem on both containers. An emptyDir volume provides writable subdirectories mounted only at these paths. A non-root init container uses Node.js fs.cpSync to copy their original contents from the same pinned image into the volume before the application starts. This preserves files that would otherwise be hidden by an empty volume, including frontend assets.

fsGroup is set to 65532 for volume access. The volume is ephemeral: its data survives a container restart within the Pod but is removed when the Pod is deleted. This lab setup does not provide persistent database storage.

### Runtime verification

The final Pod was 1/1 Running with zero restarts.

```bash
kubectl --context k3d-lab7 -n juice-shop exec deployment/juice-shop \
  -c juice-shop -- /nodejs/bin/node -p 'process.getuid()'
```

Output:

```text
65532
```

Using the absolute Node.js path was necessary because `node` was not available through PATH.

```bash
kubectl --context k3d-lab7 -n juice-shop port-forward \
  deployment/juice-shop 3007:3000

curl --fail --silent --show-error \
  -o /dev/null -w 'HTTP %{http_code}\n' \
  http://127.0.0.1:3007/
```

Output:

```text
HTTP 200
```

## final

Local evidence was saved under `labs/lab7/results/`, including:

- trivy-image.json and top10-fixable.txt
- dockerfile-scan.txt
- restricted-rejection.txt
- trivy-plain.txt, trivy-hardened.txt, and trivy-readonly.txt
- docker-diff.txt
- pods-ready.txt, runtime-uid.txt, and http-check.txt
- k8s-vulns-deduplicated.json

The final Pod specification is saved as `labs/lab7/results/pod-spec.yaml`.
The final Kubernetes scan is saved as `labs/lab7/results/trivy-k8s.json`.