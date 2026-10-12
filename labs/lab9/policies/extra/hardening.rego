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
