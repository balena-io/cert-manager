target "default" {
  dockerfile = "Dockerfile.template"
  platforms = [
    "linux/amd64",
    "linux/arm64"
  ]
}
