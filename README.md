# Flux E2E Testing Repository

A comprehensive GitOps repository for end-to-end testing of Kubernetes deployments using Flux CD, featuring a complete observability stack with monitoring, logging, and secure networking via Tailscale.

## Overview

This repository demonstrates a production-ready GitOps workflow using Flux CD to deploy and manage a Kubernetes cluster with:

- **GitOps**: Flux CD for continuous delivery
- **Networking**: Cilium CNI with Tailscale secure tunnels
- **Observability**: Grafana + Loki logging stack
- **Security**: Network policies and sealed secrets
- **Applications**: echo-server for testing

## Architecture

The deployment follows a layered approach with numbered directories representing phases:

```
├── 0-bootstrap/          # Namespaces and foundational resources
├── 1-network-policies/   # Network security policies
├── 2-secrets/           # Sealed secrets management
├── 3-config/            # Configuration resources
├── 4-infrastructure/    # Core infrastructure (cert-manager, operators)
├── 5-system/           # System services (databases, networking)
├── 6-apps/             # Applications (echo-server)
├── 7-ingress/          # Ingress resources with Tailscale funnel
├── cluster/            # Flux kustomizations orchestrating deployment
└── e2e/               # End-to-end testing configurations
```

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Flux CLI](https://fluxcd.io/flux/installation/)
- [Helm](https://helm.sh/docs/intro/install/)
- [Tailscale account](https://tailscale.com/) with API access

### Environment Variables

Set up required credentials (optional - script will prompt if not set):

```bash
# Tailscale configuration
export TAILSCALE_API_KEY="tskey-api-xxxxx"

# Tailscale Operator OAuth credentials
export OPERATOR_CLIENT_ID="your-oauth-client-id"
export OPERATOR_CLIENT_SECRET="your-oauth-client-secret"

# Git repository configuration
export GIT_URL="https://github.com/pmdroid/flux-e2e"  # Default: pmdroid/flux-e2e
export GIT_USERNAME="pmdroid"                          # Default: pmdroid
export GIT_PASSWORD="ghp_xxxxxxxxxxxx"                 # GitHub token or password
export GIT_BRANCH="main"                              # Default: current branch or "alloy"
```

**Note**: If environment variables are not set, the script will interactively prompt for required values.

### Deploy

Run the automated deployment script:

```bash
./local.sh
```

This script will:
1. Create a Kind cluster with Cilium CNI
2. Install Flux CD
3. Deploy the complete stack in the correct order
4. Set up Tailscale networking with random prefixes
5. Wait for all components to be ready
6. Display ingress endpoints

## Components

### Infrastructure Layer

- **Cert-Manager**: Automatic TLS certificate management
- **Sealed Secrets**: Encrypted secrets stored in Git
- **MariaDB Operator**: Database management
- **Loki**: Log aggregation and storage

### System Layer

- **Tailscale**: Secure networking and ingress
- **MariaDB**: Database for applications
- **Redis**: Caching and session storage
- **Grafana**: Observability dashboard with Loki integration

### Applications

- **Echo Server**: Testing utility for HTTP requests
- **Monitoring**: Grafana dashboards and Loki logs

### Networking

- **Cilium**: High-performance container networking
- **Network Policies**: Micro-segmentation and security
- **Tailscale Funnel**: Secure public ingress without port forwarding

## Accessing Services

After deployment, services are accessible via Tailscale funnel:

- **Grafana**: `https://{random-prefix}grafana.{tailnet}.ts.net`
- **Echo Server**: `https://{random-prefix}echo.{tailnet}.ts.net`
- **Loki**: `https://{random-prefix}loki.{tailnet}.ts.net`

The random prefix is generated during deployment and displayed in the output.

## Configuration

### Cluster Variables

Key configuration is managed via the `cluster-vars` ConfigMap:

```yaml
data:
  defaultStorageClassName: "hcloud-volumes"
  tailscaleTag: "tag:k8s-operator"
  tailscalePrefix: ""              # Set dynamically during deployment
  tailscaleHostname: "tailscale-operator"
  tailscaleNetName: "your.ts.net"
```

### Variable Substitution

All resources support variable substitution using `${variable}` syntax from the cluster-vars ConfigMap.

## Development

### File Structure

- **kustomization.yaml**: Each directory contains a kustomization file
- **namespace.yaml**: Namespace definitions in `0-bootstrap/`
- **release.yaml**: Helm releases for applications
- **repo.yaml**: Helm repository definitions

### Adding New Applications

1. Create namespace in `0-bootstrap/{app}/`
2. Add Helm repository in `4-infrastructure/` or `5-system/`
3. Create application in `6-apps/{app}/`
4. Add ingress in `7-ingress/`
5. Create network policy in `1-network-policies/`
6. Update parent kustomization files

### Testing

Use the `e2e/` directory for testing configurations:

```bash
# Apply e2e configurations
kubectl apply -f e2e/config.yaml
kubectl apply -f e2e/secrets.yaml
kubectl apply -f e2e/cluster-vars.yaml
```

## Monitoring and Observability

### Grafana

- **URL**: Access via Tailscale ingress
- **Credentials**: admin/admin (change in production)
- **Datasources**: Pre-configured Loki integration
- **Dashboards**: Loki logs dashboard included

### Loki

- **Deployment**: Single binary mode for testing
- **Storage**: Filesystem-based (5Gi persistent volume)
- **Retention**: Default Loki retention policies
- **Access**: Internal cluster service + external ingress

## Security

### Network Policies

Each namespace has restrictive network policies allowing only necessary traffic:

- DNS resolution (port 53)
- Ingress from Tailscale operator
- Specific inter-service communication

### Secrets Management

- All secrets encrypted with Sealed Secrets
- API keys injected via environment variables
- No sensitive data stored in Git

### Tailscale Security

- ACL-based access control
- Funnel for secure public access
- No exposed LoadBalancer services

## Troubleshooting

### Common Issues

**Ingresses without addresses:**
- Check Tailscale operator logs
- Verify ACL permissions
- Ensure Tailscale API key is valid

**Kustomization not ready:**
- Check resource dependencies
- Verify namespace exists
- Review Flux logs: `flux logs --follow`

**Application startup failures:**
- Check pod logs: `kubectl logs -n {namespace} {pod}`
- Verify resource limits and requests
- Check persistent volume claims

### Debugging Commands

```bash
# Check Flux status
flux get kustomizations
flux get sources git

# Check application status
kubectl get pods -A
kubectl get ingress -A

# View logs
kubectl logs -n flux-system -l app=helm-controller
kubectl logs -n network-tools -l app=tailscale-operator
```

## Cleanup

The deployment script includes automatic cleanup:

- Tailscale devices with random prefix are removed
- Kind cluster deletion (optional)
- Cleanup runs on script exit (success or failure)

Manual cleanup:

```bash
# Delete cluster
kind delete cluster --name flux-e2e

# Remove Tailscale devices
# (Use Tailscale admin console or API)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test changes with `./local.sh`
4. Submit a pull request

## License

This project is for educational and testing purposes. Modify for your specific use case.

## Support

For issues and questions:
- Check the troubleshooting section
- Review Flux CD documentation
- Open an issue in this repository