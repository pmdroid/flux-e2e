# Flux E2E Testing Repository

GitOps repository for end-to-end testing of Kubernetes deployments using Flux CD with full observability stack.

## Stack

- **GitOps**: Flux CD for continuous delivery
- **Networking**: Cilium CNI + Tailscale secure tunnels
- **Observability**: Grafana + Loki logging
- **Security**: Network policies + sealed secrets
- **Test App**: echo-server

## Structure

Numbered directories represent deployment phases:

```
├── 0-bootstrap/          # Namespaces
├── 1-network-policies/   # Security policies
├── 2-secrets/           # Sealed secrets
├── 3-config/            # ConfigMaps
├── 4-infrastructure/    # cert-manager, operators
├── 5-system/           # MariaDB, Redis, networking
├── 6-apps/             # echo-server
├── 7-ingress/          # Tailscale funnel ingress
├── cluster/            # Flux kustomizations
└── e2e/               # Test configs
```

## Quick Start

### Prerequisites
- Docker, Kind, kubectl, Flux CLI, Helm
- Tailscale account with API access

### Environment Variables
```bash
export TAILSCALE_API_KEY="tskey-api-xxxxx"
export OPERATOR_CLIENT_ID="your-oauth-client-id"
export OPERATOR_CLIENT_SECRET="your-oauth-client-secret"
export GIT_URL="https://github.com/pmdroid/flux-e2e"
export GIT_USERNAME="pmdroid"
export GIT_PASSWORD="ghp_xxxxxxxxxxxx"
export GIT_BRANCH="main"
```

### Deploy
```bash
./local.sh
```

The script:
1. Creates Kind cluster with Cilium
2. Installs Flux CD
3. Deploys stack in correct order
4. Sets up Tailscale networking
5. Displays ingress endpoints

## Access Services

Services available via Tailscale funnel:
- **Grafana**: `https://{prefix}grafana.{tailnet}.ts.net`
- **Echo Server**: `https://{prefix}echo.{tailnet}.ts.net`

Random prefix generated during deployment.

## Key Components

### Infrastructure
- **cert-manager**: TLS certificate management
- **sealed-secrets**: Encrypted secrets in Git
- **MariaDB Operator**: Database management
- **Loki**: Log aggregation

### System
- **Tailscale**: Secure networking/ingress
- **MariaDB**: Application database
- **Redis**: Caching layer
- **Grafana**: Observability dashboard

### Configuration
Managed via `cluster-vars` ConfigMap with variable substitution using `${variable}` syntax.

## Development

### Adding Applications
1. Create namespace in `0-bootstrap/{app}/`
2. Add Helm repo in `4-infrastructure/` or `5-system/`
3. Create app in `6-apps/{app}/`
4. Add ingress in `7-ingress/`
5. Create network policy in `1-network-policies/`
6. Update parent kustomizations

### Testing
```bash
kubectl apply -f e2e/config.yaml
kubectl apply -f e2e/secrets.yaml
kubectl apply -f e2e/cluster-vars.yaml
```

## Security Features

- **Network Policies**: Restrictive policies per namespace
- **Sealed Secrets**: All secrets encrypted
- **Tailscale ACLs**: Access control
- **No LoadBalancer**: Only Tailscale funnel exposure

## Troubleshooting

### Common Issues
- **Missing ingress addresses**: Check Tailscale operator logs, verify ACL permissions
- **Kustomization not ready**: Check dependencies, verify namespaces exist
- **App failures**: Check pod logs, verify resources, check PVCs

### Debug Commands
```bash
# Flux status
flux get kustomizations
flux get sources git

# Application status
kubectl get pods -A
kubectl get ingress -A

# Logs
kubectl logs -n flux-system -l app=helm-controller
kubectl logs -n network-tools -l app=tailscale-operator
```

## Cleanup

Automatic cleanup on script exit:
- Removes Tailscale devices with random prefix
- Optionally deletes Kind cluster

Manual cleanup:
```bash
kind delete cluster --name flux-e2e
```

## Architecture Benefits

- **GitOps**: Declarative, version-controlled deployments
- **Security**: Zero-trust networking with Tailscale
- **Observability**: Centralized logging and monitoring
- **Scalability**: Kubernetes-native with proper resource management
- **Development**: Easy testing with disposable Kind clusters