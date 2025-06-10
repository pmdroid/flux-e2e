#!/bin/bash
set -e

# Configuration
CONFIGMAP_NAME="cluster-vars"
NAMESPACE="flux-system"
TAILNET_NAME="taile07e4.ts.net"

# Function for user confirmation
confirm() {
    read -p "$1 (y/n): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# Check for uncommitted changes and new files, offer to commit
echo "Checking for uncommitted changes and new files..."
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    # Check for uncommitted changes in tracked files
    has_changes=false
    has_untracked=false

    if ! git diff-index --quiet HEAD --; then
        has_changes=true
    fi

    # Check for untracked files (excluding common ignore patterns)
    untracked_files=$(git ls-files --others --exclude-standard)
    if [ -n "$untracked_files" ]; then
        has_untracked=true
    fi

    if [ "$has_changes" = true ] || [ "$has_untracked" = true ]; then
        echo "Found uncommitted work:"
        echo ""

        if [ "$has_changes" = true ]; then
            echo "Modified files:"
            git status --porcelain
        fi

        if [ "$has_untracked" = true ]; then
            echo "Untracked files:"
            echo "$untracked_files"
        fi

        echo ""
        if confirm "Would you like to commit these changes as a WIP commit before proceeding?"; then
            # Add all changes and untracked files
            if [ "$has_untracked" = true ]; then
                echo "Adding untracked files..."
                git add .
            fi

            if [ "$has_changes" = true ]; then
                echo "Adding modified files..."
                git add -u
            fi

            # Create WIP commit
            echo "Creating WIP commit..."
            git commit -m "WIP: Auto-commit before deployment script run"
            echo "✓ WIP commit created successfully"
            git push
            echo "✓ WIP commit successfully pushed"
        fi
    fi
else
    echo "⚠ Warning: Not in a git repository - skipping git status check"
fi

# Generate a random string (6 characters) - do this early so it's available for cleanup
RANDOM_STRING=$(openssl rand -hex 3)
echo "Generated random string: $RANDOM_STRING"

# Cleanup function that will run on script exit (success or failure)
cleanup_tailscale_devices() {
    echo ""
    echo "=== Running Tailscale cleanup ==="

    # Set variables for cleanup
    TAILNET="${TAILNET_NAME:-$TAILNET_NAME}"
    API_KEY="${TAILSCALE_API_KEY:-$API_KEY}"

    # Validate required variables for cleanup
    if [[ -z "$TAILNET" || -z "$API_KEY" || -z "$RANDOM_STRING" ]]; then
        echo "Warning: Cannot run cleanup - missing TAILNET, API_KEY, or RANDOM_STRING"
        echo "TAILNET: ${TAILNET:-'not set'}"
        echo "API_KEY: ${API_KEY:+'set (hidden)'}"
        echo "RANDOM_STRING: ${RANDOM_STRING:-'not set'}"
        return 1
    fi

    echo "Searching for devices containing '$RANDOM_STRING' in tailnet '$TAILNET'..."

    # Get devices and process them
    curl -s "https://api.tailscale.com/api/v2/tailnet/$TAILNET/devices" \
        -u "$API_KEY:" \
        -H "Accept: application/json" | \
    jq -r '.devices[]? | select(.name != null) | "\(.id) \(.name)"' | \
    while IFS=' ' read -r id name; do
        # Skip empty lines
        [[ -z "$id" || -z "$name" ]] && continue

        if [[ "$name" == *"$RANDOM_STRING"* ]]; then
            echo "Found: '$name' (ID: $id) contains '$RANDOM_STRING' - removing it"

            # Delete the device
            delete_response=$(curl -s -w "%{http_code}" -o /dev/null \
                -X DELETE "https://api.tailscale.com/api/v2/device/$id" \
                -u "$API_KEY:" \
                -H "Accept: application/json")

            if [[ "$delete_response" == "200" ]]; then
                echo "✓ Successfully deleted device '$name'"
            else
                echo "✗ Failed to delete device '$name' (HTTP $delete_response)"
            fi
        fi
    done

    echo "Device cleanup complete."
}

# Cleanup function for Kind cluster
cleanup_kind_cluster() {
    echo "Cleaning up: Deleting flux-e2e cluster..."
    if kind get clusters | grep -q "flux-e2e"; then
        kind delete cluster --name flux-e2e
        echo "✓ Cluster deleted"
    else
        echo "ℹ No flux-e2e cluster found to delete"
    fi
}

# Combined cleanup function
cleanup_all() {
    echo ""
    echo "=== Starting cleanup process ==="

    # Always run Tailscale cleanup
    cleanup_tailscale_devices

    # Only cleanup cluster if user doesn't want to keep it
    if [[ "$KEEP_CLUSTER" != "true" ]]; then
        cleanup_kind_cluster
    fi

    echo "=== Cleanup process completed ==="
}

# Set up trap to run cleanup on script exit (both success and failure)
trap cleanup_all EXIT

# Function to display ingresses in a formatted table and check for missing addresses
list_ingresses_table() {
    local max_retries=10
    local retry_interval=30
    local retry_count=0

    echo "Kubernetes Ingresses Table"
    echo "=========================="
    echo

    # Always show the current ingresses table first
    kubectl get ingress --all-namespaces -o custom-columns=\
NAMESPACE:.metadata.namespace,\
NAME:.metadata.name,\
CLASS:.spec.ingressClassName,\
ADDRESS:.status.loadBalancer.ingress[0].hostname,\
AGE:.metadata.creationTimestamp | sed '1!s/\([^[:space:]]*[[:space:]]*[^[:space:]]*[[:space:]]*[^[:space:]]*[[:space:]]*\)\([^[:space:]]*\)/\1https:\/\/\2/'

    echo
    echo "Checking for ingresses without addresses..."
    echo "==========================================="

    # Retry loop for checking ingress addresses
    while [ $retry_count -lt $max_retries ]; do
        retry_count=$((retry_count + 1))

        echo "Attempt $retry_count of $max_retries..."

        # Check for ingresses without addresses
        missing_addresses=$(kubectl get ingress --all-namespaces -o json | jq -r '
            .items[] |
            select(
                (.status.loadBalancer.ingress | length) == 0 or
                (.status.loadBalancer.ingress[0].hostname // .status.loadBalancer.ingress[0].ip // "") == ""
            ) |
            .metadata.namespace + "/" + .metadata.name
        ')

        if [ -z "$missing_addresses" ]; then
            echo "✅ All ingresses have addresses assigned!"
            return 0
        else
            echo "⚠️  Found ingresses without addresses:"
            echo "$missing_addresses" | while read -r ingress; do
                echo "  - $ingress"
            done

            if [ $retry_count -lt $max_retries ]; then
                echo "⏳ Waiting ${retry_interval} seconds before retry..."
                sleep $retry_interval
                echo
                echo "Refreshing ingresses table..."
                kubectl get ingress --all-namespaces -o custom-columns=\
NAMESPACE:.metadata.namespace,\
NAME:.metadata.name,\
CLASS:.spec.ingressClassName,\
ADDRESS:.status.loadBalancer.ingress[0].hostname,\
AGE:.metadata.creationTimestamp
                echo
            fi
        fi
    done

    # If we get here, all retries failed
    echo
    echo "❌ ERROR: After $max_retries attempts, the following ingresses still do not have addresses assigned:"
    echo "$missing_addresses" | while read -r ingress; do
        echo "  - $ingress"
    done
    echo
    echo "💡 This usually means:"
    echo "   • Ingress controller is not running"
    echo "   • Load balancer provisioning failed"
    echo "   • Ingress controller doesn't support LoadBalancer service type"
    echo "   • Cloud provider integration issues"
    echo "   • Tailscale ACL wrong"
    echo
    exit 1
}

echo ""
echo "=== Collecting required credentials and configuration ==="

# Handle API key with env variables or prompts
API_KEY=${TAILSCALE_API_KEY:-""}

# If environment variable isn't set, prompt for it
if [ -z "$API_KEY" ]; then
  read -s -p "Enter Tailscale API key: " API_KEY
  echo
fi

# Handle operator OAuth secret with env variables or prompts
CLIENT_ID=${OPERATOR_CLIENT_ID:-""}
CLIENT_SECRET=${OPERATOR_CLIENT_SECRET:-""}

# If environment variables aren't set, prompt for them
if [ -z "$CLIENT_ID" ]; then
  read -p "Enter operator client ID: " CLIENT_ID
fi

if [ -z "$CLIENT_SECRET" ]; then
  read -s -p "Enter operator client secret: " CLIENT_SECRET
  echo
fi

# Get local git branch or use provided branch
if [ -z "$GIT_BRANCH" ]; then
  # Try to get current git branch if in a git repository
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    LOCAL_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null)
    GIT_BRANCH=${LOCAL_BRANCH:-"alloy"} # Default to "alloy" if not in a git repo or can't get branch
  else
    # Not in a git repository, prompt for branch
    read -p "Enter Git branch (default: alloy): " BRANCH_INPUT
    GIT_BRANCH=${BRANCH_INPUT:-"alloy"}
  fi
fi

echo "Using Git branch: $GIT_BRANCH"

# Handle other git credentials with env variables or prompts
GIT_URL=${GIT_URL:-"https://github.com/pmdroid/flux-e2e"}
GIT_USERNAME=${GIT_USERNAME:-"pmdroid"}
GIT_PASSWORD=${GIT_PASSWORD:-""}

# If GIT_PASSWORD not set, prompt for it
if [ -z "$GIT_PASSWORD" ]; then
  read -s -p "Enter Git password or token: " GIT_PASSWORD
  echo
fi

echo ""
echo "=== All credentials collected, starting cluster operations ==="

# Check if flux-e2e cluster exists
echo "Checking for existing clusters..."
if kind get clusters | grep -q "flux-e2e"; then
    echo "✓ flux-e2e cluster found - deleting for fresh start..."
    kind delete cluster --name flux-e2e
    echo "✓ Old cluster deleted"
else
    echo "✗ flux-e2e cluster not found"
fi

# Create the cluster (always create fresh)
echo "Creating fresh flux-e2e cluster..."
kind create cluster --name flux-e2e --config kind-config.yaml

if [ $? -eq 0 ]; then
    echo "✓ flux-e2e cluster created successfully"
else
    echo "✗ Failed to create cluster"
    exit 1
fi

# Get the correct API server endpoint because there's some sort-of conflict when Cilium tries to use the Kube-proxy service
APISERVER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' flux-e2e-control-plane)
echo "API Server IP: $APISERVER_IP"

# Add Cilium
helm repo add cilium https://helm.cilium.io/
docker pull quay.io/cilium/cilium:v1.17.4
kind load docker-image quay.io/cilium/cilium:v1.17.4 --name flux-e2e
helm install cilium cilium/cilium --version 1.17.4 \
     --namespace kube-system \
     --set operator.replicas=1 \
     --set operator.prometheus.enabled=true \
     --set devices="{eth+,enp+}" \
     --set ipam.operator.clusterPoolIPv4PodCIDRList=10.244.0.0/16 \
     --set l7Proxy=false \
     --set k8sServiceHost=$APISERVER_IP \
     --set k8sServicePort=6443 \
     --set ipv4NativeRoutingCIDR=10.244.0.0/16 \
     --set egressGateway.enabled=true \
     --set bpf.masquerade=true \
     --set prometheus.enabled=true \
     --set hubble.enabled=true \
     --set hubble.relay.enabled=true \
     --set hubble.ui.enabled=true \
     --set hubble.metrics.enabled="{dns,http,drop,tcp,flow,icmp}" \
     --set nodePort.enabled=true

# Ensure we're using the correct context
echo "Setting kubectl context to kind-flux-e2e..."
kubectl config use-context kind-flux-e2e

echo ""
echo "=== Starting Kubernetes deployment on flux-e2e cluster ==="

# Create necessary namespaces
echo "Creating namespaces..."
kubectl create namespace flux-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace fleetdm --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace network-tools --dry-run=client -o yaml | kubectl apply -f -

# Create the OAuth secret (using variables collected at the top)
echo "Creating OAuth secret..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: operator-oauth
  namespace: network-tools
type: Opaque
stringData:
  client_id: "${CLIENT_ID}"
  client_secret: "${CLIENT_SECRET}"
EOF

# Install and configure Flux
echo "Installing Flux..."
flux install

# Apply e2e mocks
echo "Applying e2e configurations..."
kubectl apply -f e2e/config.yaml
kubectl apply -f e2e/secrets.yaml
kubectl apply -f e2e/cluster-vars.yaml

# Patch the ConfigMap using kubectl patch
kubectl patch configmap "$CONFIGMAP_NAME" -n "$NAMESPACE" \
  --type merge \
  -p "{\"data\":{\"tailscalePrefix\":\"$RANDOM_STRING-\"}}"

# Patch the ConfigMap using kubectl patch
kubectl patch configmap "$CONFIGMAP_NAME" -n "$NAMESPACE" \
  --type merge \
  -p "{\"data\":{\"tailscaleHostname\":\"$RANDOM_STRING-operator\"}}"

# Check if the patch was successful
if [ $? -eq 0 ]; then
    echo "Successfully patched ConfigMap '$CONFIGMAP_NAME' in namespace '$NAMESPACE'"
    echo "Added tailscalePrefix: $RANDOM_STRING"
    echo "Added tailscaleHostname: $RANDOM_STRING-operator"

    # Verify the change
    echo -e "\nVerifying the patch:"
    kubectl get configmap "$CONFIGMAP_NAME" -n "$NAMESPACE" -o jsonpath="{.data.tailscalePrefix}"
    kubectl get configmap "$CONFIGMAP_NAME" -n "$NAMESPACE" -o jsonpath="{.data.tailscaleHostname}"
    echo
else
    echo "Failed to patch ConfigMap"
    exit 1
fi

# Create flux source (using variables collected at the top)
echo "Creating Flux source..."
flux create source git flux-system \
  --url="${GIT_URL}" \
  --branch="${GIT_BRANCH}" \
  --username="${GIT_USERNAME}" \
  --password="${GIT_PASSWORD}" \
  --ignore-paths="cluster/flux-system/" \
  --ignore-paths="cluster/config.yaml" \
  --ignore-paths="cluster/secrets.yaml" \
  --ignore-paths="cluster/cluster-vars.yaml"

# Create flux kustomization
echo "Creating Flux kustomization..."
flux create kustomization flux-system \
  --source=flux-system \
  --path=./cluster

# Wait for kustomizations to be ready
echo "Waiting for kustomizations to be ready..."
kubectl -n flux-system wait kustomization/bootstrap --for=condition=ready --timeout=5m
kubectl -n flux-system wait kustomization/network-policies --for=condition=ready --timeout=5m
kubectl -n flux-system wait kustomization/system --for=condition=ready --timeout=5m
kubectl -n flux-system wait kustomization/secrets --for=condition=ready --timeout=5m
kubectl -n flux-system wait kustomization/infrastructure --for=condition=ready --timeout=5m
kubectl -n flux-system wait kustomization/config --for=condition=ready --timeout=5m
kubectl -n flux-system wait kustomization/apps --for=condition=ready --timeout=5m
kubectl -n flux-system wait kustomization/ingress --for=condition=ready --timeout=5m

echo ""
echo "=== Deployment completed successfully! ==="

list_ingresses_table

# Ask what to do with the cluster at the end
echo ""
if confirm "Keep the flux-e2e cluster?"; then
    echo "✓ Keeping cluster for future use"
    echo "You can access your cluster with: kubectl config use-context kind-flux-e2e"
    KEEP_CLUSTER="true"
else
    echo "Will delete cluster during cleanup..."
    KEEP_CLUSTER="false"
fi

echo "Script completed successfully."