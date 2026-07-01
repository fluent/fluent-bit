#!/bin/bash
# Copyright 2021 Calyptia, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file  except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the  License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -eux

# Simple smoke test script using helm deployment to run up a deployment then
# ensure we can access the web server.
# Assumes a kubectl context is set up already, e.g. `kind create cluster`

NAMESPACE=${NAMESPACE:-default}
REGISTRY=${REGISTRY:-ghcr.io}
IMAGE_NAME=${IMAGE_NAME:-fluent/fluent-bit}
IMAGE_TAG=${IMAGE_TAG:-latest}

# Deploy using Helm chart
helm repo add fluent-bit https://fluent.github.io/helm-charts || helm repo add fluent-bit https://fluent.github.io/helm-charts/
helm repo update
helm upgrade --install fluent-bit fluent-bit/fluent-bit \
    --namespace "$NAMESPACE" --create-namespace \
    --wait \
    --set kind=Deployment \
    --set replicaCount=1 \
    --set image.repository="$REGISTRY/$IMAGE_NAME" \
    --set image.tag="$IMAGE_TAG"

# Output some information on pods running
kubectl describe -n "$NAMESPACE" pods --selector='app.kubernetes.io/name=fluent-bit'

while true; do
    # Find a free ephemeral port to use for port forwarding
    FREE_PORTNUM=$(shuf -i 1025-65535 -n 1)
    if ! lsof -Pi ":$FREE_PORTNUM" -sTCP:LISTEN; then
        # Forward to the deployment web server port
        kubectl port-forward -n "$NAMESPACE" deployment/fluent-bit "$FREE_PORTNUM":2020 &
        PF_PID=$!
        # Wait a bit
        sleep 60
        # Provide debug output in case it is required
        kubectl describe -n "$NAMESPACE" pods --selector='app.kubernetes.io/name=fluent-bit'
        # Check we are still functional
        curl -v localhost:"$FREE_PORTNUM"                | jq
        curl -v localhost:"$FREE_PORTNUM"/api/v1/metrics | jq
        curl -v localhost:"$FREE_PORTNUM"/api/v1/uptime  | jq
        curl -v localhost:"$FREE_PORTNUM"/api/v1/health
        kill -9 $PF_PID
        exit 0
    fi
done
echo "Unable to find free port"
exit 1