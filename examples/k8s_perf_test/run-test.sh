#/bin/bash
export TEST_NAMESPACE="${TEST_NAMESPACE:-default}"
export FLUENTBIT_IMAGE_REPOSITORY=${FLUENTBIT_IMAGE_REPOSITORY:-ghcr.io/fluent/fluent-bit}
export FLUENTBIT_IMAGE_TAG=${FLUENTBIT_IMAGE_TAG:-latest}

# update helm
helm repo add fluent https://fluent.github.io/helm-charts/
helm repo update --fail-on-repo-update-fail

echo "Installing fluent-bit via helm in namespace $TEST_NAMESPACE"
helm upgrade --install --debug --create-namespace --namespace "$TEST_NAMESPACE" fluent-bit fluent/fluent-bit \
        --values values.yaml \
        --set image.repository=${FLUENTBIT_IMAGE_REPOSITORY},image.tag=${FLUENTBIT_IMAGE_TAG} \
        --timeout "${HELM_FB_TIMEOUT:-5m0s}" \
        --wait

export POD_NAME=$(kubectl get pods --namespace $TEST_NAMESPACE -l "app.kubernetes.io/name=fluent-bit,app.kubernetes.io/instance=fluent-bit" --field-selector status.phase=Running -o jsonpath="{.items[-1].metadata.name}")
echo "$POD_NAME" deployed, tailing logs
kubectl logs -n $TEST_NAMESPACE $POD_NAME -c logwriter -f

#NOTE You can also follow -c fluent-bit for the fluent-bit logs if you'd like

# To rest the test, just `helm uninstall fluent-bit` in your $TEST_NAMESPACE and re-run ./run-test.sh