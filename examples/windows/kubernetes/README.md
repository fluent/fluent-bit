# Fluent Bit running as a sidecar on Kubernetes Windows node

You can test the Fluent Bit image as a sidecar on a Kubernetes Windows node as follows:

```
kubectl create namespace fluentbit
kubectl apply -n fluentbit -f $SAMPLE_DIR\kubernetes\configmap.yaml
kubectl apply -n fluentbit -f $SAMPLE_DIR\kubernetes\deployment.yaml
```

Ensure that the resources have been correctly deployed.

```
kubectl get pod -n fluentbit 
NAME                                             READY   STATUS    RESTARTS   AGE
logging-fluentbit-sidecar-6ff8c84494-zt4ft       2/2     Running   0          31m

kubectl get svc -n fluentbit 
NAME                                TYPE           CLUSTER-IP    EXTERNAL-IP      PORT(S)        AGE
logging-fluentbit-sidecar           LoadBalancer   10.0.27.172   52.237.212.148   80:30172/TCP   126m
```

If you tail the logs on the Fluent Bit sidecar, and then explore the website running in the external ip and port 80, you should see generated logs ...

```
kubectl logs logging-fluentbit-sidecar-6ff8c84494-zt4ft -n fluentbit -c fluentbit-logger -f
```