# Running a Dev Container in a Kubernetes Cluster

## Create a Kubernetes Cluster

You must have a Kubernetes Cluster where the Node you run a Dev Container in is running in the host PID namespace.
Unfortunately, this means the Kubernetes Cluster built into Docker Desktop will not work, as it uses Kind which does not
support host PID namespaces.

If you have a Docker context, you can create a Kubernetes Cluster in the host PID namespace using
[K3D](https://k3d.io/). After installing K3D following their instructions, you can run the following command to create a
cluster:

```bash
k3d cluster create --config .devcontainer/k3d_config.yaml
```

## Create a Dev Container

1. Create K8s Pod: `kubectl apply -f .devcontainer/k8s`
1. Attach VS Code to the pod using the "Dev Containers: Attach to Running Kubernetes Container" command
1. Clone this repository again inside the container into the /root directory
1. Re-open the repo in the VS Code window when prompted
1. Run `.devcontainer/attached_init.sh` to set up the development environment to match a devcontainer environment

The filesystem contents under /root will persist across container restarts and recycles as long as the Kubernetes
Persistent Volume Claim named `archodex-agent-dev` is not deleted.
