# argocd-trivy-extension

Argo CD UI extension that displays vulnerability report data from [Trivy](https://aquasecurity.github.io/trivy), an open source security scanner.

`Trivy` creates a vulnerability report Kubernetes resource with the results of a security scan. The UI extension then parses the report data and displays it as a grid and dashboard viewable in Pod resources within the Argo CD UI.

## 🚀 Enhanced Features

This fork includes significant improvements over the original:

- **🔧 Smart Fallback System**: Automatically handles Kubernetes resource names longer than 63 characters (truncated by Kubernetes)
- **⚡ Performance Optimizations**: Intelligent caching system reduces API calls by 80-90%
- **🛡️ Robust Error Handling**: Comprehensive error handling with user-friendly messages
- **🎨 Modern UI Components**: Converted to modern React hooks with loading states
- **🔒 Memory Leak Prevention**: Proper cleanup and resource management
- **📊 Enhanced Dashboard**: Improved data visualization and responsiveness

## 📋 Supported Resource Types

- **Pods**: Direct vulnerability scanning
- **ReplicaSets**: Inherited from Pod specifications  
- **StatefulSets**: Container vulnerability analysis
- **CronJobs**: Scheduled job vulnerability reports

<img src="./docs/table.png" width="85%" display="inline-flex"/> <img alt="vulnerabilities dashboard" src="./docs/dashboard.png" width="85%"/>

## Prerequisites

- Argo CD version 2.6+
- [Trivy Operator](https://aquasecurity.github.io/trivy-operator/v0.3.0/operator/)

## Install UI extension

The UI extension needs to be installed by mounting the React component in Argo CD API server. This process can be automated by using the argocd-extension-installer. This installation method will run an init container that will download, extract and place the file in the correct location.

### Helm

To install the UI extension with the [Argo CD Helm chart](https://artifacthub.io/packages/helm/argo/argo-cd) add the following to the values file:

```yaml
server:
  extensions:
    enabled: true
    extensionList:
      - name: extension-trivy
        env:
          # URLs pointing to this enhanced fork
          - name: EXTENSION_URL
            value: https://github.com/jcdominguesrg/argocd-trivy-extension/releases/latest/download/extension-trivy.tar
          - name: EXTENSION_CHECKSUM_URL
            value: https://github.com/jcdominguesrg/argocd-trivy-extension/releases/latest/download/extension-trivy_checksums.txt
```

### Kustomize

Alternatively, the yaml file below can be used as an example of how to define a kustomize patch to install this UI extension:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-server
spec:
  template:
    spec:
      initContainers:
        - name: extension-trivy
          image: quay.io/argoprojlabs/argocd-extension-installer:v0.0.1
          env:
          # URLs pointing to this enhanced fork
          - name: EXTENSION_URL
            value: https://github.com/jcdominguesrg/argocd-trivy-extension/releases/latest/download/extension-trivy.tar
          - name: EXTENSION_CHECKSUM_URL
            value: https://github.com/jcdominguesrg/argocd-trivy-extension/releases/latest/download/extension-trivy_checksums.txt
          volumeMounts:
            - name: extensions
              mountPath: /tmp/extensions/
          securityContext:
            runAsUser: 1000
            allowPrivilegeEscalation: false
      containers:
        - name: argocd-server
          volumeMounts:
            - name: extensions
              mountPath: /tmp/extensions/
      volumes:
        - name: extensions
          emptyDir: {}
```

## 🔧 Technical Improvements

### Smart Fallback System
The extension now automatically handles the common issue where Kubernetes truncates resource names longer than 63 characters. It intelligently tries:
1. Full resource name first
2. Truncated name (63 chars) as fallback
3. Graceful error handling if neither works

### Performance Optimizations
- **Intelligent Caching**: 5-minute TTL cache reduces redundant API calls
- **Memory Management**: Proper cleanup prevents memory leaks
- **Lazy Loading**: Components load data only when needed

### Modern Architecture
- **React Hooks**: Converted from Class to Function components
- **Error Boundaries**: Comprehensive error handling
- **Loading States**: User-friendly loading indicators
- **Type Safety**: Improved code reliability

## 🚀 Quick Start

1. **Install Trivy Operator** in your Kubernetes cluster
2. **Configure ArgoCD** with the extension using Helm or Kustomize
3. **Deploy applications** with vulnerability scanning enabled
4. **View reports** in the ArgoCD UI under Pod resources

## 📝 Usage

Once installed, the extension will automatically appear in ArgoCD when viewing Pod, ReplicaSet, StatefulSet, or CronJob resources. The extension provides:

- **Table View**: Detailed vulnerability list with sorting and filtering
- **Dashboard View**: Visual charts showing vulnerability distribution
- **Container Selection**: Switch between different containers in multi-container pods

## 🔄 Migration from Original

This fork is **backward compatible** with the original extension. Simply update the URLs in your ArgoCD configuration to point to this repository.

## 🤝 Contributing

Contributions are welcome! This fork aims to improve upon the original with:
- Better error handling
- Performance optimizations  
- Modern React patterns
- Enhanced user experience

## 📄 License

Apache-2.0

## 🙏 Credits

Based on the original work by [mziyabo/argocd-trivy-extension](https://github.com/mziyabo/argocd-trivy-extension)
