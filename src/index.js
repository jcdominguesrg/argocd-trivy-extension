import React, { useState, useEffect } from 'react';
import './index.css';
import { Tab, Tabs } from "@mui/material";
import DataGrid from './components/grid/vulnerability-report';
import Dashboard from './components/dashboard/dashboard';

// Version bump for cache invalidation
window.EXTENSION_VERSION = '0.3.14';

const Extension = (props) => {
  const { resource, application } = props;
  const appName = application?.metadata?.name || "";
  const resourceNamespace = resource?.metadata?.namespace || "";
  const isPod = resource?.kind === "Pod";
  const isCronJob = resource?.kind === "CronJob";
  const resourceName = (isPod
    ? resource?.metadata?.ownerReferences?.[0]?.name
    : resource?.metadata?.name)?.toLowerCase() || "";
  const resourceKind = (isPod
    ? resource?.metadata?.ownerReferences?.[0]?.kind
    : resource?.kind)?.toLowerCase() || "";

  const [containerName, setContainerName] = useState(
    isPod
      ? resource?.spec?.containers?.[0]?.name
      : isCronJob
      ? resource?.spec?.jobTemplate?.spec?.template?.spec?.containers?.[0]?.name
      : resource?.spec?.template?.spec?.containers?.[0]?.name
  );
  const [reportUrl, setReportUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const baseURI = `${window.location.origin}/api/v1/applications/${appName}/resource`;

  // Monta lista segura de containers (sem undefined)
  let containers = [];
  if (isPod) {
    containers = [
      ...(resource?.spec?.containers ?? []),
      ...(resource?.spec?.initContainers ?? []),
    ];
  } else if (isCronJob) {
    const tmpl = resource?.spec?.jobTemplate?.spec?.template?.spec;
    containers = [
      ...(tmpl?.containers ?? []),
      ...(tmpl?.initContainers ?? []),
    ];
  } else {
    const tmpl = resource?.spec?.template?.spec;
    containers = [
      ...(tmpl?.containers ?? []),
      ...(tmpl?.initContainers ?? []),
    ];
  }

  const containerNames = containers.map(c => c?.name).filter(Boolean);
  const images = containers.map(c => c?.image).filter(Boolean);
  const [currentTabIndex, setCurrentTabIndex] = useState(0);

  // Heurística reforçada de descoberta
  const tryResourceNames = async (kind, name, container) => {
    if (!name) return '';
    
    const hash = name.split('-').slice(-1)[0]; // último bloco do nome (hash)
    const shortName = name.slice(0, 63);

    const patterns = [
      `${kind}-${name}`,                    // replicaset-shipay-app-sample-python-b3-798c766556
      `${kind}-${shortName}`,               // nome truncado
      `${kind}-${hash}`,                    // replicaset-798c766556
      `${name}`,                            // shipay-app-sample-python-b3-798c766556
      `${name}-${container}`,               // shipay-app-sample-python-b3-798c766556-api
      `${kind}-${name}-${container}`,       // replicaset-shipay-app-sample-python-b3-798c766556-api
    ];

    for (const pattern of patterns) {
      const testUrl = `${baseURI}?name=${pattern}&namespace=${resourceNamespace}&resourceName=${pattern}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`;
      
      try {
        const response = await fetch(testUrl, { 
          method: 'GET',
          headers: { 'Accept': 'application/json' }
        });
        
        if (response.ok) {
          console.log(`✅ [Trivy Extension] Found VulnerabilityReport: ${pattern}`);
          return testUrl;
        }
      } catch (error) {
        console.log(`⚠️ [Trivy Extension] Error testing ${pattern}`, error);
      }
    }

    console.log('❌ [Trivy Extension] No VulnerabilityReport found');
    return '';
  };

  useEffect(() => {
    const findReport = async () => {
      setIsLoading(true);
      try {
        const url = await tryResourceNames(resourceKind, resourceName, containerName);
        setReportUrl(url);
      } catch (error) {
        console.error('[Trivy Extension] Error finding report:', error);
        setReportUrl('');
      } finally {
        setIsLoading(false);
      }
    };

    if (resourceKind && resourceName && containerName) {
      findReport();
    }
  }, [resourceKind, resourceName, containerName, resourceNamespace]);

  const handleTabChange = (_e, tabIndex) => setCurrentTabIndex(tabIndex);

  const onOptionChangeHandler = async (event) => {
    const newContainerName = event.target.value;
    setContainerName(newContainerName);
    setIsLoading(true);
    try {
      const url = await tryResourceNames(resourceKind, resourceName, newContainerName);
      setReportUrl(url);
    } catch (error) {
      console.error('[Trivy Extension] Error finding report:', error);
      setReportUrl('');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <select
        className="vulnerability-report__container_dropdown"
        onChange={onOptionChangeHandler}
        disabled={isLoading}
      >
        {containerNames.map((container, index) => (
          <option key={index} value={container}>
            {`${container} (${images[index]})`}
          </option>
        ))}
      </select>

      {isLoading && (
        <div style={{ padding: '10px', textAlign: 'center', color: '#666' }}>
          Carregando vulnerabilidades...
        </div>
      )}

      <Tabs value={currentTabIndex} onChange={handleTabChange}>
        <Tab label='Table' />
        <Tab label='Dashboard' />
      </Tabs>

      {!isLoading && currentTabIndex === 0 && reportUrl && (
        <DataGrid reportUrl={reportUrl} />
      )}
      {!isLoading && currentTabIndex === 1 && reportUrl && (
        <Dashboard reportUrl={reportUrl} />
      )}
      {!isLoading && !reportUrl && (
        <div style={{ padding: '10px', color: '#b00' }}>
          Nenhum VulnerabilityReport encontrado para este recurso.
        </div>
      )}
    </div>
  );
};

const component = Extension;

((window) => {
  const opts = { icon: "fa fa-triangle-exclamation" };
  window?.extensionsAPI?.registerResourceExtension(component, "*", "ReplicaSet", "Vulnerabilities", opts);
  window?.extensionsAPI?.registerResourceExtension(component, "*", "Pod", "Vulnerabilities", opts);
  window?.extensionsAPI?.registerResourceExtension(component, "*", "StatefulSet", "Vulnerabilities", opts);
  window?.extensionsAPI?.registerResourceExtension(component, "*", "CronJob", "Vulnerabilities", opts);
  window?.extensionsAPI?.registerResourceExtension(component, "*", "Deployment", "Vulnerabilities", opts);
})(window);