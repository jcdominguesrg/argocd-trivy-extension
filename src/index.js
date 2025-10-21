import React, { useState, useEffect } from 'react';

// Version bump for cache invalidation
window.EXTENSION_VERSION = '0.2.4';
import './index.css';
import { Tab, Tabs } from "@mui/material";
import DataGrid from './components/grid/vulnerability-report';
import Dashboard from './components/dashboard/dashboard';

const Extension = (props) => {

  const { resource, application } = props;
  const appName = application?.metadata?.name || "";
  const resourceNamespace = resource?.metadata?.namespace || "";
  const isPod = resource?.kind === "Pod"
  const isCronJob = resource?.kind === "CronJob"
  const resourceName = isPod ? resource?.metadata?.ownerReferences[0].name.toLowerCase() : resource?.metadata?.name;
  const resourceKind = isPod ? resource?.metadata?.ownerReferences[0].kind.toLowerCase() : resource?.kind?.toLowerCase();

  let [containerName] = useState(isPod ? resource?.spec?.containers[0]?.name : isCronJob ? resource?.spec?.jobTemplate?.spec?.template?.spec.containers[0]?.name : resource?.spec?.template?.spec?.containers[0]?.name);

  const baseURI = `${window.location.origin}/api/v1/applications/${appName}/resource`
  const [reportUrl, setReportUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  // Função para descobrir VulnerabilityReport por labels
  const findVulnerabilityReportByLabels = async (kind, name, container) => {
    if (!name) return '';
    
    console.log(`[Trivy Extension] Procurando VulnerabilityReport por labels: kind=${kind}, name=${name}, container=${container}`);
    
    try {
      // Usar /resource-tree para buscar VulnerabilityReports
      const treeUrl = `${window.location.origin}/api/v1/applications/${encodeURIComponent(appName)}/resource-tree?appNamespace=${encodeURIComponent(application?.metadata?.namespace || 'argo')}`;
      
      console.log(`[Trivy Extension] Buscando resource tree: ${treeUrl}`);
      
      const treeResponse = await fetch(treeUrl, { 
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      
      if (!treeResponse.ok) {
        console.log(`[Trivy Extension] Erro ao buscar resource tree: ${treeResponse.status}`);
        return '';
      }
      
      const treeData = await treeResponse.json();
      console.log(`[Trivy Extension] Resource tree carregado com ${treeData.nodes?.length || 0} nós`);
      
      if (!treeData.nodes || treeData.nodes.length === 0) {
        console.log('[Trivy Extension] Nenhum nó encontrado no resource tree');
        return '';
      }
      
      // Filtrar VulnerabilityReports no resource tree
      const vulnerabilityReports = treeData.nodes.filter(node => 
        node.kind === 'VulnerabilityReport' && 
        node.group === 'aquasecurity.github.io' &&
        node.namespace === resourceNamespace
      );
      
      console.log(`[Trivy Extension] Encontrados ${vulnerabilityReports.length} VulnerabilityReports no resource tree`);
      
      if (vulnerabilityReports.length === 0) {
        console.log('[Trivy Extension] Nenhum VulnerabilityReport encontrado no resource tree');
        return '';
      }
      
      // Listar todos os VulnerabilityReports para debug
      console.log(`[Trivy Extension] VulnerabilityReports disponíveis:`);
      vulnerabilityReports.forEach((report, index) => {
        console.log(`[Trivy Extension] ${index + 1}. ${report.name} (namespace: ${report.namespace})`);
        console.log(`[Trivy Extension]    Labels:`, report.info?.labels || {});
      });
      
      // Buscar por labels do Trivy Operator
      const matchingReport = vulnerabilityReports.find(report => {
        const labels = report.info?.labels || {};
        const resourceNameMatch = labels['trivy-operator.resource.name'] === name;
        const containerMatch = labels['trivy-operator.container.name'] === container;
        const kindMatch = labels['trivy-operator.resource.kind']?.toLowerCase() === kind.toLowerCase();
        
        if (resourceNameMatch && containerMatch && kindMatch) {
          console.log(`[Trivy Extension] ✅ Match por labels: ${report.name}`);
          console.log(`[Trivy Extension]    resource.name: ${labels['trivy-operator.resource.name']}`);
          console.log(`[Trivy Extension]    container.name: ${labels['trivy-operator.container.name']}`);
          console.log(`[Trivy Extension]    resource.kind: ${labels['trivy-operator.resource.kind']}`);
          return true;
        }
        
        return false;
      });
      
      if (!matchingReport) {
        console.log('[Trivy Extension] Nenhum VulnerabilityReport correspondente encontrado por labels');
        return '';
      }
      
      // Construir URL de detalhe usando o nome real do CR
      const crName = matchingReport.name;
      const detailUrl = `${baseURI}?name=${encodeURIComponent(crName)}&resourceName=${encodeURIComponent(crName)}&namespace=${encodeURIComponent(resourceNamespace)}&group=aquasecurity.github.io&version=v1alpha1&kind=VulnerabilityReport&appNamespace=${encodeURIComponent(application?.metadata?.namespace || 'argo')}`;
      
      console.log(`✅ [Trivy Extension] VulnerabilityReport encontrado: ${crName}`);
      return detailUrl;
      
    } catch (error) {
      console.log(`[Trivy Extension] Erro ao procurar VulnerabilityReport:`, error);
      return '';
    }
  };

  let containers = []
  if(isPod) {
    containers = [...resource?.spec?.containers, ...resource.spec?.initContainers ?? []]
  } else if (isCronJob) {
    containers = [...resource?.spec?.jobTemplate?.spec?.template?.spec.containers, ...resource?.spec?.jobTemplate?.spec?.template?.spec.initContainers ?? []]
  } else {
    containers = [...resource?.spec?.template?.spec.containers, ...resource?.spec?.template?.spec.initContainers ?? []]
  }
    
  const containerNames = containers.map(c => c.name)  
  const images = containers.map(c => c.image)  

  const [currentTabIndex, setCurrentTabIndex] = useState(0);
  const handleTabChange = (_e, tabIndex) => {
    setCurrentTabIndex(tabIndex);
  };

  const onOptionChangeHandler = async (event) => {
    const newContainerName = event.target.value;
    setContainerName(newContainerName);
    setIsLoading(true);
    try {
      const url = await findVulnerabilityReportByLabels(resourceKind, resourceName, newContainerName);
      setReportUrl(url);
    } catch (error) {
      console.error('[Trivy Extension] Erro ao procurar VulnerabilityReport:', error);
      setReportUrl('');
    } finally {
      setIsLoading(false);
    }
  };

  // Carregar automaticamente o VulnerabilityReport
  useEffect(() => {
    const loadReport = async () => {
      if (resourceKind && resourceName && containerName) {
        setIsLoading(true);
        try {
          const url = await findVulnerabilityReportByLabels(resourceKind, resourceName, containerName);
          setReportUrl(url);
        } catch (error) {
          console.error('[Trivy Extension] Erro ao carregar VulnerabilityReport:', error);
          setReportUrl('');
        } finally {
          setIsLoading(false);
        }
      }
    };

    loadReport();
  }, [resourceKind, resourceName, containerName, resourceNamespace]);

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
        <DataGrid key={reportUrl} reportUrl={reportUrl} />
      )}
      {!isLoading && currentTabIndex === 1 && reportUrl && (
        <Dashboard key={reportUrl} reportUrl={reportUrl} />
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
  window?.extensionsAPI?.registerResourceExtension(
    component,
    "*",
    "ReplicaSet",
    "Vulnerabilities",
    { icon: "fa fa-triangle-exclamation" }
  );
  window?.extensionsAPI?.registerResourceExtension(component, '', 'Pod', 'Vulnerabilities', { icon: "fa fa-triangle-exclamation" });
  window?.extensionsAPI?.registerResourceExtension(component, '*', 'StatefulSet', 'Vulnerabilities', { icon: "fa fa-triangle-exclamation" });
  window?.extensionsAPI?.registerResourceExtension(component, '*', 'CronJob', 'Vulnerabilities', { icon: "fa fa-triangle-exclamation" });
})(window);
