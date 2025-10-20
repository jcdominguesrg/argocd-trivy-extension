import React, { useState, useEffect } from 'react';
import './index.css';
import { Tab, Tabs } from "@mui/material";
import DataGrid from './components/grid/vulnerability-report';
import Dashboard from './components/dashboard/dashboard';

// Version bump for cache invalidation
window.EXTENSION_VERSION = '0.4.3';

const Extension = (props) => {

  const { resource, application } = props;
  const appName = application?.metadata?.name || "";
  const resourceNamespace = resource?.metadata?.namespace || "";
  const isPod = resource?.kind === "Pod"
  const isCronJob = resource?.kind === "CronJob"
  const resourceName = isPod ? resource?.metadata?.ownerReferences[0].name.toLowerCase() : resource?.metadata?.name;
  const resourceKind = isPod ? resource?.metadata?.ownerReferences[0].kind.toLowerCase() : resource?.kind?.toLowerCase();

  let [containerName] = useState(isPod ? resource?.spec?.containers[0]?.name : isCronJob ? resource?.spec?.jobTemplate?.spec?.template?.spec.containers[0]?.name : resource?.spec?.template?.spec?.containers[0]?.name);

  const appNamespace = application?.metadata?.namespace || 'argo';
  const baseURI = `${window.location.origin}/api/v1/applications/${encodeURIComponent(appName)}/resource`
  const [reportUrl, setReportUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);

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

  // Função para descobrir dinamicamente o nome do VulnerabilityReport
  const findVulnerabilityReport = async (kind, name, container) => {
    if (!name) return '';
    
    console.log(`[Trivy Extension] Procurando VulnerabilityReport para: kind=${kind}, name=${name}, container=${container}`);
    
    try {
      // Primeiro: LISTAR todos os VulnerabilityReports do namespace
      const listUrl = `${baseURI}?namespace=${encodeURIComponent(resourceNamespace)}&group=aquasecurity.github.io&version=v1alpha1&kind=VulnerabilityReport&appNamespace=${encodeURIComponent(appNamespace)}`;
      
      console.log(`[Trivy Extension] Listando VulnerabilityReports: ${listUrl}`);
      
      const listResponse = await fetch(listUrl, { 
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      
      if (!listResponse.ok) {
        console.log(`[Trivy Extension] Erro ao listar VulnerabilityReports: ${listResponse.status}`);
        return '';
      }
      
      const listData = await listResponse.json();
      console.log(`[Trivy Extension] Encontrados ${listData.items?.length || 0} VulnerabilityReports`);
      
      if (!listData.items || listData.items.length === 0) {
        console.log('[Trivy Extension] Nenhum VulnerabilityReport encontrado');
        return '';
      }
      
      // Segundo: FILTRAR pelas labels do ReplicaSet
      const matchingReport = listData.items.find(item => {
        const labels = item.metadata?.labels || {};
        const ownerRefs = item.metadata?.ownerReferences || [];
        
        // Preferência: usar labels do Trivy Operator
        const resourceNameMatch = labels['trivy-operator.resource.name'] === name;
        const containerMatch = labels['trivy-operator.container.name'] === container;
        const kindMatch = labels['trivy-operator.resource.kind']?.toLowerCase() === kind.toLowerCase();
        
        // Alternativa: usar ownerReferences
        const ownerMatch = ownerRefs.some(ref => 
          ref.name === name && ref.kind?.toLowerCase() === kind.toLowerCase()
        );
        
        const isMatch = (resourceNameMatch && containerMatch && kindMatch) || ownerMatch;
        
        if (isMatch) {
          console.log(`[Trivy Extension] Encontrado VulnerabilityReport: ${item.metadata.name}`);
          console.log(`[Trivy Extension] Labels:`, labels);
        }
        
        return isMatch;
      });
      
      if (!matchingReport) {
        console.log('[Trivy Extension] Nenhum VulnerabilityReport correspondente encontrado - tentando fallback por metadata.name encurtado');

        // Fallback: checar se algum VulnerabilityReport tem metadata.name curto (ex: 'replicaset-7cb984db4')
        // que esteja contido dentro do resourceName longo (ex: 'replicaset-...-7cb984db4-...')
        const shortNameMatch = listData.items.find(item => {
          const crName = (item.metadata?.name || '').toLowerCase();
          if (!crName) return false;
          // deve começar com o tipo (ex: 'replicaset-')
          if (!crName.startsWith(kind.toLowerCase() + '-')) return false;
          // se o resourceName (longo) contém esse crName, consideramos match
          if ((name || '').toLowerCase().includes(crName)) {
            console.log(`[Trivy Extension] Fallback curto: encontrou ${crName} contido em ${name}`);
            return true;
          }
          return false;
        });

        if (shortNameMatch) {
          const crName = shortNameMatch.metadata.name;
          const detailUrl = `${baseURI}?name=${encodeURIComponent(crName)}&resourceName=${encodeURIComponent(crName)}&namespace=${encodeURIComponent(resourceNamespace)}&group=aquasecurity.github.io&version=v1alpha1&kind=VulnerabilityReport&appNamespace=${encodeURIComponent(appNamespace)}`;
          console.log(`✅ [Trivy Extension] VulnerabilityReport encontrado via fallback curto: ${crName}`);
          return detailUrl;
        }

        console.log('[Trivy Extension] Fallback curto não encontrou nenhum VulnerabilityReport');
        return '';
      }
      
      // Terceiro: DETALHAR usando o metadata.name real do CR
      const crName = matchingReport.metadata.name;
      const detailUrl = `${baseURI}?name=${encodeURIComponent(crName)}&resourceName=${encodeURIComponent(crName)}&namespace=${encodeURIComponent(resourceNamespace)}&group=aquasecurity.github.io&version=v1alpha1&kind=VulnerabilityReport&appNamespace=${encodeURIComponent(appNamespace)}`;
      
      console.log(`✅ [Trivy Extension] VulnerabilityReport encontrado: ${crName}`);
      return detailUrl;
      
    } catch (error) {
      console.log(`[Trivy Extension] Erro ao procurar VulnerabilityReport:`, error);
      return '';
    }
  };

  const handleTabChange = (_e, tabIndex) => {
    setCurrentTabIndex(tabIndex);
  };

  const onOptionChangeHandler = async (event) => {
    const newContainerName = event.target.value;
    setContainerName(newContainerName);
    setIsLoading(true);
    try {
      const url = await findVulnerabilityReport(resourceKind, resourceName, newContainerName);
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
          const url = await findVulnerabilityReport(resourceKind, resourceName, containerName);
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
