import React, { useState, useEffect } from 'react';
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

  const [containerName, setContainerName] = useState(isPod ? resource?.spec?.containers[0]?.name : isCronJob ? resource?.spec?.jobTemplate?.spec?.template?.spec.containers[0]?.name : resource?.spec?.template?.spec?.containers[0]?.name);

  const baseURI = `${window.location.origin}/api/v1/applications/${appName}/resource`
  
  // Função para gerar nomes de recurso (completo e truncado)
  const generateResourceNames = (kind, name, container) => {
    const fullName = `${kind}-${name}-${container}`;
    const truncatedName = fullName.length > 63 ? fullName.substring(0, 63) : fullName;
    
    return {
      fullName,
      truncatedName,
      isTruncated: fullName.length > 63
    };
  };

  const resourceNames = generateResourceNames(resourceKind, resourceName, containerName);
  
  // Função para tentar diferentes variações do nome do recurso
  const tryResourceNames = async (kind, name, container) => {
    const names = generateResourceNames(kind, name, container);
    const possibleNames = [names.fullName, names.truncatedName];
    
    // Remove duplicatas se o nome não foi truncado
    const uniqueNames = [...new Set(possibleNames)];
    
    for (const resourceName of uniqueNames) {
      const testUrl = `${baseURI}?name=${resourceName}&namespace=${resourceNamespace}&resourceName=${resourceName}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`;
      
      try {
        // Tenta primeiro com GET (mais compatível que HEAD)
        const response = await fetch(testUrl, { 
          method: 'GET',
          headers: { 'Accept': 'application/json' }
        });
        
        if (response.ok) {
          return testUrl;
        }
      } catch (error) {
        // Continue tentando com o próximo nome
        console.log(`Failed to find resource with name: ${resourceName}`);
      }
    }
    
    // Se nenhum funcionar, retorna o primeiro (nome completo)
    return `${baseURI}?name=${names.fullName}&namespace=${resourceNamespace}&resourceName=${names.fullName}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`;
  };

  let [reportUrl, setReportUrl] = useState(`${baseURI}?name=${resourceNames.fullName}&namespace=${resourceNamespace}&resourceName=${resourceNames.fullName}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`);

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
  const [isLoading, setIsLoading] = useState(false); // Começa como false para não mostrar loading desnecessário
  
  const handleTabChange = (_e, tabIndex) => {
    setCurrentTabIndex(tabIndex);
  };

  // Effect para tentar encontrar o recurso correto na inicialização
  useEffect(() => {
    let isMounted = true; // Flag para evitar state updates em componentes desmontados
    
    const findCorrectResource = async () => {
      // Só ativa o fallback se o nome for muito longo (potencialmente truncado)
      const names = generateResourceNames(resourceKind, resourceName, containerName);
      
      if (names.isTruncated) {
        setIsLoading(true);
        try {
          const correctUrl = await tryResourceNames(resourceKind, resourceName, containerName);
          if (isMounted) {
            setReportUrl(correctUrl);
          }
        } catch (error) {
          console.error('Error finding correct resource:', error);
        } finally {
          if (isMounted) {
            setIsLoading(false);
          }
        }
      }
      // Se o nome não foi truncado, mantém o comportamento original (sem loading)
    };

    findCorrectResource();
    
    // Cleanup function
    return () => {
      isMounted = false;
    };
  }, [resourceKind, resourceName, containerName, resourceNamespace]);

  const onOptionChangeHandler = async (event) => {
    const newContainerName = event.target.value;
    setContainerName(newContainerName);
    
    // Só ativa o fallback se o nome for muito longo (potencialmente truncado)
    const names = generateResourceNames(resourceKind, resourceName, newContainerName);
    
    if (names.isTruncated) {
      setIsLoading(true);
      try {
        const correctUrl = await tryResourceNames(resourceKind, resourceName, newContainerName);
        setReportUrl(correctUrl);
      } catch (error) {
        console.error('Error finding correct resource:', error);
      } finally {
        setIsLoading(false);
      }
    } else {
      // Comportamento original para nomes curtos
      const newResourceNames = generateResourceNames(resourceKind, resourceName, newContainerName);
      setReportUrl(`${baseURI}?name=${newResourceNames.fullName}&namespace=${resourceNamespace}&resourceName=${newResourceNames.fullName}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`);
    }
  };

  return (
    <div>
      <React.Fragment>
        <select class="vulnerability-report__container_dropdown" onChange={onOptionChangeHandler} disabled={isLoading}>
          {containerNames.map((container, index) => {
            return (<option key={index} value={container}>{`${container} (${images[index]})`}</option>)
          })}
        </select>
        {isLoading && (
          <div style={{ padding: '10px', textAlign: 'center', color: '#666' }}>
            Carregando relatório de vulnerabilidades...
          </div>
        )}
        <Tabs value={currentTabIndex} onChange={handleTabChange}>
          <Tab label='Table' />
          <Tab label='Dashboard' />
        </Tabs>
        {!isLoading && currentTabIndex === 0 && (
          <DataGrid reportUrl={reportUrl} />
        )}
        {!isLoading && currentTabIndex === 1 && (
          <Dashboard reportUrl={reportUrl} />
        )}
      </React.Fragment>
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
