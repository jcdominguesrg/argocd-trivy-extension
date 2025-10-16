import React, { useState, useEffect } from 'react';
import './index.css';
import { Tab, Tabs } from "@mui/material";
import DataGrid from './components/grid/vulnerability-report';
import Dashboard from './components/dashboard/dashboard';

// FORCE RELOAD - VERSION 0.3.9 - COMPLETE REWRITE
window.EXTENSION_VERSION = '0.3.9-FORCE-RELOAD';

// Função inteligente para corrigir nomes truncados
const fixName = (name) => {
  console.log(`🔧 V0.3.9 - FIXING NAME: ${name}`);
  
  // Se o nome original tiver mais de 63 caracteres e contiver um hash no final
  const match = name.match(/(.+)-([a-z0-9]{7,10})$/);
  if (match) {
    // Mantém apenas o prefixo + hash, removendo o excesso do meio
    const base = match[1].split('-').slice(0, 3).join('-'); // pega só primeiros 3 blocos
    const fixedName = `${base}-${match[2]}`.slice(0, 63);
    console.log(`✅ V0.3.9 - FIXED NAME: ${name} -> ${fixedName}`);
    return fixedName;
  }
  
  const truncatedName = name.slice(0, 63);
  console.log(`✂️ V0.3.9 - TRUNCATED NAME: ${name} -> ${truncatedName}`);
  return truncatedName;
};

const Extension = (props) => {
  console.log(`🚀🚀🚀 EXTENSION V0.3.9 - COMPLETE REWRITE - FORCE RELOAD 🚀🚀🚀`);
  console.log(`🚀 VERSION: ${window.EXTENSION_VERSION}`);
  console.log(`🚀 DEBUG: Extension component started`);
  console.log(`🚀 DEBUG: Props:`, props);

  const { resource, application } = props;
  const appName = application?.metadata?.name || "";
  const resourceNamespace = resource?.metadata?.namespace || "";
  const isPod = resource?.kind === "Pod";
  const isCronJob = resource?.kind === "CronJob";
  const resourceName = fixName(isPod ? resource?.metadata?.ownerReferences[0].name.toLowerCase() : resource?.metadata?.name);
  const resourceKind = isPod ? resource?.metadata?.ownerReferences[0].kind.toLowerCase() : resource?.kind?.toLowerCase();
  
  console.log(`🚀 DEBUG: Extracted values:`, {
    appName,
    resourceNamespace,
    isPod,
    isCronJob,
    resourceName,
    resourceKind
  });

  const [containerName, setContainerName] = useState(isPod ? resource?.spec?.containers[0]?.name : isCronJob ? resource?.spec?.jobTemplate?.spec?.template?.spec.containers[0]?.name : resource?.spec?.template?.spec?.containers[0]?.name);

  const baseURI = `${window.location.origin}/api/v1/applications/${appName}/resource`
  
  // Função para gerar nomes de recurso (completo e truncado) - DEPRECATED
  // REMOVIDA - não está sendo usada mais
  
  // Função para descobrir o VulnerabilityReport real
  const tryResourceNames = async (kind, name, container) => {
    console.log(`🚀🚀🚀 V0.3.9 - DYNAMIC DISCOVERY SEARCH 🚀🚀🚀`);
    console.log(`🚀 VERSION: ${window.EXTENSION_VERSION}`);
    console.log(`🔍 Discovering real VulnerabilityReport name for:`, { kind, name, container });
    
    // Primeiro, tenta listar todos os VulnerabilityReports no namespace
    try {
      console.log(`🔍 Step 1: Listing all VulnerabilityReports in namespace: ${resourceNamespace}`);
      const listUrl = `${baseURI}?namespace=${resourceNamespace}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`;
      
      const listResponse = await fetch(listUrl, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      
      if (listResponse.ok) {
        const listData = await listResponse.json();
        console.log(`📋 Found VulnerabilityReports:`, listData);
        
        if (listData.items && listData.items.length > 0) {
          console.log(`📋 All VulnerabilityReports found:`, listData.items.map(item => item.metadata.name));
          
          // Procura por VulnerabilityReports que contenham partes do nome da aplicação
          const matchingReports = listData.items.filter(item => {
            const reportName = item.metadata?.name || '';
            const appNameLower = appName.toLowerCase();
            const resourceNameLower = resourceName.toLowerCase();
            
            // Procura por correspondências inteligentes
            return reportName.toLowerCase().includes(appNameLower) || 
                   reportName.toLowerCase().includes(resourceNameLower) ||
                   reportName.toLowerCase().includes(kind.toLowerCase()) ||
                   // Procura por padrões de hash (últimos 10 caracteres)
                   reportName.toLowerCase().includes(name.substring(name.length - 10).toLowerCase());
          });
          
          if (matchingReports.length > 0) {
            console.log(`✅ Found matching VulnerabilityReports:`, matchingReports.map(r => r.metadata.name));
            const firstMatch = matchingReports[0];
            const realName = firstMatch.metadata.name;
            
            const finalUrl = `${baseURI}?name=${realName}&namespace=${resourceNamespace}&resourceName=${realName}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`;
            console.log(`🎯 Using real VulnerabilityReport: ${realName}`);
            return finalUrl;
          } else {
            console.log(`❌ No matching VulnerabilityReports found for app: ${appName}, resource: ${resourceName}`);
          }
        }
      }
    } catch (error) {
      console.log(`💥 Error listing VulnerabilityReports:`, error);
    }
    
    // Fallback: tenta nomes baseados nos padrões conhecidos
    console.log(`🔍 Step 2: Trying known patterns`);
    const possibleNames = [
      `${kind}-${name}`,                    // Nome corrigido
      `${kind}-${name}-${container}`,       // Com container
      `${kind}-${name.substring(0, 20)}`,   // Truncado
      `${kind}-${name.substring(0, 10)}`,   // Primeiros 10 caracteres
      `${kind}-${name.substring(name.length - 10)}`, // Últimos 10 caracteres
    ];
    
    console.log(`🎯 Trying fallback names:`, possibleNames);
    
    for (const resourceName of possibleNames) {
      const testUrl = `${baseURI}?name=${resourceName}&namespace=${resourceNamespace}&resourceName=${resourceName}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`;
      
      try {
        console.log(`🔗 Testing: ${testUrl}`);
        const response = await fetch(testUrl, { 
          method: 'GET',
          headers: { 'Accept': 'application/json' }
        });
        
        if (response.ok) {
          console.log(`✅ Found VulnerabilityReport with name: ${resourceName}`);
          return testUrl;
        } else {
          console.log(`❌ Not found: ${resourceName} (${response.status})`);
        }
      } catch (error) {
        console.log(`💥 Error testing ${resourceName}:`, error);
      }
    }
    
    // Se nenhum funcionar, retorna o primeiro
    console.log(`⚠️ No VulnerabilityReport found, using default`);
    return `${baseURI}?name=${kind}-${name}-${container}&namespace=${resourceNamespace}&resourceName=${kind}-${name}-${container}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`;
  };

  const [reportUrl, setReportUrl] = useState('');

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
      console.log(`🚀 DEBUG: Starting findCorrectResource`);
      console.log(`🚀 DEBUG: resourceKind=${resourceKind}, resourceName=${resourceName}, containerName=${containerName}`);
      console.log(`🚀 DEBUG: resourceNamespace=${resourceNamespace}`);
      
      // Sempre tenta o fallback para encontrar o VulnerabilityReport correto
      setIsLoading(true);
      try {
        console.log(`🚀 DEBUG: Calling tryResourceNames...`);
        const correctUrl = await tryResourceNames(resourceKind, resourceName, containerName);
        console.log(`🚀 DEBUG: tryResourceNames returned: ${correctUrl}`);
        if (isMounted) {
          setReportUrl(correctUrl);
          console.log(`🚀 DEBUG: reportUrl updated to: ${correctUrl}`);
        }
      } catch (error) {
        console.error('🚀 DEBUG: Error finding correct resource:', error);
      } finally {
        if (isMounted) {
          setIsLoading(false);
          console.log(`🚀 DEBUG: Loading finished`);
        }
      }
    };

    findCorrectResource();
    
    // Cleanup function
    return () => {
      isMounted = false;
    };
  }, [resourceKind, resourceName, containerName, resourceNamespace]);

  const onOptionChangeHandler = async (event) => {
    const newContainerName = event.target.value;
    console.log(`🚀 DEBUG: onOptionChangeHandler called with container: ${newContainerName}`);
    setContainerName(newContainerName);
    
    // Sempre tenta o fallback para encontrar o VulnerabilityReport correto
    setIsLoading(true);
    try {
      console.log(`🚀 DEBUG: Calling tryResourceNames from handler...`);
      const correctUrl = await tryResourceNames(resourceKind, resourceName, newContainerName);
      console.log(`🚀 DEBUG: Handler got URL: ${correctUrl}`);
      setReportUrl(correctUrl);
    } catch (error) {
      console.error('🚀 DEBUG: Handler error finding correct resource:', error);
    } finally {
      setIsLoading(false);
      console.log(`🚀 DEBUG: Handler loading finished`);
    }
  };

  return (
    <div>
      <React.Fragment>
        <select className="vulnerability-report__container_dropdown" onChange={onOptionChangeHandler} disabled={isLoading}>
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
