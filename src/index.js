import React, { useState, useEffect } from 'react';
import './index.css';
import { Tab, Tabs } from "@mui/material";
import DataGrid from './components/grid/vulnerability-report';
import Dashboard from './components/dashboard/dashboard';

// Version bump for cache invalidation
window.EXTENSION_VERSION = '0.3.16';

const Extension = (props) => {
  const { resource, application } = props;
  const appName = application?.metadata?.name || "";
  const appNamespace = application?.metadata?.namespace || 'argo';
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

  const baseURI = `${window.location.origin}/api/v1/applications/${encodeURIComponent(appName)}/resource`;

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
  const [metricsAvailable, setMetricsAvailable] = useState(true);

  // Build URL helper with proper encoding
  const buildUrl = (name) => 
    `${baseURI}?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(resourceNamespace)}&resourceName=${encodeURIComponent(name)}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io&appNamespace=${encodeURIComponent(appNamespace)}`;

  // Heurística reforçada de descoberta
const tryResourceNames = async (kind, name, container) => {
  if (!name) return '';
  
  const k = kind.toLowerCase();
  console.log(`[Trivy Extension] Listing VulnerabilityReports for: kind=${kind}, name=${name}, container=${container}`);
  console.log(`[Trivy Extension] App namespace: ${appNamespace}`);

  try {
    // Primeiro: LISTAR todos os VulnerabilityReports do namespace
    const listUrl = `${baseURI}?namespace=${encodeURIComponent(resourceNamespace)}&group=aquasecurity.github.io&version=v1alpha1&kind=VulnerabilityReport&appNamespace=${encodeURIComponent(appNamespace)}`;
    
    console.log(`[Trivy Extension] Listing URL: ${listUrl}`);
    
    const listResponse = await fetch(listUrl, { 
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
    
    console.log(`[Trivy Extension] List response: ${listResponse.status} ${listResponse.statusText}`);
    
    if (!listResponse.ok) {
      console.log(`[Trivy Extension] Failed to list VulnerabilityReports: ${listResponse.status}`);
      return '';
    }
    
    const listData = await listResponse.json();
    console.log(`[Trivy Extension] Found ${listData.items?.length || 0} VulnerabilityReports`);
    
    if (!listData.items || listData.items.length === 0) {
      console.log('[Trivy Extension] No VulnerabilityReports found');
      return '';
    }
    
    // Segundo: Tentar match por nome concatenado esperado (<kind>-<resourceName>)
    const resourceUid = resource?.metadata?.uid;
    const originalResourceName = resource?.metadata?.name || '';
    const expectedConcatenatedName = `${k}-${originalResourceName}`.toLowerCase();

    // Tenta primeiro match exato no metadata.name com o padrão concatenado
    const concatMatch = listData.items.find(item => (item.metadata?.name || '').toLowerCase() === expectedConcatenatedName);
    if (concatMatch) {
      console.log(`[Trivy Extension] Found VulnerabilityReport by concatenated name: ${concatMatch.metadata.name}`);
      const crName = concatMatch.metadata.name;
      const detailUrl = `${baseURI}?name=${encodeURIComponent(crName)}&resourceName=${encodeURIComponent(crName)}&namespace=${encodeURIComponent(resourceNamespace)}&group=aquasecurity.github.io&version=v1alpha1&kind=VulnerabilityReport&appNamespace=${encodeURIComponent(appNamespace)}`;
      console.log(`[Trivy Extension] Detail URL: ${detailUrl}`);
      console.log(`✅ [Trivy Extension] Found VulnerabilityReport: ${crName}`);
      return detailUrl;
    }

    // Segundo: FILTRAR pelas labels do Trivy Operator e heurísticas adicionais

    const matchingReport = listData.items.find(item => {
      const labels = item.metadata?.labels || {};
      const ownerRefs = item.metadata?.ownerReferences || [];

      // Preferência: usar labels do Trivy Operator (exatas)
      const resourceNameMatch = labels['trivy-operator.resource.name'] === name;
      const containerMatch = labels['trivy-operator.container.name'] === container;
      const kindMatch = labels['trivy-operator.resource.kind']?.toLowerCase() === k;

      // Alternativa: usar ownerReferences (nome/uid)
      const ownerNameMatch = ownerRefs.some(ref => ref.name === name && ref.kind?.toLowerCase() === kind.toLowerCase());
      const ownerUidMatch = resourceUid ? ownerRefs.some(ref => ref.uid === resourceUid) : false;

      // Heurística adicional: verificar nomes parciais / formas encurtadas geradas pelo Trivy
      const crName = item.metadata?.name || '';
      const nameIncludesMatch = crName === name || crName.includes(name) || name.includes(crName);

      // Se o label contém o nome parcial
      const labelIncludesMatch = (labels['trivy-operator.resource.name'] && (labels['trivy-operator.resource.name'] === name || labels['trivy-operator.resource.name'].includes(name) || name.includes(labels['trivy-operator.resource.name'])));

      const isMatch = (resourceNameMatch && containerMatch && kindMatch) || ownerNameMatch || ownerUidMatch || nameIncludesMatch || labelIncludesMatch;

      if (isMatch) {
        console.log(`[Trivy Extension] Found matching report: ${crName}`);
        console.log(`[Trivy Extension] Labels:`, labels);
        console.log(`[Trivy Extension] OwnerRefs:`, ownerRefs);
      }

      return isMatch;
    });
    
    if (!matchingReport) {
      console.log('[Trivy Extension] No exact matching VulnerabilityReport found');

      // Logar candidatos para debugging: nomes, labels e ownerRefs
      let candidates = [];
      try {
        candidates = listData.items.map(item => ({
          name: item.metadata?.name,
          labels: item.metadata?.labels,
          ownerRefs: item.metadata?.ownerReferences
        }));
        console.log('[Trivy Extension] Available VulnerabilityReports:', candidates);
      } catch (e) {
        console.log('[Trivy Extension] Error while listing candidates:', e);
      }

      // Fallback: pontuar candidatos e escolher o melhor (se passar threshold)
      const scoreCandidate = (item) => {
        const labels = item.metadata?.labels || {};
        const ownerRefs = item.metadata?.ownerReferences || [];
        const crName = item.metadata?.name || '';
        let score = 0;

        // alta prioridade: label exata
        if (labels['trivy-operator.resource.name'] === name) score += 50;
        // owner uid match
        if (resourceUid && ownerRefs.some(ref => ref.uid === resourceUid)) score += 40;
        // container label match
        if (labels['trivy-operator.container.name'] && container && labels['trivy-operator.container.name'] === container) score += 10;
        // kind match
        if (labels['trivy-operator.resource.kind']?.toLowerCase() === k) score += 5;
        // partial name matches
        if (crName === name) score += 30;
        if (crName.includes(name) || name.includes(crName)) score += 20;
        if (labels['trivy-operator.resource.name'] && (labels['trivy-operator.resource.name'].includes(name) || name.includes(labels['trivy-operator.resource.name']))) score += 15;

        return score;
      };

      const scored = listData.items.map(item => ({ item, score: scoreCandidate(item) }));
      scored.sort((a, b) => b.score - a.score);

      const best = scored[0];
      const THRESHOLD = 30; // mínimo aceitável para considerar um candidato

      if (best && best.score >= THRESHOLD) {
        const chosen = best.item;
        console.log(`[Trivy Extension] Fallback selected candidate: ${chosen.metadata.name} with score ${best.score}`);
        console.log(`[Trivy Extension] Candidate labels:`, chosen.metadata.labels);
        console.log(`[Trivy Extension] Candidate ownerRefs:`, chosen.metadata.ownerReferences);

        const crName = chosen.metadata.name;
        const detailUrl = `${baseURI}?name=${encodeURIComponent(crName)}&resourceName=${encodeURIComponent(crName)}&namespace=${encodeURIComponent(resourceNamespace)}&group=aquasecurity.github.io&version=v1alpha1&kind=VulnerabilityReport&appNamespace=${encodeURIComponent(appNamespace)}`;
        console.log(`[Trivy Extension] Detail URL (fallback): ${detailUrl}`);
        return detailUrl;
      }

      console.log('[Trivy Extension] No candidate passed fallback threshold');
      return '';
    }
    
    // Terceiro: DETALHAR usando o metadata.name real do CR
    const crName = matchingReport.metadata.name;
    const detailUrl = `${baseURI}?name=${encodeURIComponent(crName)}&resourceName=${encodeURIComponent(crName)}&namespace=${encodeURIComponent(resourceNamespace)}&group=aquasecurity.github.io&version=v1alpha1&kind=VulnerabilityReport&appNamespace=${encodeURIComponent(appNamespace)}`;
    
    console.log(`[Trivy Extension] Detail URL: ${detailUrl}`);
    console.log(`✅ [Trivy Extension] Found VulnerabilityReport: ${crName}`);
    
    return detailUrl;
    
  } catch (error) {
    console.log(`[Trivy Extension] Error listing/filtering VulnerabilityReports:`, error);
    return '';
  }
};

  // Verifica disponibilidade da extensão de métricas do Argo; se indisponível, mostra fallback
  useEffect(() => {
    let mounted = true;
    const checkMetrics = async () => {
      try {
        const metricsUrl = `${window.location.origin}/extensions/metrics/api/applications/${encodeURIComponent(appName)}/groupkinds/${encodeURIComponent(resourceKind)}/dashboards?appNamespace=${encodeURIComponent(appNamespace)}`;
        console.log('[Trivy Extension] Checking metrics endpoint:', metricsUrl);
        const resp = await fetch(metricsUrl, { method: 'GET', headers: { 'Accept': 'application/json' } });
        if (!mounted) return;
        if (!resp.ok) {
          console.log(`[Trivy Extension] Metrics endpoint not available: ${resp.status} ${resp.statusText}`);
          setMetricsAvailable(false);
          // Forçar visualização do Dashboard de vulnerabilidades
          setCurrentTabIndex(1);
        } else {
          setMetricsAvailable(true);
        }
      } catch (error) {
        console.log('[Trivy Extension] Error checking metrics endpoint:', error);
        if (!mounted) return;
        setMetricsAvailable(false);
        setCurrentTabIndex(1);
      }
    };

    if (appName && resourceKind) checkMetrics();

    return () => { mounted = false; };
  }, [appName, resourceKind, appNamespace]);

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

      {!metricsAvailable && (
        <div style={{ margin: '10px 0', padding: '10px', background: '#fff3cd', color: '#856404', borderRadius: '4px' }}>
          Métricas do Argo indisponíveis (metrics endpoint retornou erro). Mostrando dashboard de vulnerabilidades diretamente a partir do VulnerabilityReport.
        </div>
      )}

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
  const opts = { icon: "fa fa-triangle-exclamation" };
  window?.extensionsAPI?.registerResourceExtension(component, "*", "Deployment", "Vulnerabilities", opts);
  window?.extensionsAPI?.registerResourceExtension(component, "*", "ReplicaSet", "Vulnerabilities", opts);
  window?.extensionsAPI?.registerResourceExtension(component, "*", "Pod", "Vulnerabilities", opts);
  window?.extensionsAPI?.registerResourceExtension(component, "*", "StatefulSet", "Vulnerabilities", opts);
  window?.extensionsAPI?.registerResourceExtension(component, "*", "CronJob", "Vulnerabilities", opts);
})(window);