import React, { useState, useEffect } from 'react';
import './index.css';
import { Tab, Tabs } from "@mui/material";
import DataGrid from './components/grid/vulnerability-report';
import Dashboard from './components/dashboard/dashboard';

// Bump visível p/ forçar recarregamento do bundle no Argo
window.EXTENSION_VERSION = '0.3.10';

// ---------- Utils ----------
const fixName = (name = '') => {
  try {
    const n = String(name).toLowerCase();
    const m = n.match(/(.+)-([a-z0-9]{7,10})$/);
    if (m) {
      const base = m[1].split('-').slice(0, 3).join('-');
      return `${base}-${m[2]}`.slice(0, 63);
    }
    return n.slice(0, 63);
  } catch {
    return (name || '').toString().slice(0, 63);
  }
};

// pega último bloco (hash) de um nome "xxx-yyy-<hash>"
const lastBlock = (name = '') => {
  const parts = String(name).split('-');
  return parts[parts.length - 1] || '';
};

// ---------- Componente ----------
const Extension = (props) => {
  console.log('🔌 Trivy Ext v', window.EXTENSION_VERSION, props);

  const { resource = {}, application = {} } = props;
  const appName = application?.metadata?.name || '';
  const resourceNamespace = resource?.metadata?.namespace || '';
  const isPod = resource?.kind === 'Pod';
  const isCronJob = resource?.kind === 'CronJob';

  // Nome "base" do recurso que gerou a imagem a ser escaneada
  const baseNameRaw = isPod
    ? resource?.metadata?.ownerReferences?.[0]?.name
    : resource?.metadata?.name;

  const resourceName = fixName(baseNameRaw || '');
  const resourceKind = (isPod
    ? resource?.metadata?.ownerReferences?.[0]?.kind
    : resource?.kind) || '';

  // containers (corrigido: nunca espalhar undefined)
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
  const [containerName, setContainerName] = useState(containerNames[0] || '');
  const [currentTabIndex, setCurrentTabIndex] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [reportUrl, setReportUrl] = useState('');

  const baseURI = `${window.location.origin}/api/v1/applications/${encodeURIComponent(appName)}`;

  // Busca na árvore de recursos do app e tenta casar um VulnerabilityReport no namespace
  const discoverReportViaTree = async () => {
    const treeUrl = `${baseURI}/resource-tree`;
    console.log('🌳 Fetching resource-tree:', treeUrl);

    const res = await fetch(treeUrl, { headers: { Accept: 'application/json' } });
    if (!res.ok) {
      console.warn('resource-tree fetch failed:', res.status);
      return null;
    }
    const data = await res.json();

    // Argo retorna nós em data.nodes (ou data?.nodes), mantendo retrocompatibilidade
    const nodes = data?.nodes || data?.resourceTree?.nodes || [];
    const vrNodes = nodes.filter(n =>
      (n.group === 'aquasecurity.github.io') &&
      (String(n.kind).toLowerCase() === 'vulnerabilityreport') &&
      (n.namespace === resourceNamespace)
    );

    if (vrNodes.length === 0) {
      console.log('Nenhum VulnerabilityReport no namespace na árvore.');
      return null;
    }

    // Heurística de matching:
    // 1) tenta nome exato "kind-lowercase + '-' + resourceName"
    const kindLower = String(resourceKind || '').toLowerCase();
    const expected1 = `${kindLower}-${resourceName}`; // ex: replicaset-shipay-...-66fb4b695f
    // 2) tenta apenas o HASH final do RS (ex: replicaset-66fb4b695f)
    const hash = lastBlock(baseNameRaw || resourceName);
    const expected2 = `${kindLower}-${hash}`;

    // 3) também aceita qualquer VR que contenha o hash
    const byExact = vrNodes.find(n => n.name === expected1)
      || vrNodes.find(n => n.name === expected2);

    if (byExact) {
      console.log('🎯 VR por nome esperado:', byExact.name);
      return byExact.name;
    }

    const byHash = vrNodes.find(n => n.name?.includes(hash));
    if (byHash) {
      console.log('🎯 VR por hash:', byHash.name);
      return byHash.name;
    }

    // 4) fallback: primeiro VR do namespace (não ideal, mas evita 404)
    console.log('⚠️ Nenhum match por nome/hash; usando primeiro VR do namespace:', vrNodes[0]?.name);
    return vrNodes[0]?.name || null;
  };

  // Monta a URL final do Argo para UM resource específico
  const buildReportUrl = (vrName) => {
    const p = new URLSearchParams({
      name: vrName,
      namespace: resourceNamespace,
      resourceName: vrName,
      version: 'v1alpha1',
      kind: 'VulnerabilityReport',
      group: 'aquasecurity.github.io'
    });
    return `${baseURI}/resource?${p.toString()}`;
  };

  const tryResolveReport = async () => {
    setIsLoading(true);
    try {
      // 1) tenta achar via árvore
      const vrName = await discoverReportViaTree();
      if (vrName) {
        const url = buildReportUrl(vrName);
        console.log('✅ resolved reportUrl:', url);
        setReportUrl(url);
        return;
      }

      // 2) fallback por padrões (se árvore falhar)
      const kindLower = String(resourceKind || '').toLowerCase();
      const hash = lastBlock(baseNameRaw || resourceName);
      const candidates = [
        `${kindLower}-${resourceName}`,
        `${kindLower}-${hash}`,
        `${kindLower}-${resourceName.substring(0, 20)}`,
        `${kindLower}-${resourceName.substring(0, 10)}`,
      ];
      for (const vr of candidates) {
        const url = buildReportUrl(vr);
        const r = await fetch(url, { headers: { Accept: 'application/json' } });
        if (r.ok) {
          console.log('✅ fallback OK com', vr);
          setReportUrl(url);
          return;
        }
      }

      console.warn('❌ Nenhum VulnerabilityReport encontrado por heurística.');
      setReportUrl('');
    } catch (e) {
      console.error('💥 tryResolveReport error:', e);
      setReportUrl('');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    tryResolveReport();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appName, resourceNamespace, resourceKind, resourceName, containerName]);

  const onOptionChangeHandler = async (e) => {
    const newContainerName = e.target.value;
    setContainerName(newContainerName);
    // não muda a heurística do nome do VR, mas re-dispara busca p/ consistência
    await tryResolveReport();
  };

  const handleTabChange = (_e, tabIndex) => setCurrentTabIndex(tabIndex);

  return (
    <div>
      <select
        className="vulnerability-report__container_dropdown"
        onChange={onOptionChangeHandler}
        disabled={isLoading || containerNames.length <= 1}
        value={containerName}
      >
        {containerNames.map((container, i) => (
          <option key={container} value={container}>
            {container}{images[i] ? ` (${images[i]})` : ''}
          </option>
        ))}
      </select>

      {isLoading && (
        <div style={{ padding: 10, textAlign: 'center', color: '#666' }}>
          Carregando relatório de vulnerabilidades...
        </div>
      )}

      <Tabs value={currentTabIndex} onChange={handleTabChange}>
        <Tab label="Table" />
        <Tab label="Dashboard" />
      </Tabs>

      {!isLoading && currentTabIndex === 0 && reportUrl && (
        <DataGrid reportUrl={reportUrl} />
      )}
      {!isLoading && currentTabIndex === 1 && reportUrl && (
        <Dashboard reportUrl={reportUrl} />
      )}
      {!isLoading && !reportUrl && (
        <div style={{ padding: 10, color: '#b00' }}>
          Não foi possível localizar o VulnerabilityReport para este recurso.
        </div>
      )}
    </div>
  );
};

const component = Extension;

// Registre também em Deployment se quiser ver na view do Deployment
((window) => {
  const opts = { icon: "fa fa-triangle-exclamation" };
  window?.extensionsAPI?.registerResourceExtension(component, '*', 'ReplicaSet', 'Vulnerabilities', opts);
  window?.extensionsAPI?.registerResourceExtension(component, '*', 'Pod', 'Vulnerabilities', opts);
  window?.extensionsAPI?.registerResourceExtension(component, '*', 'StatefulSet', 'Vulnerabilities', opts);
  window?.extensionsAPI?.registerResourceExtension(component, '*', 'CronJob', 'Vulnerabilities', opts);
  window?.extensionsAPI?.registerResourceExtension(component, '*', 'Deployment', 'Vulnerabilities', opts); // opcional
})(window);