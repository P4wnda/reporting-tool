(() => {
  const STORAGE_KEY = 'p4wnda_reporting_tool_v1';
  const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  const emptyReport = () => ({
    schema: 'p4wnda.vulnerability-report.v1',
    title: '',
    client: '',
    target: '',
    scope: '',
    summary: '',
    importedRun: null,
    findings: []
  });

  let state = readState();
  let selectedId = state.findings[0]?.id || '';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function readState() {
    try {
      return { ...emptyReport(), ...JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') };
    } catch {
      return emptyReport();
    }
  }

  function saveState() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    render();
  }

  function esc(s = '') {
    return String(s).replace(/[&<>'"]/g, ch => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[ch]));
  }

  function init() {
    bindEvents();
    render();
  }

  function bindEvents() {
    document.addEventListener('click', onClick);
    document.addEventListener('input', onInput);
    document.addEventListener('change', onChange);
    document.addEventListener('paste', onPaste);
    $('#importFile').addEventListener('change', importFile);
  }

  function onClick(e) {
    const button = e.target.closest('button');
    if (!button) return;
    const action = button.dataset.action;
    if (button.dataset.findingId) {
      selectedId = button.dataset.findingId;
      render();
      return;
    }
    if (button.dataset.evidenceIndex) {
      appendEvidence(Number(button.dataset.evidenceIndex));
      return;
    }
    if (button.dataset.deleteScreenshot) {
      deleteScreenshot(button.dataset.deleteScreenshot);
      return;
    }
    if (action === 'add-finding') addFinding();
    if (action === 'delete-finding') deleteFinding();
    if (action === 'export-json') exportJson();
    if (action === 'export-md') exportMarkdown();
    if (action === 'reset-report') resetReport();
  }

  function onInput(e) {
    const reportKey = e.target.dataset.report;
    const findingKey = e.target.dataset.finding;
    if (reportKey) {
      state[reportKey] = e.target.value;
      persistOnly();
      updateSummary();
    }
    if (findingKey) {
      const finding = currentFinding();
      if (!finding) return;
      finding[findingKey] = e.target.value;
      persistOnly();
      renderFindingList();
      updateSelectedMeta();
      updateSummary();
    }
  }

  function onChange(e) {
    if (!e.target.matches('[data-screenshot-upload]')) return;
    addScreenshotFiles(Array.from(e.target.files || []));
    e.target.value = '';
  }

  function onPaste(e) {
    if (!currentFinding()) return;
    const files = Array.from(e.clipboardData?.files || []).filter(file => file.type.startsWith('image/'));
    if (!files.length) return;
    e.preventDefault();
    addScreenshotFiles(files);
  }

  function persistOnly() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }

  async function importFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      importRun(parsed);
      toast('Run JSON imported');
    } catch {
      toast('Invalid JSON file');
    } finally {
      e.target.value = '';
    }
  }

  function importRun(run) {
    if (run.schema !== 'p4wnda.pentest-run.v1') {
      toast('Unsupported run schema');
      return;
    }
    state.importedRun = run;
    state.target ||= run.target?.name || '';
    state.scope ||= run.target?.scope || '';
    state.summary ||= run.target?.objective || '';
    saveState();
  }

  function addFinding() {
    const finding = {
      id: String(Date.now()),
      title: 'Untitled Finding',
      severity: 'Medium',
      cvss: '',
      status: 'Open',
      asset: state.target || '',
      category: '',
      description: '',
      impact: '',
      evidence: '',
      screenshots: [],
      reproduction: '',
      remediation: '',
      references: ''
    };
    state.findings.push(finding);
    selectedId = finding.id;
    saveState();
  }

  function deleteFinding() {
    const finding = currentFinding();
    if (!finding) return;
    if (!confirm(`Delete "${finding.title || 'Untitled Finding'}"?`)) return;
    state.findings = state.findings.filter(f => f.id !== finding.id);
    selectedId = state.findings[0]?.id || '';
    saveState();
  }

  function resetReport() {
    if (!confirm('Reset this report? This clears imported data and all findings.')) return;
    state = emptyReport();
    selectedId = '';
    saveState();
    toast('Report reset');
  }

  function currentFinding() {
    return state.findings.find(f => f.id === selectedId) || null;
  }

  function appendEvidence(index) {
    const item = evidenceItems()[index];
    if (!item) return;
    const finding = currentFinding();
    if (!finding) {
      addFinding();
    }
    const target = currentFinding();
    target.evidence = [target.evidence, item.body].filter(Boolean).join('\n\n');
    saveState();
    toast('Evidence added');
  }

  async function addScreenshotFiles(files) {
    const images = files.filter(file => file.type.startsWith('image/'));
    if (!images.length) return;
    if (!currentFinding()) addFinding();
    const finding = currentFinding();
    finding.screenshots ||= [];
    const loaded = await Promise.all(images.map(fileToScreenshot));
    finding.screenshots.push(...loaded);
    saveState();
    toast(`${loaded.length} screenshot${loaded.length === 1 ? '' : 's'} added`);
  }

  function fileToScreenshot(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve({
        id: String(Date.now()) + Math.random().toString(16).slice(2),
        name: file.name || 'pasted-screenshot.png',
        type: file.type || 'image/png',
        dataUrl: reader.result,
        addedAt: new Date().toISOString()
      });
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  function deleteScreenshot(id) {
    const finding = currentFinding();
    if (!finding) return;
    finding.screenshots = (finding.screenshots || []).filter(s => s.id !== id);
    saveState();
  }

  function render() {
    renderReportFields();
    renderFindingList();
    renderEvidenceList();
    renderEditor();
    updateSummary();
  }

  function renderReportFields() {
    $$('[data-report]').forEach(el => {
      if (el.value !== (state[el.dataset.report] || '')) el.value = state[el.dataset.report] || '';
    });
  }

  function renderFindingList() {
    const sorted = [...state.findings].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
    $('#findingCount').textContent = String(state.findings.length);
    $('#findingList').innerHTML = sorted.length ? sorted.map(f => `
      <button type="button" class="finding-item severity-card-${esc(f.severity.toLowerCase())} ${f.id === selectedId ? 'active' : ''}" data-finding-id="${esc(f.id)}">
        <span class="finding-top"><span class="finding-title">${esc(f.title || 'Untitled Finding')}</span><span class="severity ${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span></span>
        <span class="finding-sub">${esc([f.asset, f.status].filter(Boolean).join(' - ') || 'No asset set')}</span>
      </button>`).join('') : '<div class="empty-state"><p>No findings yet.</p></div>';
  }

  function renderEvidenceList() {
    const items = evidenceItems();
    $('#evidenceCount').textContent = String(items.length);
    $('#evidenceList').innerHTML = items.length ? items.map((item, index) => `
      <button type="button" class="evidence-item" data-evidence-index="${index}">
        <span class="evidence-title">${esc(item.title)}</span>
        <span class="evidence-sub">${esc(item.kind)}</span>
      </button>`).join('') : '<div class="empty-state"><p>No run JSON imported.</p></div>';
  }

  function renderEditor() {
    const finding = currentFinding();
    if (!finding) {
      $('#findingEditor').innerHTML = '<div class="empty-state"><h2>No finding selected</h2><p>Import a Pentest Cheatsheet run JSON, then add findings and attach relevant evidence.</p></div>';
      return;
    }
    const fragment = $('#findingTemplate').content.cloneNode(true);
    $('#findingEditor').replaceChildren(fragment);
    $('#selectedMeta').textContent = `${finding.severity} / ${finding.status}`;
    $$('[data-finding]', $('#findingEditor')).forEach(el => {
      el.value = finding[el.dataset.finding] || '';
    });
    renderScreenshots(finding);
  }

  function renderScreenshots(finding) {
    const screenshots = finding.screenshots || [];
    $('#screenshotList').innerHTML = screenshots.length ? screenshots.map(s => `
      <figure class="screenshot-card">
        <img src="${esc(s.dataUrl)}" alt="${esc(s.name || 'Evidence screenshot')}">
        <figcaption>
          <span>${esc(s.name || 'Screenshot')}</span>
          <button type="button" data-delete-screenshot="${esc(s.id)}">Remove</button>
        </figcaption>
      </figure>`).join('') : '<div class="empty-inline">No screenshots attached.</div>';
  }

  function updateSelectedMeta() {
    const finding = currentFinding();
    const meta = $('#selectedMeta');
    if (finding && meta) meta.textContent = `${finding.severity} / ${finding.status}`;
  }

  function evidenceItems() {
    const run = state.importedRun;
    if (!run) return [];
    const items = [];
    (run.commands?.done || []).forEach(cmd => items.push({
      kind: 'Done command',
      title: cmd.title || 'Command',
      body: commandBlock(cmd)
    }));
    (run.commands?.favorites || []).forEach(cmd => items.push({
      kind: 'Favorite command',
      title: cmd.title || 'Command',
      body: commandBlock(cmd)
    }));
    (run.commands?.notes || []).forEach(entry => items.push({
      kind: 'Command note',
      title: entry.command?.title || 'Command note',
      body: `${commandBlock(entry.command)}\nNote: ${entry.note || ''}`
    }));
    (run.sideNotes || []).forEach(note => items.push({
      kind: 'Side note',
      title: note.title || 'Side note',
      body: `${note.title || 'Side note'}\n${note.body || ''}`.trim()
    }));
    (run.copyHistory || []).slice(0, 30).forEach(entry => items.push({
      kind: 'Copy history',
      title: entry.command || 'Copied command',
      body: entry.command || ''
    }));
    (run.intel?.flags || []).forEach(flag => items.push({ kind: 'Flag', title: flag, body: `Flag: ${flag}` }));
    (run.intel?.credentials || []).forEach(cred => items.push({ kind: 'Credential', title: cred, body: `Credential: ${cred}` }));
    return items;
  }

  function commandBlock(cmd = {}) {
    return `${cmd.title || 'Command'}\n${cmd.command || cmd.oneLine || ''}`.trim();
  }

  function updateSummary() {
    const target = state.target || state.importedRun?.target?.name || 'No target';
    const counts = severityOrder
      .map(sev => `${state.findings.filter(f => f.severity === sev).length} ${sev}`)
      .join(' / ');
    $('#summary').textContent = `${target} - ${state.findings.length} findings - ${counts}`;
  }

  function exportJson() {
    download(`${fileBase()}-report.json`, JSON.stringify(buildReport(), null, 2), 'application/json');
  }

  function exportMarkdown() {
    download(`${fileBase()}-report.md`, buildMarkdown(), 'text/markdown');
  }

  function buildReport() {
    return {
      ...state,
      exportedAt: new Date().toISOString()
    };
  }

  function buildMarkdown() {
    const report = buildReport();
    const findings = [...report.findings].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
    return [
      `# ${report.title || 'Vulnerability Report'}`,
      `**Client:** ${report.client || ''}`,
      `**Target:** ${report.target || ''}`,
      `**Scope:** ${report.scope || ''}`,
      `**Exported:** ${report.exportedAt}`,
      `## Executive Summary\n\n${report.summary || ''}`,
      `## Finding Summary\n\n${summaryTable(findings)}`,
      ...findings.map(findingMarkdown)
    ].join('\n\n');
  }

  function summaryTable(findings) {
    const rows = findings.map(f => `| ${f.severity || ''} | ${f.title || ''} | ${f.asset || ''} | ${f.status || ''} |`);
    return ['| Severity | Title | Asset | Status |', '| --- | --- | --- | --- |', ...rows].join('\n');
  }

  function findingMarkdown(f) {
    return [
      `## ${f.severity || 'Medium'} - ${f.title || 'Untitled Finding'}`,
      `**CVSS:** ${f.cvss || ''}`,
      `**Status:** ${f.status || ''}`,
      `**Affected Asset:** ${f.asset || ''}`,
      `**Category:** ${f.category || ''}`,
      `### Description\n\n${f.description || ''}`,
      `### Impact\n\n${f.impact || ''}`,
      `### Evidence\n\n${f.evidence || ''}`,
      screenshotMarkdown(f),
      `### Reproduction Steps\n\n${f.reproduction || ''}`,
      `### Remediation\n\n${f.remediation || ''}`,
      `### References\n\n${f.references || ''}`
    ].join('\n\n');
  }

  function screenshotMarkdown(f) {
    const shots = f.screenshots || [];
    if (!shots.length) return '### Screenshots\n\n';
    return `### Screenshots\n\n${shots.map(s => `![${s.name || 'Screenshot'}](${s.dataUrl})`).join('\n\n')}`;
  }

  function fileBase() {
    return (state.target || state.title || 'pentest').trim().replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '') || 'pentest';
  }

  function download(name, text, type) {
    const blob = new Blob([text], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function toast(message) {
    const el = $('#toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => el.classList.remove('show'), 1400);
  }

  init();
})();
