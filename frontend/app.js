'use strict';

const content = document.querySelector('#content');
const notification = document.querySelector('#notification');
let status;
let accessToken = '';
let identity;
let renderVersion = 0;
const labels = {overview:'Overview',datasets:'Datasets',findings:'Findings',models:'Model & evaluation',settings:'Configuration',integrations:'Connections'};
const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const json = value => escape(JSON.stringify(value, null, 2));
const count = value => new Intl.NumberFormat().format(value);
const badge = (text, tone = '') => `<span class="tag ${tone}">${escape(text)}</span>`;
const heading = (title, text, action = '') => `<div class="page-heading"><div><span class="eyebrow">NETWORK EVIDENCE WORKBENCH</span><h1>${escape(title)}</h1><p>${escape(text)}</p></div>${action}</div>`;
const empty = (title, text, action = '') => `<div class="empty"><div class="empty-symbol" aria-hidden="true">◎</div><h3>${escape(title)}</h3><p>${escape(text)}</p>${action}</div>`;
const panel = (title, body, trailing = '') => `<section class="panel"><div class="panel-heading"><h2>${escape(title)}</h2>${trailing}</div>${body}</section>`;
const importLink = '<a class="button primary" href="#datasets">＋ Import dataset</a>';

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  const response = await fetch(`/api${path}`, {...options, headers});
  const data = await response.json();
  if (!response.ok) {
    const detail = typeof data.detail === 'string' ? data.detail : 'The request could not be processed. Check your input and configuration.';
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return data;
}

function notify(message, error = false) {
  notification.textContent = message;
  notification.className = error ? 'error' : '';
  notification.hidden = false;
}

async function action(button, operation) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Working…';
  button.setAttribute('aria-busy', 'true');
  try { await operation(); } catch (error) { notify(error.message, true); }
  finally { button.disabled = false; button.textContent = label; button.removeAttribute('aria-busy'); }
}

function stats() {
  return `<dl class="stats"><div class="stat"><dt>Imported datasets</dt><dd>${count(status.datasets)}</dd><small>Files provided to this workspace</small></div><div class="stat"><dt>Measured findings</dt><dd>${count(status.findings)}</dd><small>Persisted analysis records</small></div><div class="stat"><dt>ML model</dt><dd class="word">${status.model.status === 'trained' ? 'Experimental' : 'Not trained'}</dd><small>${escape(status.model.message)}</small></div><div class="stat"><dt>AI Analyst</dt><dd class="word">${status.ai.available ? 'Configured' : 'Unavailable'}</dd><small>Secondary to the detection engine</small></div></dl>`;
}

function overview() {
  return `${heading('An evidence-first view.', 'Understand the traffic. Follow the evidence. Keep control of the conclusion.', importLink)}${stats()}
    <div class="layout"><div>${panel('Your investigation starts with data', `<div class="intro"><div class="evidence-symbol" aria-hidden="true"><span></span><span></span><span></span><span></span><span></span><span></span></div><h2>${status.datasets ? 'Continue with your supplied traffic.' : 'Bring your network data into focus.'}</h2><p>Import your files, inspect their actual fields, and confirm how records should be interpreted. Every finding keeps a path back to its source.</p><a class="button primary" href="#datasets">${status.datasets ? 'Open datasets' : 'Import your first dataset'} <span aria-hidden="true">→</span></a></div>`, badge(status.datasets ? 'Data imported' : 'Awaiting your data'))}
    ${panel('Findings', status.findings ? `<div class="panel-body"><p class="subtle">${count(status.findings)} measured findings are available. Review engine results and AI assessments separately.</p><a class="button section-gap" href="#findings">Review findings →</a></div>` : empty('No traffic has been analysed', 'Findings will appear here only after your data produces measured evidence.'))}</div>
    <div>${panel('From traffic to evidence', `<ol class="pipeline"><li><span class="step">1</span><div><strong>Import & inspect</strong><small>Discover actual columns, types, and missing values.</small></div></li><li><span class="step">2</span><div><strong>Confirm the dataset</strong><small>Map fields and explicitly confirm labels.</small></div></li><li><span class="step">3</span><div><strong>Measure & evaluate</strong><small>Local metadata scoring and measured connection behaviour.</small></div></li><li><span class="step">4</span><div><strong>Investigate the evidence</strong><small>Optional AI triage follows the engine result.</small></div></li></ol>`)}
    <div class="callout neutral"><strong>Network data stays local by default.</strong><br>AI is disabled until configured. Raw files and packet contents are never included in analyst requests.</div><p class="subtle">${escape(status.ai.message)}</p></div></div>`;
}

function pagination(page, offset, total) {
  return `<div class="pagination"><a class="button" href="#${page}/${Math.max(0, offset-status.page_size)}${location.hash.includes('?') ? '?' + escape(location.hash.split('?')[1]) : ''}" ${offset === 0 ? 'hidden' : ''}>Previous</a><span>${total ? `${offset + 1}–${Math.min(offset + status.page_size, total)} of ${count(total)}` : 'No records'}</span>${offset + status.page_size < total ? `<a class="button" href="#${page}/${offset + status.page_size}${location.hash.includes('?') ? '?' + escape(location.hash.split('?')[1]) : ''}">Next</a>` : ''}</div>`;
}

async function datasets(offset) {
  const data = await api(`/datasets?offset=${offset}`);
  const formats = Object.keys(status.formats).join(', ');
  const table = data.items.length ? `<div class="table-wrap"><table><thead><tr><th>Source file</th><th>Format</th><th>Records</th><th>Status</th><th></th></tr></thead><tbody>${data.items.map(item => `<tr><td class="file-name">${escape(item.filename)}<small>${escape(new Date(item.created_at).toLocaleString())}</small></td><td class="mono">${escape(item.format)}</td><td>${item.inspection ? count(item.inspection.row_count) : 'Not extracted'}</td><td>${badge(item.status.replaceAll('_',' '), 'amber')}</td><td><a href="#dataset/${item.id}">Inspect →</a></td></tr>`).join('')}</tbody></table></div>${pagination('datasets',offset,data.total)}` : empty('No datasets imported', 'Choose a real dataset to inspect its schema. Nothing is generated or substituted.');
  return `${heading('Datasets', 'Inspect what your files actually contain before choosing features or labels.')}
    ${panel('Import network data', `<div class="panel-body"><form id="import-form" class="import-zone"><h3>Select a file from your device</h3><p>Supported: ${escape(formats)} · Request limit ${count(status.max_upload_bytes)} bytes</p><input type="file" id="dataset-file" name="file" accept="${escape(formats)}" required aria-label="Choose a dataset"><div class="row"><button class="button primary" type="submit">Import & inspect</button></div><p class="progress-note">TCP/UDP flows and visible DNS/QUIC metadata are extracted and analysed automatically. Tabular records require confirmed field meanings.</p></form></div>`,badge('Local import','teal'))}${panel('Imported files',table,badge(`${data.total} files`))}`;
}

async function datasetDetail(id) {
  const [data, confirmations] = await Promise.all([api(`/datasets/${encodeURIComponent(id)}`),api(`/datasets/${encodeURIComponent(id)}/confirmations`)]);
  let body = `<a class="back" href="#datasets">← All datasets</a>${heading(data.filename, data.message)}<div class="callout neutral">Source SHA-256: <code>${escape(data.sha256)}</code></div>`;
  if (!data.inspection) return body + panel('Flow extraction required',empty('Capture stored; no flows extracted', 'Supply the capture for inspection so packet decoding and flow extraction can be adapted to its actual contents. No detections or labels have been inferred.'));
  const profile = data.inspection;
  if (confirmations.length) {
    body += panel('Saved interpretations', `<div class="panel-body">${confirmations.map(item => `<details><summary>Confirmed ${escape(new Date(item.created_at).toLocaleString())}</summary><pre>${json(item)}</pre><button class="button" data-analyse="${escape(item.id)}">Analyse traffic</button></details>`).join('')}</div>`);
  }
  body += panel('Actual schema',`<div class="table-wrap"><table><thead><tr><th>Column</th><th>Inferred type</th><th>Missing</th><th>Range / values</th><th>Distinct</th></tr></thead><tbody>${profile.columns.map(column => `<tr><td class="mono">${escape(column.name)}${column.possible_label ? `<small>Possible label · confirm below</small>` : ''}</td><td>${escape(column.inferred_type)}<small>${escape(column.storage_type)}</small></td><td>${column.null_percentage.toFixed(2)}%<small>${count(column.null_count)} records</small></td><td>${column.inferred_type === 'numeric' ? `${escape(column.minimum)} → ${escape(column.maximum)}` : `<details><summary>Inspect observed values</summary>${column.values.map(value => `<div>${escape(value.value)} <small>${count(value.count)} records</small></div>`).join('')}${column.values_truncated ? '<small>Preview truncated; confirm all label values from the source.</small>' : ''}</details>`}</td><td>${count(column.unique_count)}</td></tr>`).join('')}</tbody></table></div>`,badge(`${count(profile.row_count)} records`));
  const options = profile.columns.map(column => `<option value="${escape(column.name)}">${escape(column.name)}</option>`).join('');
  body += panel('Confirm interpretation', `<div class="panel-body"><p class="subtle">Map only fields whose meaning you have verified. Names must use letters, numbers, and underscores, and cannot start with a number. Leave a field blank to exclude it.</p><form id="mapping-form" data-id="${escape(id)}"><div class="table-wrap section-gap"><table><thead><tr><th>Source column</th><th>Canonical field name</th></tr></thead><tbody>${profile.columns.map((column,index) => `<tr><td><label for="field-${index}" class="mono">${escape(column.name)}</label></td><td><input id="field-${index}" data-source="${escape(column.name)}" aria-label="Canonical name for ${escape(column.name)}" autocomplete="off"></td></tr>`).join('')}</tbody></table></div><div class="form-grid section-gap"><div class="field"><label for="label-column">Label column</label><select id="label-column"><option value="">No confirmed label</option>${options}</select></div><div class="field"><label for="assumptions">Dataset assumptions</label><textarea id="assumptions" placeholder="Document how records were collected and what each row represents."></textarea></div><div class="field"><label for="positive-labels">Positive labels · one exact value per line</label><textarea id="positive-labels"></textarea></div><div class="field"><label for="negative-labels">Benign labels · one exact value per line</label><textarea id="negative-labels"></textarea></div></div><label class="check"><input id="flows-confirmed" type="checkbox">I verified that each row represents an extracted network flow.</label><button class="button primary" type="submit">Save confirmed mapping</button></form><div id="confirmation-result" class="section-gap"></div></div>`);
  return body;
}

async function findings(offset) {
  const filters = new URLSearchParams(location.hash.split('?')[1] || '');
  filters.set('offset', offset);
  const data = await api(`/findings?${filters}`);
  const filterForm = `<form id="finding-filters" class="panel-body form-grid">${[['source','Source IP'],['destination','Destination IP'],['protocol','Protocol']].map(([key, label]) => `<div class="field"><label for="filter-${key}">${label}</label><input id="filter-${key}" name="${key}" value="${escape(filters.get(key) || '')}"></div>`).join('')}<div class="field"><label for="filter-severity">Risk level</label><select id="filter-severity" name="severity"><option value="">All levels</option>${status.risk_levels.map(level => `<option ${filters.get('severity') === level ? 'selected' : ''}>${escape(level)}</option>`).join('')}</select></div><button class="button" type="submit">Filter findings</button></form>`;
  const body = data.items.length ? `<div class="table-wrap"><table><thead><tr><th>Connection</th><th>ML score</th><th>Engine risk</th><th>Triggered rules</th><th>Evidence</th><th></th></tr></thead><tbody>${data.items.map(item => `<tr><td class="mono">${escape(item.features.src_ip || item.flow_id)} → ${escape(item.features.dst_ip || 'unknown')}<small>${escape(item.features.protocol)} · port ${escape(item.features.dst_port)}</small></td><td>${item.ml_score == null ? 'Unavailable' : `${(item.ml_score * 100).toFixed(1)}%`}<small>${escape(item.prediction || 'Unscored')}</small></td><td>${badge(item.risk.score === null ? 'Incomplete' : `${item.risk.level} · ${item.risk.score.toFixed(1)}`,'amber')}</td><td>${escape(item.triggered_rules.join(', ') || 'No rule triggered')}</td><td>${item.evidence.length} items</td><td><a href="#finding/${item.id}">Review →</a></td></tr>`).join('')}</tbody></table></div>${pagination('findings',offset,data.total)}` : empty('No measured findings yet', 'Import your data, confirm the flow mapping, and configure evidence-based rules to begin.', importLink);
  return `${heading('Findings', 'Engine results and analyst recommendations, with evidence kept in view.')}${panel('Filter connections',filterForm)}<p class="subtle">Ordered by complete risk, then uncalibrated ML score. An incomplete risk is not a benign verdict.</p>${panel('Investigation queue',body,badge(`${count(data.total)} findings`))}`;
}

async function findingDetail(id) {
  const finding = await api(`/findings/${encodeURIComponent(id)}`);
  const metric = value => value === null ? 'Unavailable' : Number(value).toFixed(2);
  return `<a class="back" href="#findings">← All findings</a>${heading('Review the evidence',`Source record ${finding.flow_id}`,`<div class="row"><button class="button" data-export="${escape(id)}">Export evidence</button><button class="button" data-siem="${escape(id)}" ${status.integrations.siem_enabled ? '' : 'disabled'}>Send to SIEM</button></div>`)}<div class="details"><section class="panel"><div class="panel-heading"><h2>Detection engine</h2>${badge('Experimental')}</div><div class="panel-body"><div class="engine-risk"><span class="eyebrow">FINAL RISK</span><strong>${finding.risk.score === null ? 'Unavailable · incomplete engine' : `${metric(finding.risk.score)} / ${finding.configuration.risk.risk.scale}`}</strong></div><dl class="engine-metrics"><div><dt>ML score · uncalibrated</dt><dd>${metric(finding.ml_score)}</dd></div><div><dt>Behaviour score</dt><dd>${metric(finding.scores.behaviour)}</dd></div><div><dt>Context score</dt><dd>${metric(finding.scores.context)}</dd></div><div><dt>Model version</dt><dd>${escape(finding.model_version || 'Not trained')}</dd></div></dl><p class="subtle section-gap">${escape(finding.limitations.join(' '))}</p></div></section><section class="panel ai-panel"><div class="panel-heading"><h2>AI Analyst</h2>${badge('Secondary assessment','teal')}</div><div class="panel-body"><p class="subtle">Send a minimal evidence package for cited triage and defensive investigation steps.</p><button class="button primary section-gap" data-investigate="${escape(id)}" ${status.ai.available ? '' : 'disabled'}>Investigate with AI</button><p class="progress-note">${escape(status.ai.message)}</p><div id="ai-result" class="section-gap"></div></div></section><div class="wide">${panel('Measured evidence',finding.evidence.map(item => `<article class="evidence"><code>${escape(item.id)}</code><h3>${escape(item.type)}</h3><pre>${json(item.data)}</pre></article>`),badge(`${finding.evidence.length} evidence items`))}${panel('Audit trail',`<div class="panel-body"><details><summary>Source, extracted fields, rule configuration, and scoring policy</summary><pre>${json(finding)}</pre></details></div>`)}</div></div>`;
}

function models() {
  const model = status.model;
  const metric = value => value === null ? 'Not measurable' : `${(value * 100).toFixed(1)}%`;
  const results = model.metrics ? `<div class="table-wrap"><table><thead><tr><th>Held-out group</th><th>C2 / normal</th><th>C2 recall</th><th>False positive rate</th><th>TP / FN / FP / TN</th></tr></thead><tbody>${Object.entries(model.metrics).map(([group, result]) => `<tr><td>${escape(group)}</td><td>${result.c2} / ${result.normal}</td><td>${metric(result.recall)}</td><td>${metric(result.false_positive_rate)}</td><td>${['tp','fn','fp','tn'].map(key => result.confusion_matrix[key]).join(' / ')}</td></tr>`).join('')}</tbody></table></div>` : empty('No model trained', model.message);
  return `${heading('Model & evaluation', 'A local Random Forest scores TCP metadata without an LLM call.', '<button class="button primary" id="train-model">Train from curated labels</button>')}
    <div class="callout"><strong>Experimental model scores.</strong> These are not calibrated probabilities. Positive-only captures cannot establish precision or false-positive rate. Related connections are not independent experiments.</div>
    ${model.status === 'trained' ? `<p class="section-gap">Trained on ${count(model.training_records)} streams, including ${count(model.training_c2)} C2 streams. Fixed decision threshold: ${model.threshold}.</p>` : ''}
    ${panel('Measured held-out results', results)}
    ${model.limitations ? panel('Coverage and limits', `<div class="panel-body"><ul>${model.limitations.map(value => `<li>${escape(value)}</li>`).join('')}</ul></div>`) : ''}
    ${model.feature_importance ? panel('Global feature importance', `<div class="panel-body"><p>Forest impurity importance describes the training model; it is not a causal explanation of an individual alert.</p><pre>${json(model.feature_importance)}</pre></div>`) : ''}
    ${panel('Training audit', `<div class="panel-body"><details><summary>Model version, source digest and evaluation record</summary><pre>${json(model)}</pre></details></div>`)}`;
}

async function configuration() {
  const config = await api('/config');
  return `${heading('Configuration', 'Review the active policy. Change configuration files without editing application source.')}
    <div class="callout neutral">Configuration is read for each request. The listening host and port require a restart. Store API keys in your local .env file; keys are never displayed here.</div>
    <div class="callout">Risk weights and levels are example policy values, not calibrated results. Exploratory behaviour rules and hosting context are enabled. Provider lookups, risk fusion, live capture, SIEM forwarding and AI follow their individual configuration settings.</div>
    ${Object.entries(config).map(([name, value]) => `<details class="panel config-section"><summary>config/${escape(name)}.yaml</summary><pre>${json(value)}</pre></details>`).join('')}`;
}

function connections() {
  const info = status.integrations;
  const capture = info.live_capture;
  return `${heading('Connections', 'Manage network capture, hosting context and external evidence.')}
    ${panel('Access', `<div class="panel-body"><p>Signed in as ${escape(identity.name)} · ${escape(identity.role)}. ${info.auth_enabled ? 'Access tokens stay in this tab memory.' : 'Local access mode; enable authentication before network deployment.'}</p><button class="button section-gap" id="sign-out">Sign out</button></div>`)}
    ${panel('Hosting and threat intelligence', `<div class="panel-body"><p>Hosting ranges: ${info.hosting_enabled ? 'enabled' : 'disabled'}. Threat intelligence: ${info.intel_enabled ? 'enabled' : 'disabled'}. IP lookups require provider keys configured on the server.</p><p class="progress-note">Refreshing downloads published Cloudflare and AWS ranges. Reanalyse a dataset to apply current context. Ownership does not establish maliciousness.</p><button class="button section-gap" id="refresh-context" ${info.hosting_enabled ? '' : 'disabled'}>Refresh hosting ranges</button></div>`)}
    ${panel('Capture network traffic', `<form id="capture-form" class="panel-body"><p>${capture.enabled ? 'Capture is bounded by the configured time, packet and file limits.' : 'Enable live capture and configure permitted interfaces on the server first.'}</p><div class="form-grid section-gap"><div class="field"><label for="capture-interface">Interface</label><select id="capture-interface" required>${capture.interfaces.map(value => `<option>${escape(value)}</option>`).join('')}</select></div><div class="field"><label for="capture-seconds">Duration in seconds</label><input id="capture-seconds" type="number" min="1" max="${capture.max_seconds}" value="${capture.max_seconds}" required></div></div><button class="button primary" type="submit" ${capture.enabled && capture.interfaces.length ? '' : 'disabled'}>Capture and analyse</button></form>`)}
    ${panel('Endpoint and SIEM evidence', `<div class="panel-body"><p>${count(info.endpoint_events)} endpoint events received. Authenticated sensors can submit ECS or Wazuh Sysmon network events through the supplied importer.</p><p class="progress-note">SIEM forwarding is ${info.siem_enabled ? 'enabled' : 'disabled'}. Review an individual finding before forwarding it. Endpoint process associations are matched by connection and time, and do not establish malware attribution.</p></div>`)}`;
}

function signIn() {
  content.innerHTML = `${heading('Sign in', 'Use an access token issued by your administrator.')}${panel('Workspace access', '<form id="sign-in" class="panel-body"><div class="field"><label for="access-token">Access token</label><input id="access-token" type="password" autocomplete="off" required minlength="32"></div><button class="button primary" type="submit">Sign in</button></form>')}`;
  document.querySelector('#sign-in').addEventListener('submit', event => {
    event.preventDefault();
    action(event.submitter, async () => {
      accessToken = document.querySelector('#access-token').value;
      try { identity = await api('/session'); } catch (error) { accessToken = ''; throw error; }
      notification.hidden = true;
      await render();
    });
  });
}

function showAssessment(result) {
  const target = document.querySelector('#ai-result');
  if (!target) return;
  if (!result.available) { target.textContent = result.message; return; }
  const assessment = result.assessment;
  const claims = items => `<ul class="claims">${items.map(item => `<li>${escape(item.interpretation)}<q>${escape(item.quote)}</q><code>${escape(item.evidence_id)}</code></li>`).join('')}</ul>`;
  target.innerHTML = `${badge(assessment.triage.replaceAll('_',' '),'teal')}<p class="progress-note">AI-reported confidence: ${Math.round(assessment.confidence*100)}% · ${result.cached ? 'Previously generated' : 'Generated now'}</p><div class="callout section-gap">${escape(result.notice)}</div><h3>Executive summary</h3>${claims(assessment.summary)}<h3>Supporting evidence</h3>${claims(assessment.supporting_evidence)}<h3>Counter-evidence</h3>${claims(assessment.counter_evidence)}<h3>Risk assessment</h3>${claims(assessment.risk)}<h3>Recommended next steps</h3><ul class="action-list">${assessment.recommended_actions.map(item => `<li>${escape(item)}</li>`).join('')}</ul><p class="subtle">Limitations: ${escape(assessment.limitations.join(', ').replaceAll('_',' '))}</p><details class="section-gap"><summary>AI audit record</summary><pre>${json(result)}</pre></details>`;
}

function bindActions() {
  if (identity.role !== 'admin') {
    content.querySelectorAll('#train-model, #refresh-context, #capture-form button').forEach(button => { button.disabled = true; });
  }
  if (!['admin', 'analyst'].includes(identity.role)) {
    content.querySelectorAll('#import-form button, #mapping-form button, [data-analyse], [data-investigate], [data-siem]').forEach(button => { button.disabled = true; });
  }
  document.querySelector('#sign-out')?.addEventListener('click', () => { accessToken = ''; identity = null; signIn(); });
  document.querySelector('#refresh-context')?.addEventListener('click', event => action(event.target, async () => {
    const result = await api('/context/refresh', {method:'POST'});
    notify(`Refreshed ${count(result.ranges)} hosting ranges. Reanalyse traffic to apply them.`);
  }));
  document.querySelector('#capture-form')?.addEventListener('submit', event => {
    event.preventDefault();
    action(event.submitter, async () => {
      notify('Capturing traffic on the selected interface…');
      const result = await api('/capture', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({interface:document.querySelector('#capture-interface').value, seconds:Number(document.querySelector('#capture-seconds').value)})});
      notify(`Capture complete: ${count(result.analysis.processed_records)} flows processed.`);
      location.hash = 'findings';
    });
  });
  document.querySelector('[data-siem]')?.addEventListener('click', event => action(event.target, async () => {
    const result = await api('/siem/send', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({finding_ids:[event.target.dataset.siem]})});
    notify(result.message);
  }));
  document.querySelector('#train-model')?.addEventListener('click', event => action(event.target, async () => {
    notify('Training locally and evaluating held-out groups…');
    await api('/train', {method:'POST'});
    await render();
    notify('Training completed. Review measured results and limitations.');
  }));
  document.querySelector('#finding-filters')?.addEventListener('submit', event => {
    event.preventDefault();
    location.hash = `findings/0?${new URLSearchParams(new FormData(event.target))}`;
  });
  const findingId = document.querySelector('[data-investigate]')?.dataset.investigate;
  if (findingId) {
    api(`/findings/${findingId}/analysis`).then(result => {
      if (result && document.querySelector('[data-investigate]')?.dataset.investigate === findingId) showAssessment(result);
    }).catch(error => notify(`Saved AI assessment could not be loaded: ${error.message}`,true));
  }
  document.querySelector('#import-form')?.addEventListener('submit', event => {
    event.preventDefault();
    action(event.submitter, async () => {
      const file = document.querySelector('#dataset-file').files[0];
      if (file.size > status.max_upload_bytes) throw new Error('The file exceeds the configured upload limit.');
      const form = new FormData(); form.append('file',file);
      notify('Importing and inspecting your file…');
      const data = await api('/datasets',{method:'POST',body:form});
      if (data.format === 'capture') {
        const mappings = await api(`/datasets/${data.id}/confirmations`);
        if (mappings.length) { await runAnalysis(event.submitter, mappings[0].id); return; }
      }
      notify('Dataset imported. Inspect its actual schema and confirm your mapping.');
      location.hash = `dataset/${data.id}`;
    });
  });
  document.querySelector('#mapping-form')?.addEventListener('submit', event => {
    event.preventDefault();
    action(event.submitter, async () => {
      const mapping = {};
      for (const input of event.target.querySelectorAll('[data-source]')) {
        if (!input.value.trim()) continue;
        const name = input.value.trim();
        if (Object.hasOwn(mapping,name)) throw new Error('Canonical field names must be unique.');
        Object.defineProperty(mapping,name,{value:input.dataset.source,enumerable:true});
      }
      const lines = id => document.querySelector(id).value.split(/\r?\n/).filter(value => value.length > 0);
      const data = await api(`/datasets/${event.target.dataset.id}/confirm`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({field_mapping:mapping,label_column:document.querySelector('#label-column').value || null,positive_labels:lines('#positive-labels'),negative_labels:lines('#negative-labels'),flow_records_confirmed:document.querySelector('#flows-confirmed').checked,assumptions:lines('#assumptions')})});
      document.querySelector('#confirmation-result').innerHTML = `<div class="callout neutral">Mapping saved with an immutable audit reference: <code>${escape(data.id)}</code></div>${data.class_distribution ? `<h3>Confirmed class distribution</h3><pre>${json(data.class_distribution)}</pre>` : '<p class="subtle">No label is confirmed. Supervised training remains unavailable.</p>'}<p class="subtle">Enabled features: ${escape(data.selected_features.join(', ') || 'None configured')}. Disabled missing features: ${escape(data.disabled_features.join(', ') || 'None')}.</p><button class="button section-gap" id="analyse-button">Analyse traffic</button><p class="progress-note">Uses the active local model and configured rules. This does not retrain the model.</p>`;
      document.querySelector('#analyse-button').addEventListener('click', event => runAnalysis(event.target,data.id));
    });
  });
  document.querySelectorAll('[data-analyse]').forEach(button => button.addEventListener('click', () => runAnalysis(button,button.dataset.analyse)));
  document.querySelector('[data-investigate]')?.addEventListener('click', event => action(event.target,async () => {
    notify('Requesting an assessment using the minimum structured evidence…');
    const result = await api(`/findings/${event.target.dataset.investigate}/investigate`,{method:'POST'});
    showAssessment(result);
    notify(result.available ? 'AI assessment ready for human review.' : result.message,!result.available);
  }));
  document.querySelector('[data-export]')?.addEventListener('click', event => action(event.target,async () => {
    const data = await api(`/findings/${event.target.dataset.export}`);
    const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
    const link = document.createElement('a'); link.href=url; link.download=`finding-${data.id}.json`; link.click(); URL.revokeObjectURL(url);
  }));
}

function runAnalysis(button, id) {
  return action(button, async () => {
    notify('Measuring configured behaviour and context…');
    const result = await api(`/confirmations/${id}/analyse`,{method:'POST'});
    notify(`${result.reused ? 'Reopened existing analysis. ' : ''}${count(result.processed_records)} source records processed; ${count(result.measured_findings)} measured findings; ${count(result.unmeasured_records)} records without usable configured evidence. ${result.message}`);
    location.hash = 'findings';
  });
}

async function render() {
  const version = ++renderVersion;
  const [page = 'overview',parameter] = location.hash.slice(1).split('?')[0].split('/');
  const section = page === 'dataset' ? 'datasets' : page === 'finding' ? 'findings' : page;
  document.querySelectorAll('nav a').forEach(link => link.dataset.page === section ? link.setAttribute('aria-current','page') : link.removeAttribute('aria-current'));
  document.querySelector('#breadcrumb').textContent = labels[section] || 'Overview';
  content.innerHTML = '<p class="loading">Loading workspace…</p>';
  try {
    identity = await api('/session');
    status = await api('/status');
    document.querySelector('nav [data-page="settings"]').hidden = identity.role !== 'admin';
    let markup;
    if (page === 'datasets') markup = await datasets(Math.max(0,Number(parameter) || 0));
    else if (page === 'dataset') markup = await datasetDetail(parameter);
    else if (page === 'findings') markup = await findings(Math.max(0,Number(parameter) || 0));
    else if (page === 'finding') markup = await findingDetail(parameter);
    else if (page === 'models') markup = models();
    else if (page === 'integrations') markup = connections();
    else if (page === 'settings') markup = await configuration();
    else markup = overview();
    if (version !== renderVersion) return;
    content.innerHTML = markup;
    bindActions();
    document.title = `${labels[section] || 'Overview'} — Hello Panda`;
  } catch (error) {
    if (version !== renderVersion) return;
    if (error.status === 401) { accessToken = ''; signIn(); return; }
    content.innerHTML = empty('Workspace unavailable',error.message,'<button class="button" id="retry">Try again</button>');
    document.querySelector('#retry').addEventListener('click',render);
  }
}
window.addEventListener('hashchange',render);
render();
