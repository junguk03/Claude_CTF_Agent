const $ = (selector, root = document) => root.querySelector(selector);

document.querySelectorAll('.tabs button').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.tabs button, .panel').forEach((node) => node.classList.remove('active'));
    button.classList.add('active');
    document.getElementById(button.dataset.panel).classList.add('active');
  });
});

function expressionNode(form) {
  const kind = $('.kind', form).value;
  const raw = $('.expression', form).value;
  if (kind === 'field') return {kind, name: raw.trim()};
  if (kind === 'literal') {
    const number = Number(raw);
    return {kind, value: Number.isFinite(number) ? number : raw};
  }
  return {kind, expr: raw};
}

async function post(route, body) {
  const response = await fetch(route, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
    cache: 'no-store',
  });
  const text = await response.text();
  if (!response.ok) throw new Error(text || `HTTP ${response.status}`);
  return {text, contentType: response.headers.get('content-type') || ''};
}

document.querySelectorAll('.formula-form').forEach((form) => {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const output = document.getElementById(form.dataset.output);
    const body = {index: expressionNode(form)};
    const query = $('.audit-query', form);
    if (query) body.query = query.value;
    output.textContent = 'Loading…';
    try {
      const result = await post(form.dataset.route, body);
      output.textContent = result.contentType.includes('json')
        ? JSON.stringify(JSON.parse(result.text), null, 2)
        : result.text;
    } catch (error) {
      output.textContent = `Request failed: ${error.message}`;
    }
  });
});

let reportId = null;
let runId = null;

$('#save-report').addEventListener('click', async () => {
  const output = $('#reports-output');
  output.textContent = 'Saving…';
  const body = {
    name: $('#report-name').value,
    definition: {version: 1, index: {kind: 'formula', expr: $('#report-expression').value}},
  };
  if (reportId) body.report_id = reportId;
  try {
    const result = await post('/api/reports/save', body);
    const value = JSON.parse(result.text);
    reportId = value.report_id;
    $('#report-id').textContent = reportId;
    $('#run-report').disabled = false;
    output.textContent = JSON.stringify(value, null, 2);
  } catch (error) {
    output.textContent = `Save failed: ${error.message}`;
  }
});

$('#run-report').addEventListener('click', async () => {
  const output = $('#reports-output');
  output.textContent = 'Starting report…';
  try {
    const result = await post('/api/reports/run', {report_id: reportId});
    const value = JSON.parse(result.text);
    runId = value.run_id;
    $('#run-id').textContent = runId;
    output.textContent = JSON.stringify(value, null, 2) + '\n\nWaiting for result…';
    pollRun();
  } catch (error) {
    output.textContent = `Run failed: ${error.message}`;
  }
});

async function pollRun() {
  if (!reportId || !runId) return;
  try {
    const response = await fetch(`/api/reports/${reportId}/runs/${runId}`, {cache: 'no-store'});
    const value = await response.json();
    $('#reports-output').textContent = JSON.stringify(value, null, 2);
    if (value.state === 'pending') setTimeout(pollRun, 350);
  } catch (error) {
    $('#reports-output').textContent = `Read failed: ${error.message}`;
  }
}
