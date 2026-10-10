'use strict';
const $ = id => document.getElementById(id);
const form = $('check-form');
let measurement = null;
let selected = 0;
const number = (value, suffix = '') => value == null ? 'N/A' : value.toFixed(2) + suffix;
const statusClass = status => ({REACHABLE: 'reachable', REPLY: 'reachable', TIMEOUT: 'timeout',
  'ICMP ERROR': 'error', 'LOCAL ERROR': 'local', CANCELLED: 'local'}[status] || 'local');

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function resetResults() {
  measurement = null;
  $('results').replaceChildren();
  $('results-wrap').hidden = true;
  $('results-empty').hidden = false;
  $('checked-at').hidden = true;
  $('download').disabled = true;
  for (const id of ['metric-targets', 'metric-reachable', 'metric-loss', 'metric-elapsed',
    'rtt-min', 'rtt-avg', 'rtt-max']) $(id).textContent = '—';
  $('chart').hidden = true;
  $('chart-empty').hidden = false;
  $('chart-empty').textContent = 'Select a measured target to inspect its response times.';
  $('chart-target').textContent = '';
  $('details').replaceChildren(element('p',
    'Choose a target from the results table to inspect every probe.', 'detail-empty'));
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  const settings = {targets: $('targets').value, count: Number($('count').value),
    timeout: Number($('timeout').value), ttl: Number($('ttl').value)};
  resetResults();
  const controls = [...form.querySelectorAll('input,button')];
  controls.forEach(node => node.disabled = true);
  $('start').textContent = 'Checking…';
  $('notice').className = 'notice busy';
  $('notice').textContent = 'Sending ICMP requests and collecting matching replies or errors…';
  try {
    const response = await fetch('/api/check', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(settings)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'The check could not complete.');
    measurement = data;
    renderResults();
    $('notice').className = 'notice';
    $('notice').textContent = 'Check complete. Select a target to inspect its RTT and each probe.';
  } catch (error) {
    $('notice').className = 'notice error';
    $('notice').textContent = error instanceof TypeError
      ? 'Cannot reach the local server. Make sure the project is running, then try again.' : error.message;
  } finally {
    controls.forEach(node => node.disabled = false);
    $('start').textContent = 'Start check ↗';
  }
});

function renderResults() {
  const summaries = measurement.targets;
  $('results-empty').hidden = true;
  $('results-wrap').hidden = false;
  summaries.forEach((summary, index) => {
    const row = element('tr');
    const address = element('td');
    const button = element('button', summary.target, 'target-button');
    button.type = 'button';
    button.setAttribute('aria-label', 'Inspect ' + summary.target);
    address.append(button);
    const status = element('td');
    status.append(element('span', summary.status, 'status ' + statusClass(summary.status)));
    row.append(address, status, element('td', `${summary.received} / ${summary.sent}`),
      element('td', number(summary.loss, '%')), element('td', number(summary.average, ' ms')));
    row.addEventListener('click', () => selectTarget(index));
    button.addEventListener('click', event => {event.stopPropagation(); selectTarget(index);});
    $('results').append(row);
  });
  const sent = summaries.reduce((total, target) => total + target.sent, 0);
  const received = summaries.reduce((total, target) => total + target.received, 0);
  $('metric-targets').textContent = summaries.length;
  $('metric-reachable').textContent = summaries.filter(target => target.received > 0).length;
  $('metric-loss').textContent = sent ? number((sent - received) / sent * 100, '%') : 'N/A';
  $('metric-elapsed').textContent = number(measurement.elapsed, ' s');
  $('checked-at').textContent = 'Observed ' + new Date(measurement.checked_at).toLocaleString()
    + ` · ${measurement.settings.count} packets / target · TTL ${measurement.settings.ttl}`;
  $('checked-at').hidden = false;
  $('download').disabled = false;
  if (summaries.length) selectTarget(0);
}

function selectTarget(index) {
  selected = index;
  const summary = measurement.targets[index];
  [...$('results').children].forEach((row, i) => row.classList.toggle('selected', i === index));
  $('chart-target').textContent = summary.target;
  $('rtt-min').textContent = number(summary.minimum, ' ms');
  $('rtt-avg').textContent = number(summary.average, ' ms');
  $('rtt-max').textContent = number(summary.maximum, ' ms');
  drawChart(summary);
  $('details').replaceChildren();
  summary.results.forEach((probe, i) => {
    const row = element('div', null, 'probe');
    const description = element('p');
    if (probe.rtt != null) description.append(element('b', number(probe.rtt, ' ms') + ' · '));
    description.append(document.createTextNode(probe.detail));
    row.append(element('span', '#' + (i + 1), 'probe-number'),
      element('span', probe.status, 'status ' + statusClass(probe.status)), description);
    $('details').append(row);
  });
}

function drawChart(summary) {
  const values = summary.results.map(probe => probe.rtt);
  const replies = values.filter(value => value != null);
  $('chart').replaceChildren();
  $('chart').hidden = !replies.length;
  $('chart-empty').hidden = !!replies.length;
  if (!replies.length) {
    $('chart-empty').textContent = 'No Echo Replies for this target. RTT is unavailable.';
    return;
  }
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 640 210');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Measured RTT per probe for ' + summary.target + ', in milliseconds.');
  const add = (tag, attrs, text) => {
    const node = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    if (text != null) node.textContent = text;
    svg.append(node);
    return node;
  };
  const maximum = Math.max(...replies) * 1.2 || 1;
  const x = i => values.length === 1 ? 332 : 48 + i / (values.length - 1) * 570;
  const y = value => 168 - value / maximum * 142;
  for (let i = 0; i <= 4; i++) {
    const value = maximum * i / 4;
    add('line', {x1: 48, x2: 618, y1: y(value), y2: y(value), stroke: '#e8eef0'});
    add('text', {x: 38, y: y(value) + 4, fill: '#82929c',
      'font-size': 10, 'text-anchor': 'end'}, value.toFixed(2));
  }
  add('text', {x: 15, y: 14, fill: '#82929c', 'font-size': 10}, 'ms');
  let segment = [];
  const flush = () => {
    if (segment.length > 1) add('polyline', {points: segment.join(' '),
      fill: 'none', stroke: '#087e83', 'stroke-width': 2.5});
    segment = [];
  };
  values.forEach((value, i) => {
    add('text', {x: x(i), y: 195, fill: '#82929c', 'font-size': 10, 'text-anchor': 'middle'}, '#' + (i + 1));
    if (value == null) {flush(); return;}
    segment.push(`${x(i)},${y(value)}`);
    const point = add('circle', {cx: x(i), cy: y(value), r: 4,
      fill: '#087e83', stroke: '#fff', 'stroke-width': 2});
    const title = document.createElementNS(ns, 'title');
    title.textContent = 'Probe ' + (i + 1) + ': ' + number(value, ' ms');
    point.append(title);
  });
  flush();
  $('chart').append(svg);
}

document.querySelectorAll('[data-preset]').forEach(button => button.addEventListener('click', () => {
  const preset = button.dataset.preset;
  $('targets').value = preset === 'loopback' ? '127.0.0.1' : preset === 'ttl' ? '1.1.1.1' : '192.0.2.1';
  $('ttl').value = preset === 'ttl' ? '1' : '64';
  $('count').value = preset === 'loopback' ? '5' : '2';
  $('timeout').value = preset === 'loopback' ? '2' : '1';
  $('notice').className = 'notice';
  $('notice').textContent = 'Preset selected. Click Start check to run it.';
}));

$('download').addEventListener('click', () => {
  if (!measurement) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(measurement, null, 2)],
    {type: 'application/json'}));
  const link = element('a');
  link.href = url;
  link.download = 'icmp-results-' + measurement.checked_at.slice(0, 10) + '.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
