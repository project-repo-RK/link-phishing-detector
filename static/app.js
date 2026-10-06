// Keep page elements together so their roles are easy to follow.
const form = document.getElementById('url-form');
const urlInput = document.getElementById('urls');
const statusText = document.getElementById('status');
const analyseButton = document.getElementById('analyse');
const exampleButton = document.getElementById('example');
const clearButton = document.getElementById('clear');
const emptyPanel = document.getElementById('empty');
const resultPanel = document.getElementById('result');

// Reset an old result when the input changes.
function clearResult() {
  emptyPanel.hidden = false;
  resultPanel.hidden = true;
  statusText.textContent = '';
  statusText.className = '';
}
form.addEventListener('input', clearResult);
clearButton.addEventListener('click', () => { form.reset(); clearResult(); });

// Use a reserved public example domain for demonstrating collection.
exampleButton.addEventListener('click', () => {
  urlInput.value = 'https://example.com/';
  clearResult();
});

// Create text elements rather than inserting submitted content as executable HTML.
function element(tag, text, className) {
  const item = document.createElement(tag);
  item.textContent = text;
  if (className) item.className = className;
  return item;
}

function showResult(data) {
  emptyPanel.hidden = true;
  resultPanel.hidden = false;
  const score = document.getElementById('score');
  const description = document.getElementById('result-description');
  const track = document.getElementById('score-track');
  if (data.score === null) {
    score.textContent = 'Unable to assess';
    score.className = 'score unavailable';
    track.hidden = true;
    description.textContent = 'No supported URL was found. Paste a full URL beginning with https://, http://, or www.';
  } else {
    score.textContent = (data.score * 100).toFixed(1) + '%';
    score.className = 'score';
    track.hidden = false;
    document.getElementById('score-bar').style.width = (data.score * 100) + '%';
    description.textContent = data.links.length === 1 ? 'Model score for the submitted URL.' : 'Highest score among ' + data.links.length + ' unique URLs. Each URL is assessed separately.';
  }

  // Show any input parsing notes separately from model predictions.
  const notes = document.getElementById('notes');
  notes.replaceChildren();
  for (const note of data.notes) notes.appendChild(element('li', note));
  document.getElementById('observations').hidden = data.notes.length === 0;

  // Keep extracted links as plain text, with expandable feature values.
  const links = document.getElementById('links');
  links.replaceChildren();
  for (const link of data.links) {
    const card = element('div', '', 'link-result');
    card.appendChild(element('p', (link.score * 100).toFixed(1) + '% URL score', 'link-score'));
    card.appendChild(element('p', link.url));
    if (link.feature_url !== link.url) card.appendChild(element('p', 'Scored destination: ' + link.feature_url));
    card.appendChild(element('p', link.feature_count + ' of 30 features used. Unavailable features were omitted, not guessed.'));
    card.appendChild(element('p', 'Historical dataset accuracy for this feature subset: ' + (link.historical_test_accuracy * 100).toFixed(1) + '%. This is not measured live-URL accuracy.'));
    for (const note of link.notes) card.appendChild(element('p', note, 'collection-note'));
    const details = document.createElement('details');
    details.appendChild(element('summary', 'View ' + link.feature_count + ' features used by the model'));
    const list = element('ul', '', 'feature-list');
    for (const [name, value] of Object.entries(link.features)) {
      list.appendChild(element('li', name + ': ' + value));
    }
    details.appendChild(list);
    card.appendChild(details);
    const missing = document.createElement('details');
    missing.appendChild(element('summary', 'Unavailable features and collection details'));
    const reasons = element('ul', '', 'feature-list');
    for (const [name, reason] of Object.entries(link.unavailable)) reasons.appendChild(element('li', name + ': ' + reason));
    for (const [name, value] of Object.entries(link.observations)) reasons.appendChild(element('li', name + ': ' + String(value)));
    for (const step of link.redirects) reasons.appendChild(element('li', 'HTTP ' + step.status + ': ' + step.url));
    missing.appendChild(reasons);
    card.appendChild(missing);
    links.appendChild(card);
  }
}

// Submit the URLs to the local server and update the right-hand panel.
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearResult();
  for (const button of [analyseButton, exampleButton, clearButton]) button.disabled = true;
  // Prevent edits while waiting so the result always matches the submitted URLs.
  for (const input of form.querySelectorAll('input, textarea')) input.disabled = true;
  statusText.textContent = 'Collecting features and scoring URLs… Allow about 50 seconds per URL.';
  try {
    const response = await fetch('/analyse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        urls: urlInput.value,
        network: document.getElementById('network').checked,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Analysis failed.');
    showResult(data);
    statusText.textContent = 'Analysis complete.';
  } catch (error) {
    statusText.className = 'error';
    statusText.textContent = error.message;
  } finally {
    for (const button of [analyseButton, exampleButton, clearButton]) button.disabled = false;
    for (const input of form.querySelectorAll('input, textarea')) input.disabled = false;
  }
});
