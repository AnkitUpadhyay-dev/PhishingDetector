/**
 * Phishing Detector — client-side UX: fetch analyze, gauge, progress bars, theme toggle.
 */

function getCsrfToken() {
  const el = document.querySelector('[name=csrfmiddlewaretoken]');
  return el ? el.value : '';
}

function threatColor(score) {
  if (score <= 30) return '#22c55e';
  if (score <= 60) return '#eab308';
  if (score <= 85) return '#f97316';
  return '#ff3b3b';
}

function initGauge(score) {
  const fill = document.getElementById('gauge-fill');
  const valueEl = document.getElementById('gauge-percent');
  if (!fill || !valueEl) return;

  const radius = 85;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  fill.style.stroke = threatColor(score);
  fill.style.strokeDasharray = circumference;
  fill.style.strokeDashoffset = circumference;

  requestAnimationFrame(() => {
    fill.style.strokeDashoffset = offset;
  });

  let current = 0;
  const step = () => {
    current += Math.ceil((score - current) / 12) || 1;
    if (current > score) current = score;
    valueEl.textContent = current + '%';
    if (current < score) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function initProgressBars() {
  document.querySelectorAll('.progress-fill[data-score]').forEach((bar) => {
    const score = parseInt(bar.dataset.score, 10) || 0;
    const level = bar.dataset.level || 'medium';
    bar.classList.add(level);
    requestAnimationFrame(() => {
      bar.style.width = score + '%';
    });
  });
}

function initCardAnimations() {
  document.querySelectorAll('.card-soc.animate-in').forEach((card, i) => {
    card.style.animationDelay = (i * 0.06) + 's';
  });
}

function setLoading(loading) {
  const btn = document.getElementById('analyze-btn');
  const label = document.getElementById('analyze-btn-label');
  const spinner = document.getElementById('analyze-spinner');
  if (!btn) return;
  btn.disabled = loading;
  if (label) label.textContent = loading ? 'Analyzing…' : 'Analyze Email';
  if (spinner) spinner.classList.toggle('hidden', !loading);
}

async function submitAnalysis(form) {
  const formData = new FormData(form);
  formData.append('format', 'json');

  setLoading(true);
  try {
    const res = await fetch(form.action, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRFToken': getCsrfToken(),
      },
      body: formData,
    });
    const data = await res.json();
    if (!res.ok) {
      alert(data.error || 'Analysis failed.');
      return;
    }
    window.location.href = '/scan/' + data.scan_id + '/';
  } catch (err) {
    console.error(err);
    form.submit();
  } finally {
    setLoading(false);
  }
}

function initAnalyzeForm() {
  const form = document.getElementById('analyze-form');
  if (!form) return;

  form.addEventListener('submit', (e) => {
    if (form.dataset.ajax === 'true') {
      e.preventDefault();
      submitAnalysis(form);
    }
  });

  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('eml-file');
  const textarea = document.getElementById('raw-email');

  if (dropZone && fileInput) {
    ['dragenter', 'dragover'].forEach((ev) => {
      dropZone.addEventListener(ev, (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
      });
    });
    ['dragleave', 'drop'].forEach((ev) => {
      dropZone.addEventListener(ev, (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
      });
    });
    dropZone.addEventListener('drop', (e) => {
      const file = e.dataTransfer.files[0];
      if (file && file.name.endsWith('.eml')) {
        fileInput.files = e.dataTransfer.files;
        const reader = new FileReader();
        reader.onload = () => {
          if (textarea) textarea.value = reader.result;
        };
        reader.readAsText(file);
      }
    });
    fileInput.addEventListener('change', () => {
      const file = fileInput.files[0];
      if (file && textarea) {
        const reader = new FileReader();
        reader.onload = () => { textarea.value = reader.result; };
        reader.readAsText(file);
      }
    });
  }
}

function initThemeToggle() {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;
  const stored = localStorage.getItem('theme');
  if (stored === 'light') document.body.classList.add('light-mode');

  btn.addEventListener('click', () => {
    document.body.classList.toggle('light-mode');
    localStorage.setItem(
      'theme',
      document.body.classList.contains('light-mode') ? 'light' : 'dark'
    );
  });
}

function copyWhyDangerous() {
  const text = document.getElementById('why-dangerous-text');
  if (!text) return;
  navigator.clipboard.writeText(text.innerText).then(() => {
    const toast = document.getElementById('copy-toast');
    if (toast) {
      toast.classList.remove('hidden');
      setTimeout(() => toast.classList.add('hidden'), 2000);
    }
  });
}

function initCopyButton() {
  const btn = document.getElementById('copy-report-btn');
  if (btn) btn.addEventListener('click', copyWhyDangerous);
}

document.addEventListener('DOMContentLoaded', () => {
  initAnalyzeForm();
  initThemeToggle();
  initCopyButton();

  const scoreEl = document.getElementById('threat-score-data');
  if (scoreEl) {
    initGauge(parseInt(scoreEl.dataset.score, 10) || 0);
    initProgressBars();
    initCardAnimations();
  }
});
