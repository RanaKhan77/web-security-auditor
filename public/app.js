'use strict';

const SEVERITY = {
    critical: { label: 'Kritis', order: 0 },
    high: { label: 'Tinggi', order: 1 },
    medium: { label: 'Sedang', order: 2 },
    low: { label: 'Rendah', order: 3 },
    info: { label: 'Info', order: 4 },
    ok: { label: 'Aman', order: 5 },
};

const FEATURES = [
    ['Header keamanan', 'CSP, HSTS, X-Frame-Options, dan header lain yang melindungi dari XSS dan clickjacking.'],
    ['Sertifikat & TLS', 'Versi TLS, masa berlaku sertifikat, dan sertifikat self-signed.'],
    ['Flag cookie', 'Apakah cookie memakai Secure, HttpOnly, dan SameSite.'],
    ['File sensitif terekspos', 'File seperti .env, .git, dan backup yang tidak sengaja bisa diakses publik.'],
    ['Kebocoran versi', 'Header dan tag yang membocorkan versi server atau CMS.'],
    ['Konfigurasi CORS', 'Apakah server menerima permintaan lintas domain secara berbahaya.'],
];

const $ = id => document.getElementById(id);

document.addEventListener('DOMContentLoaded', () => {
    renderFeatures();
    $('scan-form').addEventListener('submit', onSubmit);
});

function renderFeatures() {
    const grid = $('feature-grid');
    FEATURES.forEach(([title, desc]) => {
        const card = document.createElement('article');
        card.className = 'feature card';
        const h = document.createElement('h3');
        h.textContent = title;
        const p = document.createElement('p');
        p.textContent = desc;
        card.append(h, p);
        grid.appendChild(card);
    });
}

async function onSubmit(e) {
    e.preventDefault();
    const url = $('url').value.trim();
    if (!url) return showToast('Masukkan alamat situs', true);
    if (!$('consent').checked) return showToast('Centang dulu pernyataan izinnya', true);

    const btn = $('scan-btn');
    btn.disabled = true;
    btn.textContent = 'Memeriksa...';
    renderLoading(url);

    try {
        const res = await fetch('api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, consent: true }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Gagal memindai');
        renderReport(data);
    } catch (err) {
        renderError(err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Periksa';
    }
}

function renderLoading(url) {
    const area = $('result-area');
    area.hidden = false;
    area.innerHTML = `<div class="card loading-card">
        <div class="spinner" aria-hidden="true"></div>
        <p>Memeriksa <strong>${escape(url)}</strong>...</p>
        <span class="muted">Mengirim beberapa request dan membaca responsnya.</span>
    </div>`;
    area.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderError(message) {
    const area = $('result-area');
    area.hidden = false;
    area.innerHTML = `<div class="card error-card">
        <strong>Tidak bisa memeriksa situs ini</strong>
        <p>${escape(message)}</p>
    </div>`;
}

function renderReport(report) {
    const area = $('result-area');
    const g = report.grade;
    const findings = [...report.findings].sort(
        (a, b) => SEVERITY[a.severity].order - SEVERITY[b.severity].order
    );
    const issues = findings.filter(f => f.severity !== 'ok');
    const passed = findings.filter(f => f.severity === 'ok');
    const s = report.summary;

    const chips = ['critical', 'high', 'medium', 'low']
        .filter(k => s[k] > 0)
        .map(k => `<span class="count-chip sev-${k}">${s[k]} ${SEVERITY[k].label}</span>`)
        .join('');

    area.hidden = false;
    area.innerHTML = `
      <div class="report" id="report">
        <div class="report-head card grade-${g.letter}">
          <div class="grade-badge">
            <span class="grade-letter">${g.letter}</span>
            <span class="grade-score">${g.score}/100</span>
          </div>
          <div class="report-meta">
            <h2>${escape(report.target.host)}</h2>
            <p class="muted">${escape(report.target.final_url)} &middot; ${escape(report.target.ip)}</p>
            <p class="grade-label">${escape(g.label)}</p>
            <div class="count-chips">${chips || '<span class="count-chip sev-ok">Tidak ada masalah</span>'}</div>
          </div>
          <button class="btn btn-ghost btn-sm print-btn" onclick="window.print()">Unduh PDF</button>
        </div>

        ${issues.length ? `<h3 class="report-section-title">Yang perlu diperbaiki (${issues.length})</h3>` : ''}
        <div class="findings">
          ${issues.map(findingCard).join('')}
        </div>

        ${passed.length ? `
        <details class="passed">
          <summary>Pemeriksaan yang lolos (${passed.length})</summary>
          <ul>${passed.map(f => `<li><span class="dot ok"></span>${escape(f.title)}</li>`).join('')}</ul>
        </details>` : ''}

        <p class="report-foot muted">
          Diperiksa ${new Date(report.scanned_at).toLocaleString('id-ID')} &middot;
          ${report.duration_ms} ms &middot; pemeriksaan pasif oleh SiteAudit
        </p>
      </div>`;
    area.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function findingCard(f) {
    const sev = SEVERITY[f.severity];
    return `<article class="finding sev-${f.severity}">
        <div class="finding-head">
          <span class="sev-tag sev-${f.severity}">${sev.label}</span>
          <h4>${escape(f.title)}</h4>
        </div>
        <p class="finding-detail">${escape(f.detail)}</p>
        ${f.evidence ? `<details class="finding-evidence"><summary>Bukti</summary><pre>${escape(f.evidence)}</pre></details>` : ''}
        ${f.fix ? `<div class="finding-fix"><strong>Perbaikan:</strong> ${escape(f.fix)}</div>` : ''}
      </article>`;
}

function escape(s) {
    return String(s).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

let toastTimer;
function showToast(message, isError) {
    const toast = $('toast');
    toast.textContent = message;
    toast.classList.toggle('is-error', !!isError);
    toast.classList.add('is-visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('is-visible'), 2800);
}
