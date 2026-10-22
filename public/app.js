'use strict';

const SEVERITY = {
    critical: { label: 'Kritis', code: 'CRIT', order: 0 },
    high: { label: 'Tinggi', code: 'HIGH', order: 1 },
    medium: { label: 'Sedang', code: 'MED', order: 2 },
    low: { label: 'Rendah', code: 'LOW', order: 3 },
    info: { label: 'Info', code: 'INFO', order: 4 },
    ok: { label: 'Aman', code: 'OK', order: 5 },
};

const FEATURES = [
    ['Header keamanan', 'CSP, HSTS, X-Frame-Options, dan header lain pelindung dari XSS dan clickjacking.'],
    ['Analisis CSP', 'Bukan cuma ada atau tidak: unsafe-inline, unsafe-eval, wildcard, dan direktif yang hilang.'],
    ['Sertifikat & TLS', 'Versi TLS, masa berlaku sertifikat, dan sertifikat self-signed.'],
    ['File & direktori', 'File sensitif (.env, .git, backup) dan direktori terbuka, ditemukan dari petunjuk situs sendiri.'],
    ['Rahasia di JavaScript', 'API key dan token yang tanpa sengaja ikut ter-bundle di kode frontend.'],
    ['Metode HTTP', 'Metode berbahaya seperti TRACE (XST) dan metode tulis yang terbuka.'],
    ['Keamanan email (DNS)', 'SPF dan DMARC untuk mencegah orang memalsukan email atas nama domainmu.'],
    ['Cookie, CORS, SRI', 'Flag cookie, CORS berbahaya, resource pihak ketiga tanpa Subresource Integrity, dan mixed content.'],
];

const $ = id => document.getElementById(id);
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// Reveal elements as they scroll into view.
const revealObserver = 'IntersectionObserver' in window
    ? new IntersectionObserver((entries, obs) => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                e.target.classList.add('in');
                obs.unobserve(e.target);
            }
        });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' })
    : null;

function observeReveals(root = document) {
    const els = root.querySelectorAll('.reveal:not(.in)');
    if (!revealObserver) {
        els.forEach(el => el.classList.add('in')); // old browsers: just show them
        return;
    }
    els.forEach(el => revealObserver.observe(el));
}

document.addEventListener('DOMContentLoaded', () => {
    renderFeatures();
    observeReveals();
    $('scan-form').addEventListener('submit', onSubmit);
});

// Count a number up smoothly (respects reduced motion).
function countUp(el, to, suffix = '', ms = 900) {
    if (reduceMotion) { el.textContent = to + suffix; return; }
    const start = performance.now();
    const step = now => {
        const t = Math.min(1, (now - start) / ms);
        const eased = 1 - Math.pow(1 - t, 3);
        el.textContent = Math.round(to * eased) + suffix;
        if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

function renderFeatures() {
    const grid = $('feature-grid');
    FEATURES.forEach(([title, desc], i) => {
        const card = document.createElement('article');
        card.className = 'feature card reveal';
        card.style.setProperty('--i', i);
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
    const active = $('active') && $('active').checked;

    const btn = $('scan-btn');
    btn.disabled = true;
    btn.textContent = 'Memeriksa...';
    renderLoading(url);

    try {
        const res = await fetch('api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, consent: true, active }),
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

    const mode = report.active_mode ? 'pemeriksaan pasif + aktif' : 'pemeriksaan pasif';
    area.hidden = false;
    area.innerHTML = `
      <div class="report" id="report">
        <div class="report-head card grade-${g.letter}">
          <div class="grade-badge">
            <span class="grade-letter">${g.letter}</span>
            <span class="grade-score"><span class="score-n">0</span>/100</span>
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
          ${report.duration_ms} ms &middot; ${mode} oleh SiteAudit
        </p>
      </div>`;

    requestAnimationFrame(() => {
        const n = area.querySelector('.score-n');
        if (n) countUp(n, g.score);
        observeReveals(area);
    });
    area.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function findingCard(f, i) {
    const sev = SEVERITY[f.severity];
    return `<article class="finding rise sev-${f.severity}" style="--i:${i}">
        <div class="finding-row">
          <span class="sev-code">${sev.code}</span>
          <div class="finding-body">
            <h4 class="finding-title">${escape(f.title)}</h4>
            <p class="finding-detail">${escape(f.detail)}</p>
            ${f.evidence ? `<details class="finding-evidence"><summary>$ bukti</summary><pre>${escape(f.evidence)}</pre></details>` : ''}
            ${f.fix ? `<p class="finding-fix"><span class="fix-tag">FIX</span> ${escape(f.fix)}</p>` : ''}
          </div>
        </div>
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
