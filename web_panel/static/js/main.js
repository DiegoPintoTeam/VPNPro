/* main.js — VPNPro Web Panel */

// ── Theme switcher ─────────────────────────────────────
(function () {
  const THEME_KEY = 'vpnpro-theme';
  const RANDOM_DAILY = 'random_daily';
  const THEMES = ['enterprise', 'carbon', 'oceanic', 'crimson', 'obsidian', 'aurora', 'titanium', 'sunset', 'forest', 'midnight', 'ruby', 'arctic', 'copper', 'neon', 'slate'];
  const select = document.getElementById('themeSelect');
  const body = document.body;

  if (!body) return;

  function dailyTheme() {
    const now = new Date();
    const dayKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
    let hash = 0;
    for (let i = 0; i < dayKey.length; i += 1) {
      hash = (hash * 31 + dayKey.charCodeAt(i)) >>> 0;
    }
    return THEMES[hash % THEMES.length];
  }

  function applyTheme(theme) {
    let chosen = theme;
    if (chosen === RANDOM_DAILY) {
      chosen = dailyTheme();
      body.dataset.dailyTheme = chosen;
    } else {
      delete body.dataset.dailyTheme;
    }

    if (!THEMES.includes(chosen)) {
      chosen = 'enterprise';
    }

    body.classList.remove(...THEMES.map(name => `theme-${name}`));
    body.classList.add(`theme-${chosen}`);
    if (select) {
      select.value = theme === RANDOM_DAILY ? RANDOM_DAILY : chosen;
      select.title = theme === RANDOM_DAILY ? `Tema del dia: ${chosen}` : '';
    }
  }

  applyTheme(localStorage.getItem(THEME_KEY) || 'enterprise');

  if (select) {
    select.addEventListener('change', () => {
      const nextTheme = select.value;
      localStorage.setItem(THEME_KEY, nextTheme);
      applyTheme(nextTheme);
    });
  }
})();

// ── Sidebar toggle ──────────────────────────────────────
(function () {
  const toggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const wrapper = document.getElementById('mainWrapper');

  if (!toggle || !sidebar) return;

  function isMobile() {
    return window.innerWidth < 768;
  }

  toggle.addEventListener('click', () => {
    if (isMobile()) {
      sidebar.classList.toggle('open');
    } else {
      const collapsed = sidebar.style.width === '0px';
      if (collapsed) {
        sidebar.style.width = 'var(--sidebar-width)';
        if (wrapper) wrapper.style.marginLeft = 'var(--sidebar-width)';
      } else {
        sidebar.style.width = '0px';
        sidebar.style.overflow = 'hidden';
        if (wrapper) wrapper.style.marginLeft = '0';
      }
    }
  });

  // Close sidebar on outside click (mobile)
  document.addEventListener('click', (e) => {
    if (isMobile() && sidebar.classList.contains('open')) {
      if (!sidebar.contains(e.target) && e.target !== toggle) {
        sidebar.classList.remove('open');
      }
    }
  });
})();


// ── In-page banners (same visual style across views) ───
window.showPanelBanner = function showPanelBanner(message, category = 'success', timeoutMs = 4000) {
  const host = document.querySelector('.page-header') || document.querySelector('.content-area');
  if (!host) return;

  const alertDiv = document.createElement('div');
  alertDiv.className = `alert alert-${category} alert-dismissible fade show mb-3`;
  alertDiv.innerHTML = `${message} <button type="button" class="btn-close" data-bs-dismiss="alert"></button>`;
  host.insertAdjacentElement('afterend', alertDiv);

  if (timeoutMs > 0) {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alertDiv);
      if (bsAlert) {
        bsAlert.close();
      } else {
        alertDiv.remove();
      }
    }, timeoutMs);
  }
};


// ── Confirmation dialogs ────────────────────────────────
window.confirmPanelAction = async function confirmPanelAction({
  title = '¿Confirmar?',
  message = '¿Confirmar esta acción?',
  scope = '',
  confirmText = 'Sí, continuar',
  cancelText = 'Cancelar',
}) {
  const css = getComputedStyle(document.body);
  const escapedMessage = (message || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/\n/g, '<br>');
  const escapedScope = (scope || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
  const html = `${escapedScope ? `<div style="font-weight:700;letter-spacing:.04em;margin-bottom:8px;">${escapedScope}</div>` : ''}<div>${escapedMessage}</div>`;

  const result = await Swal.fire({
    icon: 'warning',
    title,
    html,
    showCancelButton: true,
    confirmButtonColor: '#ef4444',
    cancelButtonColor: '#6b7280',
    confirmButtonText: confirmText,
    cancelButtonText: cancelText,
    background: css.getPropertyValue('--bg-card').trim() || '#111b27',
    color: css.getPropertyValue('--text-primary').trim() || '#e5edf5',
  });

  return result.isConfirmed;
};

document.querySelectorAll('.form-confirm').forEach(form => {
  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    const isConfirmed = await window.confirmPanelAction({
      title: this.dataset.confirmTitle || '¿Confirmar?',
      message: this.dataset.msg || '¿Confirmar esta acción?',
      scope: this.dataset.confirmScope || '',
      confirmText: this.dataset.confirmText || 'Sí, continuar',
      cancelText: this.dataset.cancelText || 'Cancelar',
    });
    if (isConfirmed) this.submit();
  });
});


// ── Auto-dismiss alerts after 5 s ──────────────────────
setTimeout(() => {
  document.querySelectorAll('.alert.alert-dismissible').forEach(el => {
    const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
    if (bsAlert) bsAlert.close();
  });
}, 80);
