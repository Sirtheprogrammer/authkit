// AuthKit Interactive Client & Playground Scripts
document.addEventListener('DOMContentLoaded', () => {
  initHealthCheck();
  initCopyButtons();
  initPlayground();
  initCodeTabs();
  initMobileNav();
});

// Live Health & Status Polling
async function initHealthCheck() {
  const dot = document.getElementById('health-dot');
  const text = document.getElementById('health-text');
  if (!dot) return;

  try {
    const res = await fetch('/health');
    const data = await res.json();
    if (res.ok && data.status === 'healthy') {
      dot.style.background = '#ffffff';
      dot.style.boxShadow = '0 0 10px rgba(255,255,255,0.9)';
      if (text) text.innerText = `AuthKit Operational (${data.database_type.toUpperCase()})`;
    } else {
      dot.style.background = '#71717a';
      if (text) text.innerText = 'Degraded';
    }
  } catch (err) {
    if (dot) dot.style.background = '#71717a';
    if (text) text.innerText = 'Offline';
  }
}

// Copy to clipboard helper
function initCopyButtons() {
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const textToCopy = btn.getAttribute('data-copy') || btn.parentElement.querySelector('.cmd-text')?.innerText;
      if (!textToCopy) return;

      const cleanText = textToCopy.replace(/^\$\s*/, '').trim();
      navigator.clipboard.writeText(cleanText).then(() => {
        const origText = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => {
          btn.innerText = origText;
        }, 1800);
      });
    });
  });
}

// Playground State and Interactive API Testing
function initPlayground() {
  const playground = document.getElementById('api-playground');
  if (!playground) return;

  const tabs = document.querySelectorAll('.playground-tab');
  const forms = document.querySelectorAll('.playground-form');
  const responseBox = document.getElementById('playground-response');
  const statusBadge = document.getElementById('response-status');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      forms.forEach(f => f.style.display = 'none');

      tab.classList.add('active');
      const targetId = tab.getAttribute('data-target');
      const targetForm = document.getElementById(targetId);
      if (targetForm) {
        targetForm.style.display = 'block';
      }
    });
  });

  // Handler for Signup Form
  const signupForm = document.getElementById('form-signup');
  if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('signup-email').value;
      const password = document.getElementById('signup-password').value;
      const metaRaw = document.getElementById('signup-metadata').value;

      let metadata = {};
      try {
        if (metaRaw.trim()) metadata = JSON.parse(metaRaw);
      } catch (err) {
        alert('Invalid JSON in metadata field');
        return;
      }

      await executeRequest('/api/v1/auth/signup', 'POST', { email, password, metadata }, responseBox, statusBadge);
    });
  }

  // Handler for Login Form
  const loginForm = document.getElementById('form-login');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value;
      const password = document.getElementById('login-password').value;
      await executeRequest('/api/v1/auth/login', 'POST', { email, password }, responseBox, statusBadge);
    });
  }

  // Handler for Inspect Token Form
  const inspectForm = document.getElementById('form-inspect');
  if (inspectForm) {
    inspectForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = document.getElementById('inspect-token').value;
      const claims = decodeJWTPayload(token);
      if (statusBadge) {
        statusBadge.innerText = claims ? 'Decoded Claims' : 'Invalid JWT Format';
        statusBadge.style.color = '#ffffff';
      }
      if (responseBox) {
        responseBox.innerText = claims ? JSON.stringify(claims, null, 2) : '{"error": "Failed to decode JWT payload format"}';
      }
    });
  }

  // Handler for Me Form
  const meForm = document.getElementById('form-me');
  if (meForm) {
    meForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = document.getElementById('me-token').value;
      await executeRequest('/api/v1/auth/me', 'GET', null, responseBox, statusBadge, token);
    });
  }
}

async function executeRequest(url, method, payload, responseBox, statusBadge, token) {
  if (statusBadge) statusBadge.innerText = 'Executing...';
  if (responseBox) responseBox.innerText = 'Loading response...';

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = 'Bearer ' + token.trim();
    }

    const opts = { method, headers };
    if (payload && method !== 'GET') {
      opts.body = JSON.stringify(payload);
    }

    const res = await fetch(url, opts);
    const data = await res.json();

    if (statusBadge) {
      statusBadge.innerText = `${res.status} ${res.statusText}`;
      statusBadge.style.color = res.ok ? '#ffffff' : '#a1a1aa';
    }

    if (responseBox) {
      responseBox.innerText = JSON.stringify(data, null, 2);
    }

    // Auto-fill tokens into other playground tabs if response contained access_token
    if (data.access_token) {
      const inspectInput = document.getElementById('inspect-token');
      const meInput = document.getElementById('me-token');
      if (inspectInput && !inspectInput.value) inspectInput.value = data.access_token;
      if (meInput && !meInput.value) meInput.value = data.access_token;
    }
  } catch (err) {
    if (statusBadge) statusBadge.innerText = 'Network Error';
    if (responseBox) responseBox.innerText = JSON.stringify({ error: err.message }, null, 2);
  }
}

function decodeJWTPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

// Code Snippet Tabs (cURL, TypeScript, Python, Go)
function initCodeTabs() {
  document.querySelectorAll('.snippet-container').forEach(container => {
    const tabs = container.querySelectorAll('.snippet-tab');
    const blocks = container.querySelectorAll('.snippet-block');

    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        blocks.forEach(b => b.style.display = 'none');

        tab.classList.add('active');
        const lang = tab.getAttribute('data-lang');
        const targetBlock = container.querySelector(`.snippet-block[data-lang="${lang}"]`);
        if (targetBlock) targetBlock.style.display = 'block';
      });
    });
  });
}

// Mobile navigation drawer toggle
function initMobileNav() {
  const toggle = document.getElementById('mobile-toggle');
  const nav = document.getElementById('mobile-nav');
  const hamburger = document.getElementById('hamburger-icon');
  const close = document.getElementById('close-icon');

  if (!toggle || !nav) return;

  const toggleOpen = () => {
    const isOpen = nav.classList.toggle('open');
    if (hamburger) hamburger.style.display = isOpen ? 'none' : 'block';
    if (close) close.style.display = isOpen ? 'block' : 'none';
  };

  toggle.addEventListener('click', toggleOpen);

  nav.querySelectorAll('.mobile-link').forEach(link => {
    link.addEventListener('click', () => {
      nav.classList.remove('open');
      if (hamburger) hamburger.style.display = 'block';
      if (close) close.style.display = 'none';
    });
  });
}
