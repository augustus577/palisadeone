// Palisade One — Shared Components
// Nav + Footer injected on every page

function getCurrentPage() {
  const path = window.location.pathname;
  if (path.includes('services')) return 'services';
  if (path.includes('platform')) return 'platform';
  if (path.includes('about')) return 'about';
  if (path.includes('pricing')) return 'pricing';
  if (path.includes('contact')) return 'contact';
  if (path.includes('portal')) return 'portal';
  return 'home';
}

function injectNav() {
  const current = getCurrentPage();
  const links = [
    { href: 'services.html', label: 'Services', id: 'services' },
    { href: 'platform.html', label: 'Platform', id: 'platform' },
    { href: 'about.html', label: 'About', id: 'about' },
    { href: 'pricing.html', label: 'Pricing', id: 'pricing' },
    { href: 'contact.html', label: 'Contact', id: 'contact' },
  ];

  const navHTML = `
  <nav id="main-nav">
    <a href="index.html" class="nav-logo">
      <div class="logo-mark">
        <svg viewBox="0 0 36 36" fill="none">
          <polygon points="18,2 34,10 34,26 18,34 2,26 2,10" stroke="#00FFD1" stroke-width="1.5" fill="rgba(0,255,209,0.05)"/>
          <polygon points="18,8 28,13 28,23 18,28 8,23 8,13" stroke="#00FFD1" stroke-width="1" fill="rgba(0,255,209,0.08)" opacity="0.6"/>
          <circle cx="18" cy="18" r="3" fill="#00FFD1"/>
        </svg>
      </div>
      <span class="logo-text">PALISADE<span>ONE</span></span>
    </a>

    <ul class="nav-links desktop-nav">
      ${links.map(l => `
        <li><a href="${l.href}" class="${current === l.id ? 'nav-active' : ''}">${l.label}</a></li>
      `).join('')}
      <li><a href="portal.html" class="nav-portal">Client Portal</a></li>
      <li><a href="contact.html" class="nav-cta">Book Demo</a></li>
    </ul>

    <button class="hamburger" id="hamburger" aria-label="Menu">
      <span></span><span></span><span></span>
    </button>
  </nav>

  <div class="mobile-menu" id="mobile-menu">
    <ul>
      ${links.map(l => `
        <li><a href="${l.href}" class="${current === l.id ? 'nav-active' : ''}">${l.label}</a></li>
      `).join('')}
      <li><a href="portal.html" class="nav-portal">Client Portal</a></li>
      <li><a href="contact.html" class="mobile-cta">Book a Demo</a></li>
    </ul>
  </div>
  `;

  document.body.insertAdjacentHTML('afterbegin', navHTML);

  // Hamburger toggle
  const hamburger = document.getElementById('hamburger');
  const mobileMenu = document.getElementById('mobile-menu');
  hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('open');
    mobileMenu.classList.toggle('open');
  });

  // Close on link click
  mobileMenu.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => {
      hamburger.classList.remove('open');
      mobileMenu.classList.remove('open');
    });
  });

  // Scroll effect
  window.addEventListener('scroll', () => {
    const nav = document.getElementById('main-nav');
    nav.classList.toggle('scrolled', window.scrollY > 50);
  });
}

function injectFooter() {
  const footerHTML = `
  <footer>
    <div class="footer-inner">
      <div class="footer-brand">
        <div class="footer-logo">PALISADE<span>ONE</span></div>
        <p class="footer-tagline">Enterprise cybersecurity for businesses that can't afford to be breached.</p>
        <div class="footer-social">
          <a href="#" aria-label="LinkedIn">in</a>
          <a href="#" aria-label="Twitter">𝕏</a>
        </div>
      </div>
      <div class="footer-links-group">
        <div class="footer-col">
          <div class="footer-col-title">Services</div>
          <a href="services.html">EDR & Threat Detection</a>
          <a href="services.html">SIEM & Log Management</a>
          <a href="services.html">Zero Trust Security</a>
          <a href="services.html">RMM & Patch Management</a>
          <a href="services.html">Dark Web Monitoring</a>
          <a href="services.html">Cyber Risk Assessment</a>
        </div>
        <div class="footer-col">
          <div class="footer-col-title">Company</div>
          <a href="platform.html">Platform</a>
          <a href="about.html">About</a>
          <a href="pricing.html">Pricing</a>
          <a href="contact.html">Contact</a>
          <a href="portal.html">Client Portal</a>
        </div>
        <div class="footer-col">
          <div class="footer-col-title">Contact</div>
          <a href="mailto:hello@palisadeone.com">hello@palisadeone.com</a>
          <a href="contact.html">Book a Demo</a>
          <span style="color:#4A6080;font-size:12px;">24/7 SOC Monitoring</span>
        </div>
      </div>
    </div>
    <div class="footer-bottom">
      <span>© 2026 Palisade One — All Rights Reserved</span>
      <div class="footer-bottom-links">
        <a href="#">Privacy Policy</a>
        <a href="#">Terms of Service</a>
      </div>
    </div>
  </footer>
  `;
  document.body.insertAdjacentHTML('beforeend', footerHTML);
}

function initCursor() {
  const cursor = document.createElement('div');
  cursor.className = 'cursor';
  cursor.id = 'cursor';
  const ring = document.createElement('div');
  ring.className = 'cursor-ring';
  ring.id = 'cursorRing';
  document.body.appendChild(cursor);
  document.body.appendChild(ring);

  let mouseX = 0, mouseY = 0, ringX = 0, ringY = 0;
  document.addEventListener('mousemove', e => {
    mouseX = e.clientX; mouseY = e.clientY;
    cursor.style.left = mouseX - 4 + 'px';
    cursor.style.top = mouseY - 4 + 'px';
  });
  function animateRing() {
    ringX += (mouseX - ringX - 16) * 0.12;
    ringY += (mouseY - ringY - 16) * 0.12;
    ring.style.left = ringX + 'px';
    ring.style.top = ringY + 'px';
    requestAnimationFrame(animateRing);
  }
  animateRing();
  document.querySelectorAll('a, button').forEach(el => {
    el.addEventListener('mouseenter', () => { cursor.style.transform = 'scale(2.5)'; ring.style.transform = 'scale(1.5)'; ring.style.opacity = '0.8'; });
    el.addEventListener('mouseleave', () => { cursor.style.transform = 'scale(1)'; ring.style.transform = 'scale(1)'; ring.style.opacity = '0.5'; });
  });
}

function initScrollAnimations() {
  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.classList.add('visible');
        const siblings = e.target.parentElement.querySelectorAll('.fade-up');
        siblings.forEach((s, i) => setTimeout(() => s.classList.add('visible'), i * 80));
      }
    });
  }, { threshold: 0.1 });
  document.querySelectorAll('.fade-up').forEach(el => observer.observe(el));
}

function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(a.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    });
  });
}

// Shared CSS injected into every page
function injectSharedStyles() {
  const style = document.createElement('style');
  style.textContent = `
    @import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Outfit:wght@300;400;500;600&family=JetBrains+Mono:wght@300;400&display=swap');

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --black: #03050A; --deep: #070C14; --surface: #0B1220;
      --border: #112240; --accent: #00FFD1; --accent2: #0084FF;
      --danger: #FF3B5C; --text: #C8D8F0; --muted: #4A6080; --white: #F0F6FF;
    }
    html { scroll-behavior: smooth; }
    body { background: var(--black); color: var(--text); font-family: 'Outfit', sans-serif; font-weight: 300; overflow-x: hidden; cursor: none; }
    ::-webkit-scrollbar { width: 3px; }
    ::-webkit-scrollbar-track { background: var(--black); }
    ::-webkit-scrollbar-thumb { background: var(--accent); }

    /* CURSOR */
    .cursor { width:8px;height:8px;background:var(--accent);border-radius:50%;position:fixed;pointer-events:none;z-index:99999;transition:transform 0.1s ease;mix-blend-mode:screen; }
    .cursor-ring { width:32px;height:32px;border:1px solid var(--accent);border-radius:50%;position:fixed;pointer-events:none;z-index:99998;transition:all 0.15s ease;opacity:0.5; }

    /* NAV */
    #main-nav { position:fixed;top:0;left:0;right:0;z-index:1000;padding:20px 60px;display:flex;align-items:center;justify-content:space-between;background:linear-gradient(to bottom,rgba(3,5,10,0.95) 0%,transparent 100%);backdrop-filter:blur(10px);border-bottom:1px solid rgba(17,34,64,0.5);transition:all 0.3s; }
    #main-nav.scrolled { background:rgba(3,5,10,0.98);border-bottom-color:rgba(17,34,64,0.8); }
    .nav-logo { display:flex;align-items:center;gap:12px;text-decoration:none; }
    .logo-mark { width:36px;height:36px; }
    .logo-mark svg { width:100%;height:100%; }
    .logo-text { font-family:'Bebas Neue',sans-serif;font-size:22px;letter-spacing:3px;color:var(--white); }
    .logo-text span { color:var(--accent); }
    .desktop-nav { display:flex;align-items:center;gap:32px;list-style:none; }
    .desktop-nav a { color:var(--muted);text-decoration:none;font-size:12px;letter-spacing:2px;text-transform:uppercase;transition:color 0.2s;font-weight:500; }
    .desktop-nav a:hover, .desktop-nav a.nav-active { color:var(--accent); }
    .nav-portal { border:1px solid var(--border);padding:6px 14px;color:var(--text) !important;transition:all 0.2s !important; }
    .nav-portal:hover { border-color:var(--accent) !important;color:var(--accent) !important; }
    .nav-cta { background:transparent;border:1px solid var(--accent);color:var(--accent) !important;padding:8px 20px;transition:all 0.2s !important; }
    .nav-cta:hover { background:var(--accent) !important;color:var(--black) !important; }

    /* HAMBURGER */
    .hamburger { display:none;flex-direction:column;gap:5px;background:none;border:none;cursor:none;padding:4px; }
    .hamburger span { display:block;width:24px;height:2px;background:var(--text);transition:all 0.3s ease; }
    .hamburger.open span:nth-child(1) { transform:translateY(7px) rotate(45deg); }
    .hamburger.open span:nth-child(2) { opacity:0; }
    .hamburger.open span:nth-child(3) { transform:translateY(-7px) rotate(-45deg); }

    /* MOBILE MENU */
    .mobile-menu { position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(3,5,10,0.98);backdrop-filter:blur(20px);z-index:999;display:flex;align-items:center;justify-content:center;transform:translateX(100%);transition:transform 0.4s cubic-bezier(0.77,0,0.175,1); }
    .mobile-menu.open { transform:translateX(0); }
    .mobile-menu ul { list-style:none;display:flex;flex-direction:column;gap:32px;text-align:center; }
    .mobile-menu a { font-family:'Bebas Neue',sans-serif;font-size:36px;letter-spacing:4px;color:var(--text);text-decoration:none;transition:color 0.2s; }
    .mobile-menu a:hover, .mobile-menu a.nav-active { color:var(--accent); }
    .mobile-menu .mobile-cta { display:inline-block;margin-top:8px;background:var(--accent);color:var(--black) !important;padding:14px 40px;font-size:20px; }

    /* FOOTER */
    footer { background:var(--deep);border-top:1px solid var(--border);padding:64px 60px 32px; }
    .footer-inner { display:grid;grid-template-columns:1fr 2fr;gap:64px;margin-bottom:48px; }
    .footer-logo { font-family:'Bebas Neue',sans-serif;font-size:24px;letter-spacing:3px;color:var(--white);margin-bottom:12px; }
    .footer-logo span { color:var(--accent); }
    .footer-tagline { font-size:13px;color:var(--muted);line-height:1.7;max-width:260px;margin-bottom:20px; }
    .footer-social { display:flex;gap:12px; }
    .footer-social a { width:32px;height:32px;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;color:var(--muted);text-decoration:none;font-size:13px;font-weight:600;transition:all 0.2s; }
    .footer-social a:hover { border-color:var(--accent);color:var(--accent); }
    .footer-links-group { display:grid;grid-template-columns:repeat(3,1fr);gap:32px; }
    .footer-col { display:flex;flex-direction:column;gap:10px; }
    .footer-col-title { font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:3px;color:var(--accent);text-transform:uppercase;margin-bottom:8px; }
    .footer-col a { font-size:13px;color:var(--muted);text-decoration:none;transition:color 0.2s; }
    .footer-col a:hover { color:var(--text); }
    .footer-bottom { border-top:1px solid var(--border);padding-top:24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px; }
    .footer-bottom span { font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted);letter-spacing:1px; }
    .footer-bottom-links { display:flex;gap:24px; }
    .footer-bottom-links a { font-size:11px;color:var(--muted);text-decoration:none;transition:color 0.2s; }
    .footer-bottom-links a:hover { color:var(--accent); }

    /* SHARED SECTION STYLES */
    section { padding:120px 60px;position:relative; }
    .section-label { font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent);letter-spacing:3px;text-transform:uppercase;margin-bottom:16px;display:flex;align-items:center;gap:12px; }
    .section-label::before { content:'';width:32px;height:1px;background:var(--accent); }
    .section-title { font-family:'Bebas Neue',sans-serif;font-size:clamp(40px,5vw,64px);color:var(--white);letter-spacing:2px;line-height:1;margin-bottom:20px; }
    .section-sub { color:var(--muted);font-size:15px;max-width:520px;line-height:1.7; }
    .page-hero { min-height:50vh;display:flex;align-items:center;padding:160px 60px 80px;position:relative;overflow:hidden; }
    .page-hero-bg { position:absolute;inset:0;background:radial-gradient(ellipse 60% 60% at 50% 50%,rgba(0,132,255,0.06) 0%,transparent 70%); }
    .grid-overlay { position:absolute;inset:0;background-image:linear-gradient(rgba(0,255,209,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,209,0.03) 1px,transparent 1px);background-size:60px 60px;mask-image:radial-gradient(ellipse at center,black 20%,transparent 80%); }

    /* BUTTONS */
    .btn-primary { background:var(--accent);color:var(--black);padding:14px 32px;font-family:'Outfit',sans-serif;font-size:13px;font-weight:600;letter-spacing:2px;text-transform:uppercase;text-decoration:none;border:none;cursor:none;transition:all 0.2s;display:inline-block;clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px)); }
    .btn-primary:hover { background:var(--white);transform:translateY(-2px);box-shadow:0 20px 40px rgba(0,255,209,0.2); }
    .btn-secondary { color:var(--text);padding:14px 32px;font-size:13px;font-weight:500;letter-spacing:2px;text-transform:uppercase;text-decoration:none;border:1px solid var(--border);transition:all 0.2s;display:inline-block;clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px)); }
    .btn-secondary:hover { border-color:var(--accent);color:var(--accent); }

    /* ANIMATIONS */
    .fade-up { opacity:0;transform:translateY(30px);transition:opacity 0.7s ease,transform 0.7s ease; }
    .fade-up.visible { opacity:1;transform:translateY(0); }
    @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(0.8)} }

    /* FORM STYLES */
    .form-group { display:flex;flex-direction:column;gap:8px; }
    .form-label { font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase; }
    .form-input, .form-select, .form-textarea { background:var(--surface);border:1px solid var(--border);color:var(--text);padding:12px 16px;font-family:'Outfit',sans-serif;font-size:13px;outline:none;transition:border-color 0.2s;appearance:none;width:100%; }
    .form-input:focus, .form-select:focus, .form-textarea:focus { border-color:var(--accent); }
    .form-textarea { resize:vertical;min-height:120px; }
    .form-submit { background:var(--accent);color:var(--black);border:none;padding:16px 32px;font-family:'Outfit',sans-serif;font-size:13px;font-weight:700;letter-spacing:2px;text-transform:uppercase;cursor:none;transition:all 0.2s;clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px));width:100%; }
    .form-submit:hover { background:var(--white);transform:translateY(-2px); }

    /* RESPONSIVE */
    @media (max-width:768px) {
      #main-nav { padding:16px 24px; }
      .desktop-nav { display:none; }
      .hamburger { display:flex; }
      section { padding:80px 24px; }
      .page-hero { padding:120px 24px 60px; }
      footer { padding:48px 24px 24px; }
      .footer-inner { grid-template-columns:1fr; gap:40px; }
      .footer-links-group { grid-template-columns:1fr 1fr; }
      .footer-bottom { flex-direction:column;text-align:center; }
      body { cursor:auto; }
      .cursor, .cursor-ring { display:none; }
    }
  `;
  document.head.appendChild(style);
}

// Init everything
document.addEventListener('DOMContentLoaded', () => {
  injectSharedStyles();
  injectNav();
  injectFooter();
  initCursor();
  initScrollAnimations();
  initSmoothScroll();
});
