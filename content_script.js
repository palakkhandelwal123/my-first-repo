// content_script.js
// Runs on Gmail. Extracts sender, subject, body, links and injects a banner with detection.

(function(){
  const CHECK_INTERVAL = 1200; // ms, poll for new opened mail

  // --- Utility helpers ---
  function normalizeText(s) { return (s||"").replace(/\s+/g,' ').trim().toLowerCase(); }
  function extractLinksFromNode(node) {
    const links = [];
    node.querySelectorAll('a[href]').forEach(a=>{
      try {
        const href = a.getAttribute('href');
        if(!href) return;
        // Gmail sometimes uses redirect URLs like https://mail.google.com/mail/u/0/?ui=2&...&url=http...
        // Try to decode real target if present
        const dec = decodeURIComponent(href);
        links.push({href, text: a.innerText || a.getAttribute('aria-label') || '', resolved: tryExtractUrlFromGmailHref(href) || dec});
      } catch(e){}
    });
    return links;
  }
  function tryExtractUrlFromGmailHref(href){
    // common pattern: https://mail.google.com/...&url=https%3A%2F%2Fexample.com%2F...
    try{
      const m = href.match(/url=([^&]+)/);
      if(m) return decodeURIComponent(m[1]);
      return null;
    }catch(e){return null;}
  }
  function getDomain(url){
    try {
      const u = new URL(url);
      return u.hostname.replace(/^www\./,'');
    } catch(e) { return null; }
  }

  // --- Heuristics / indicators ---
  const SUSPICIOUS_KEYWORDS = [
    "verify", "verification", "confirm", "account suspended", "update your account",
    "urgent", "immediately", "click here", "password", "reset", "billing", "payment failed",
    "limited time", "security alert", "unauthorized", "login to your account", "identity"
  ];
  const HIGH_RISK_DOMAINS = [
    // example list - can be expanded in options
    "bit.ly","tinyurl.com","ow.ly","goo.gl"
  ];

  function scoreEmail({sender, senderName, subject, body, links, hasAttachment}){
    let score = 0;
    const reasons = [];

    const subj = normalizeText(subject);
    const bod = normalizeText(body + " " + subject);

    // keywords
    SUSPICIOUS_KEYWORDS.forEach(k=>{
      if(bod.includes(k)) { score += 12; reasons.push(`suspicious keyword: "${k}"`); }
    });

    // urgency / action-oriented
    ["urgent","immediately","asap","within 24 hours","verify now"].forEach(k=>{
      if(bod.includes(k)) { score += 10; reasons.push(`urgent language: "${k}"`); }
    });

    // sender email vs display name mismatch
    if(sender && senderName) {
      const senderLower = sender.toLowerCase();
      const nameLower = senderName.toLowerCase();
      // if display name contains brand but email domain doesn't match brand
      const brandWords = ["paypal","google","amazon","apple","netflix","bank","hdfc","sbi","icici"];
      brandWords.forEach(brand=>{
        if(nameLower.includes(brand) && !senderLower.includes(brand)) {
          score += 15;
          reasons.push(`display name mentions "${brand}" but sender address doesn't`);
        }
      });
    }

    // links analysis
    if(links && links.length>0){
      links.forEach(l=>{
        const resolved = l.resolved || l.href;
        const domain = getDomain(resolved) || getDomain(l.href);
        if(!domain) return;
        // shorteners
        if(HIGH_RISK_DOMAINS.includes(domain)) { score += 20; reasons.push(`uses URL shortener: ${domain}`); }
        // mismatched text vs href (display text looks like bank url but actual href different)
        const text = normalizeText(l.text || "");
        if(text && text.includes("http") && !resolved.includes(text.replace(/\s+/g,''))){
          score += 12;
          reasons.push(`link text looks like a URL but points elsewhere`);
        }
        // suspicious TLDs / punycode
        if(domain.match(/[a-z0-9-]+\.(tk|pw|cf|gq|ml)$/i)) {
          score += 12; reasons.push(`suspicious TLD: ${domain}`);
        }
      });
    } else {
      // legitimate emails often include some safe links but phishing may too; neutral
    }

    // attachments
    if(hasAttachment) { score += 6; reasons.push("has attachment"); }

    // sender is numeric or weird
    if(sender && sender.match(/\d{6,}/)) { score += 8; reasons.push("sender address contains long digits"); }

    // cap
    if(score > 100) score = 100;
    return {score, reasons};
  }

  // --- UI injection ---
  function createBanner() {
    let el = document.getElementById('phishguard-banner');
    if(el) return el;
    el = document.createElement('div');
    el.id = 'phishguard-banner';
    el.style.position = 'fixed';
    el.style.top = '8px';
    el.style.left = '50%';
    el.style.transform = 'translateX(-50%)';
    el.style.zIndex = 99999;
    el.style.minWidth = '360px';
    el.style.maxWidth = '820px';
    el.style.borderRadius = '10px';
    el.style.boxShadow = '0 6px 20px rgba(0,0,0,0.2)';
    el.style.padding = '12px 16px';
    el.style.fontFamily = 'Inter, Roboto, Arial, sans-serif';
    el.style.display = 'flex';
    el.style.alignItems = 'center';
    el.style.gap = '12px';
    el.style.background = '#f5f7fb';
    el.style.color = '#111';
    el.style.transition = 'transform .18s ease, opacity .18s ease';
    el.innerHTML = `
      <div id="pg-icon" style="width:44px;height:44px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;background:#fff;border:1px solid #e6e9ef">PG</div>
      <div style="flex:1">
        <div id="pg-status" style="font-weight:700;font-size:15px">Analyzing email...</div>
        <div id="pg-details" style="font-size:12px;opacity:.9;margin-top:4px">Checking content and links</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px">
        <div id="pg-score" style="font-weight:700">—</div>
        <button id="pg-hide" style="background:transparent;border:none;color:#666;cursor:pointer;font-size:12px">Hide</button>
      </div>
    `;
    document.body.appendChild(el);
    document.getElementById('pg-hide').addEventListener('click', ()=> el.style.display='none');
    return el;
  }

  function updateBanner(result){
    const el = createBanner();
    const status = el.querySelector('#pg-status');
    const details = el.querySelector('#pg-details');
    const scoreEl = el.querySelector('#pg-score');
    const icon = el.querySelector('#pg-icon');

    scoreEl.innerText = `${result.score}%`;

    if(result.score >= 60) {
      el.style.background = '#fff3f3';
      status.innerText = 'PHISHING — high risk';
      status.style.color = '#9b1b1b';
      details.innerText = result.reasons.slice(0,3).join(' · ') || 'Multiple suspicious indicators.';
      icon.style.background = '#fff0f0';
      icon.style.color = '#9b1b1b';
    } else if(result.score >= 30) {
      el.style.background = '#fff9ec';
      status.innerText = 'Suspicious — caution';
      status.style.color = '#7a4d00';
      details.innerText = result.reasons.slice(0,3).join(' · ') || 'Some suspicious indicators.';
      icon.style.background = '#fffaf0';
      icon.style.color = '#7a4d00';
    } else {
      el.style.background = '#f3faf7';
      status.innerText = 'Likely Legitimate';
      status.style.color = '#125a2d';
      details.innerText = result.reasons.slice(0,3).join(' · ') || 'No major red flags found.';
      icon.style.background = '#f6fff9';
      icon.style.color = '#0d7a3a';
    }
  }

  // --- Extraction logic (best-effort for Gmail dynamic DOM) ---
  function extractMailFromGmail(){
    // Gmail dynamic selectors; try multiple approaches.
    // 1) When reading a single message: subject often in 'h2' with aria-label, sender cluster in 'h3' or span with email
    try {
      // Subject
      let subject = '';
      const subjEl = document.querySelector('h2[data-legacy-thread-id], h2.hP'); // common Gmail classes
      if(subjEl) subject = subjEl.innerText;

      // Sender name and address
      let senderName = '';
      let senderEmail = '';
      // Attempt: find 'from' header area
      const header = document.querySelector('.gD, .gE'); // gD has email attribute in some Gmail DOMs
      if(header){
        senderName = header.getAttribute('name') || header.innerText || '';
        const emailAttr = header.getAttribute('email') || header.getAttribute('data-hovercard-id');
        senderEmail = emailAttr || '';
      }
      // Another attempt: the top-left header area
      const senderSpan = document.querySelector('.gD[email], span.go');
      if(!senderEmail && senderSpan) senderEmail = senderSpan.getAttribute('email') || senderSpan.innerText || '';

      // Body: Gmail content container has 'ii' class or '.a3s'
      let bodyText = '';
      const bodyEl = document.querySelector('.ii.gt, .a3s.aXjCH'); // common
      if(bodyEl) {
        bodyText = bodyEl.innerText || bodyEl.textContent || '';
      } else {
        // fallback: gather visible text from message pane
        const readPane = document.querySelector('[role="main"]');
        bodyText = readPane ? readPane.innerText : '';
      }

      // attachments detection: Gmail shows 'aQH' class attachments container
      const hasAttachment = !!document.querySelector('.aQH .aQy, .aQH');

      // collect links from body element if found
      const links = bodyEl ? extractLinksFromNode(bodyEl) : [];

      return {sender: senderEmail, senderName, subject, body: bodyText, links, hasAttachment};
    } catch(e){
      return null;
    }
  }

  // Poller to detect when a mail is opened
  let lastFingerprint = null;
  setInterval(()=>{
    const mail = extractMailFromGmail();
    if(!mail) return;
    // fingerprint to avoid repeated analysis of same message
    const fp = (mail.sender||'') + '|' + (mail.subject||'').slice(0,80);
    if(fp === lastFingerprint) return;
    lastFingerprint = fp;

    // do scoring
    const result = scoreEmail(mail);
    updateBanner(result);
  }, CHECK_INTERVAL);

})();
