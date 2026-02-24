# XSS Lab

An interactive, self-hosted XSS training lab with 23 progressively harder challenges. Built for hackers, pentesters, and developers who want to understand cross-site scripting from the ground up.

Every level runs on a single Node.js server with zero external dependencies beyond Express. No Docker, no databases, no build step.

## Levels

| # | Name | Difficulty | Technique |
|---|------|------------|-----------|
| 1 | Hello, Reflected XSS | Easy | Basic reflected XSS |
| 2 | Stored XSS Guestbook | Easy | Persistent/stored XSS |
| 3 | Script Tag Blocked | Medium | Alternative tags & event handlers |
| 4 | Attribute Injection | Medium | Breaking out of HTML attributes |
| 5 | JavaScript Context | Medium | Escaping JS string context |
| 6 | Event Handler Blocklist | Hard | Bypassing event handler filters |
| 7 | Case & Keyword Filter | Hard | Case tricks & bracket notation |
| 8 | DOM-Based XSS | Hard | Client-side DOM manipulation |
| 9 | href Injection with Filters | Expert | `javascript:` URI with entity encoding |
| 10 | CSP Bypass | Expert | JSONP callback abuse |
| 11 | Double Encoding Bypass | Expert | Double URL encoding |
| 12 | Client-Side Template Injection | Expert | Sandbox escape via constructors |
| 13 | postMessage XSS | Expert | Cross-origin message handling |
| 14 | SVG Upload XSS | Expert | Malicious SVG with embedded scripts |
| 15 | Mutation XSS | Expert | DOM mutation via innerHTML |
| 16 | Recursive Keyword Filter | Expert | Nested tag reconstruction |
| 17 | The Polyglot | Expert | Multi-context polyglot payload |
| 18 | DOM Clobbering | Expert | Named element property override |
| 19 | Prototype Pollution to XSS | Expert | `__proto__` poisoning |
| 20 | Base Tag Injection | Expert | Hijacking relative script paths |
| 21 | Dangling Markup Injection | Expert | Data exfiltration without JavaScript |
| 22 | JSON Injection in Script Block | Expert | Breaking out of inline JSON |
| 23 | URL Scheme Bypass | Expert | HTML entity encoding mismatch |

## Getting Started

```bash
git clone https://github.com/ArtSecTest/xss-lab.git
cd xss-lab
npm install
npm start
```

Open http://localhost:3000 in your browser.

## Features

- **Dashboard** with progress tracking across all 23 levels
- **Hints** for every level (base64-encoded so you won't accidentally spoil yourself in page source)
- **Detailed writeups** that unlock after solving each level, explaining why the attack worked, the key lesson, and real-world applications
- **Cheat sheet** with all techniques, injection contexts, and defenses at a glance
- **Solutions saved locally** to `solutions.json` (gitignored) so your progress persists across restarts
- **Reset button** on the dashboard to start fresh

## How It Works

Each level presents a vulnerable web page with specific defenses. Your goal is to trigger `alert()` (or exfiltrate data, for level 21). The server deliberately implements flawed sanitization to teach you why each defense fails and what the correct fix would be.

Levels 1-8 cover fundamentals. Levels 9-17 introduce CSP bypasses, template injection, mutation XSS, and other intermediate techniques. Levels 18-23 cover advanced topics like DOM clobbering, prototype pollution, base tag injection, dangling markup, and encoding mismatches.

## Requirements

- Node.js 18+
- A modern browser (Chrome recommended)

## Disclaimer

This project is for **educational purposes only**. The vulnerabilities are intentional and should only be exploited within this local lab environment. Do not use these techniques against systems you do not own or have explicit authorization to test.
