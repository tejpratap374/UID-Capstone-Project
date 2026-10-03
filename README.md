# CryptoLab

A browser-based cryptography playground. Vanilla HTML, CSS and JavaScript: no frameworks, backend or database.

## Run
Open `index.html` in any modern browser. No build step.
(SHA-256 uses the Web Crypto API, which needs `https://` or `localhost`; opening the file directly via `file://` works in current browsers.)

## Algorithms
Caesar, Vigenère, Rail Fence, ROT13, Base64, XOR (hex output), SHA-256 (hash only, no decrypt).

## Features
Live output as you type, copy and clear, character/byte counters, an "About algorithm" panel with a security verdict for each, and a 15-entry history (click an entry to reload it).

## Security note
Everything here except SHA-256 is educational. None of the ciphers should protect real data. For real use, reach for AES-GCM or ChaCha20-Poly1305 via a vetted library, and Argon2/bcrypt for passwords.

## Files
- `index.html` – layout
- `style.css` – dark theme, responsive
- `script.js` – algorithms and UI logic
