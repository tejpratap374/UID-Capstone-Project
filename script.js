'use strict';

// Alias for DOM lookups to keep the code shorter and more readable.
const $ = (id) => document.getElementById(id);
const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });
const toHex = (bytes) => [...bytes].map((x) => x.toString(16).padStart(2, '0')).join('');

const GROUPS = [
  { id: 'all', label: 'All' },
  { id: 'classical', label: 'Classical' },
  { id: 'encoding', label: 'Encoding' },
  { id: 'hashing', label: 'Hashing' },
  { id: 'modern', label: 'Modern' }
];

const PRESETS = [
  { label: 'Hello World', value: 'HELLO WORLD' },
  { label: 'Secret', value: 'MEET AT MIDNIGHT' },
  { label: 'Password', value: 'P@ssw0rd123' },
  { label: 'Sample', value: 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG' }
];

// ---------- basic cipher helpers ----------
const shiftText = (text, shift) =>
  text.replace(/[a-z]/gi, (char) => {
    const base = char <= 'Z' ? 65 : 97;
    return String.fromCharCode((char.charCodeAt(0) - base + (shift % 26) + 26) % 26 + base);
  });

function vigenere(text, key, direction) {
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!cleanKey) throw Error('Key must contain at least one letter.');

  let index = 0;
  return text.replace(/[a-z]/gi, (char) => {
    const base = char <= 'Z' ? 65 : 97;
    const shift = (cleanKey.charCodeAt(index++ % cleanKey.length) - 65) * direction;
    return String.fromCharCode((char.charCodeAt(0) - base + shift + 26) % 26 + base);
  });
}

function railOrder(length, rails) {
  if (!Number.isInteger(rails) || rails < 2) {
    throw Error('Rails must be a whole number of 2 or more.');
  }

  const pattern = [];
  let row = 0;
  let direction = 1;

  for (let i = 0; i < length; i += 1) {
    pattern.push(row);
    if (row === 0) direction = 1;
    else if (row === rails - 1) direction = -1;
    row += direction;
  }

  return [...pattern.keys()].sort((left, right) => pattern[left] - pattern[right] || left - right);
}

function railFence(text, rails, decrypt) {
  const chars = [...text];
  const order = railOrder(chars.length, rails);

  if (!decrypt) return order.map((index) => chars[index]).join('');

  const out = [];
  order.forEach((originalIndex, position) => {
    out[originalIndex] = chars[position];
  });

  return out.join('');
}

function xorBytes(bytes, key) {
  if (!key) throw Error('Key cannot be empty.');
  const repeatedKey = te.encode(key);
  return bytes.map((byte, index) => byte ^ repeatedKey[index % repeatedKey.length]);
}

const b64enc = (text) => {
  let binaryString = '';
  te.encode(text).forEach((byte) => {
    binaryString += String.fromCharCode(byte);
  });
  return btoa(binaryString);
};

const b64dec = (text) => {
  try {
    return td.decode(Uint8Array.from(atob(text.trim()), (char) => char.charCodeAt(0)));
  } catch {
    throw Error('Input is not valid Base64 text.');
  }
};

// ---------- algorithm registry ----------
const A = {
  caesar: {
    name: 'Caesar',
    group: 'classical',
    strength: { label: 'Weak', tone: 'weak' },
    opts: [{ id: 'shift', label: 'Shift', type: 'number', value: 3 }],
    enc: (text, options) => shiftText(text, +options.shift || 0),
    dec: (text, options) => shiftText(text, -(+options.shift || 0)),
    badge: ['broken', 'Broken'],
    what: 'Replaces each letter with the one a fixed number of places further along the alphabet. Attributed to Julius Caesar, who used a shift of 3.',
    secure: 'There are only 25 usable keys, so an attacker can try them all in a blink. Letter-frequency analysis breaks it even faster. Use it for learning and puzzles only.',
    example: 'Example: HELLO becomes KHOOR with a shift of 3.'
  },
  vigenere: {
    name: 'Vigenère',
    group: 'classical',
    strength: { label: 'Weak', tone: 'weak' },
    opts: [{ id: 'key', label: 'Key (letters)', type: 'text', value: 'KEY' }],
    enc: (text, options) => vigenere(text, options.key, 1),
    dec: (text, options) => vigenere(text, options.key, -1),
    badge: ['broken', 'Broken'],
    what: 'Applies a different Caesar shift to each letter, cycling through the letters of a keyword. Once called "le chiffre indéchiffrable".',
    secure: 'Broken since the 1860s. The Kasiski examination and index of coincidence reveal the key length, which reduces the cipher to several Caesar ciphers. Only a key as long as the message and never reused (a one-time pad) would be unbreakable.',
    example: 'Example: use a keyword like KEY to vary the shift for each letter.'
  },
  railfence: {
    name: 'Rail Fence',
    group: 'classical',
    strength: { label: 'Weak', tone: 'weak' },
    opts: [{ id: 'rails', label: 'Rails', type: 'number', value: 3 }],
    enc: (text, options) => railFence(text, +options.rails, false),
    dec: (text, options) => railFence(text, +options.rails, true),
    badge: ['broken', 'Broken'],
    what: 'A transposition cipher. It writes the text in a zig-zag across several rows (rails), then reads each row in turn. Letters keep their identity but change position.',
    secure: 'The key space is tiny (one number up to the message length), and letter frequencies are unchanged, so it falls to brute force immediately.',
    example: 'Example: a zig-zag row pattern reshuffles the order of letters without changing the letters themselves.'
  },
  rot13: {
    name: 'ROT13',
    group: 'classical',
    strength: { label: 'Very weak', tone: 'weak' },
    opts: [],
    enc: (text) => shiftText(text, 13),
    dec: (text) => shiftText(text, 13),
    badge: ['broken', 'Not encryption'],
    what: 'A Caesar cipher with a fixed shift of 13. Applying it twice returns the original text, so encrypt and decrypt are the same operation.',
    secure: 'It has no key, so it protects nothing. It is used to hide spoilers and punchlines from a casual glance, not from anyone who wants to read them.',
    example: 'Example: SECRET becomes FRPERG, and applying it again returns SECRET.'
  },
  base64: {
    name: 'Base64',
    group: 'encoding',
    strength: { label: 'Not encryption', tone: 'medium' },
    opts: [],
    enc: (text) => b64enc(text),
    dec: (text) => b64dec(text),
    badge: ['enc', 'Encoding only'],
    what: 'Converts binary data into 64 printable characters so it can travel through text-only systems such as email, JSON and URLs.',
    secure: 'Base64 is an encoding, not encryption. It has no key and anyone can reverse it. Never use it to hide passwords or secrets, a mistake that regularly shows up in real breaches.',
    example: 'Example: plain text is mapped into readable ASCII characters for transport through text-only systems.'
  },
  xor: {
    name: 'XOR',
    group: 'modern',
    strength: { label: 'Weak', tone: 'weak' },
    opts: [{ id: 'key', label: 'Key (text)', type: 'text', value: 'secret' }],
    enc: (text, options) => toHex(xorBytes(te.encode(text), options.key)),
    dec: (text, options) => {
      const hexInput = text.replace(/\s/g, '');
      if (!/^([0-9a-f]{2})+$/i.test(hexInput)) throw Error('Input must be hex pairs, e.g. 1a2b3c.');

      try {
        return td.decode(xorBytes(Uint8Array.from(hexInput.match(/../g), (value) => parseInt(value, 16)), options.key));
      } catch (error) {
        const message = error.message || '';
        throw Error(message.includes('Key') ? message : 'Wrong key, or the data is not text.');
      }
    },
    badge: ['enc', 'Insecure as used here'],
    what: 'Combines each byte of the message with a byte of a repeating key using the exclusive-or operation. Output is shown as hex.',
    secure: 'XOR with a short repeating key is easily broken: if any plaintext is guessable, XOR-ing it with the ciphertext reveals the key. XOR is only secure as a one-time pad, where the key is truly random, as long as the message, and never reused. It is a building block inside AES and stream ciphers.',
    example: 'Example: XORing each byte with a repeating key creates a stream that can be reversed only with the same key.'
  },
  sha256: {
    name: 'SHA-256',
    group: 'hashing',
    strength: { label: 'Strong', tone: 'strong' },
    opts: [],
    hash: true,
    enc: async (text) => toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(text)))),
    badge: ['ok', 'Secure hash'],
    what: 'A one-way hash function from the SHA-2 family. It turns any input into a fixed 256-bit fingerprint. A tiny change in the input gives a completely different output.',
    secure: 'No practical collision or preimage attacks are known, so it is safe for integrity checks and digital signatures. It is too fast for storing passwords: use a slow, salted function such as Argon2, bcrypt or scrypt instead. It cannot be decrypted, only guessed and compared.',
    example: 'Example: hashing the same input twice always produces the same fingerprint, even when the text is long.'
  }
};

// ---------- state and UI ----------
let cur = 'caesar';
let curGroup = 'all';
let mode = 'enc';
let hist = [];

const bytes = (text) => te.encode(text).length;
const opts = () => Object.fromEntries([...document.querySelectorAll('#opts input')].map((input) => [input.id, input.value]));

function getValidationMessage() {
  const algorithm = A[cur];
  const currentOpts = opts();

  if (algorithm.hash) return '';

  if (cur === 'caesar' && (!Number.isFinite(+currentOpts.shift) || +currentOpts.shift < 0)) {
    return 'Shift should be a non-negative number.';
  }

  if (cur === 'vigenere' && (!currentOpts.key || !/[A-Za-z]/.test(currentOpts.key))) {
    return 'Use at least one letter in the key.';
  }

  if (cur === 'railfence' && (!Number.isFinite(+currentOpts.rails) || +currentOpts.rails < 2)) {
    return 'Rails must be 2 or more.';
  }

  if (cur === 'xor' && (!currentOpts.key || !currentOpts.key.trim())) {
    return 'XOR key should not be empty.';
  }

  return '';
}

function renderGroupList() {
  $('groupList').innerHTML = GROUPS.map(
    (group) => `<button class="group-btn ${curGroup === group.id ? 'on' : ''}" data-group="${group.id}">${group.label}</button>`
  ).join('');
}

function renderPresetList() {
  $('presetList').innerHTML = PRESETS.map(
    (preset, index) => `<button type="button" class="preset-btn" data-index="${index}">${preset.label}</button>`
  ).join('');
}

function renderAlgoList() {
  const visible = Object.entries(A).filter(([id, algorithm]) => curGroup === 'all' || algorithm.group === curGroup);

  if (!visible.some(([id]) => id === cur)) {
    cur = visible[0][0];
  }

  $('algoList').innerHTML = visible
    .map(([id, algorithm]) => `<button class="algo ${cur === id ? 'on' : ''}" data-id="${id}">${algorithm.name}</button>`)
    .join('');
}

function renderAlgo() {
  const algorithm = A[cur];
  $('title').textContent = algorithm.name;

  $('opts').innerHTML = (algorithm.opts || [])
    .map(
      (option) =>
        `<label for="${option.id}">${option.label}</label><input id="${option.id}" type="${option.type}" value="${option.value}" ${option.type === 'number' ? 'min="1"' : ''}>`
    )
    .join('');

  $('opts').querySelectorAll('input').forEach((input) => input.addEventListener('input', run));
  $('decBtn').disabled = !!algorithm.hash;
  if (algorithm.hash) mode = 'enc';

  const validationMessage = getValidationMessage();
  const validationBox = $('validationMsg');
  if (validationMessage) {
    validationBox.textContent = validationMessage;
    validationBox.classList.add('show');
  } else {
    validationBox.textContent = '';
    validationBox.classList.remove('show');
  }

  const cards = [
    { title: 'How it works', text: algorithm.what },
    { title: 'Quick example', text: algorithm.example || 'Try a short phrase and compare the result before and after encryption.' },
    { title: 'Why it matters', text: algorithm.secure }
  ];

  $('aboutBody').innerHTML = `
    <div class="security-strip">
      <span class="badge ${algorithm.badge[0]}">${algorithm.badge[1]}</span>
      <span class="strength-pill strength-${algorithm.strength.tone}">Strength: ${algorithm.strength.label}</span>
    </div>
    <div class="card-grid">
      ${cards.map((card) => `
        <article class="info-card">
          <h4>${card.title}</h4>
          <p>${card.text}</p>
        </article>
      `).join('')}
    </div>`;

  document.querySelectorAll('.algo').forEach((button) => {
    button.classList.toggle('on', button.dataset.id === cur);
  });

  document.querySelectorAll('.group-btn').forEach((button) => {
    button.classList.toggle('on', button.dataset.group === curGroup);
  });

  run();
}

async function run() {
  const algorithm = A[cur];
  const inputText = $('input').value;
  const output = $('output');

  $('encBtn').classList.toggle('on', mode === 'enc');
  $('decBtn').classList.toggle('on', mode === 'dec');
  output.classList.remove('err');

  try {
    output.textContent = inputText ? await (mode === 'enc' ? algorithm.enc : algorithm.dec)(inputText, opts()) : '';
  } catch (error) {
    output.textContent = error.message;
    output.classList.add('err');
  }

  const validationMessage = getValidationMessage();
  const validationBox = $('validationMsg');
  if (validationMessage) {
    validationBox.textContent = validationMessage;
    validationBox.classList.add('show');
  } else {
    validationBox.textContent = '';
    validationBox.classList.remove('show');
  }

  $('inCount').textContent = `${[...inputText].length} chars · ${bytes(inputText)} bytes`;
  const outputText = output.classList.contains('err') ? '' : output.textContent;
  $('outCount').textContent = `${[...outputText].length} chars · ${bytes(outputText)} bytes`;
}

function log() {
  const output = $('output');
  if (!$('input').value || output.classList.contains('err')) return;

  hist.unshift({ id: cur, mode, input: $('input').value, output: output.textContent });
  hist = hist.slice(0, 15);
  renderHist();
}

function renderHist() {
  const list = $('history');
  list.innerHTML = '';

  if (!hist.length) {
    list.innerHTML = '<li>No operations yet. Press Encrypt or Decrypt to record one.</li>';
    return;
  }

  hist.forEach((entry) => {
    const item = document.createElement('li');
    item.innerHTML = `<em>${A[entry.id].name} ${entry.mode === 'enc' ? 'encrypt' : 'decrypt'}</em> `;
    item.append(`${entry.input.slice(0, 30)} → ${entry.output.slice(0, 40)}`);
    item.title = 'Click to reload this input';
    item.onclick = () => {
      cur = entry.id;
      mode = entry.mode;
      $('input').value = entry.input;
      renderAlgo();
    };
    list.append(item);
  });
}

function applyTheme(theme) {
  document.body.dataset.theme = theme;
  const toggle = $('themeToggle');
  if (!toggle) return;
  toggle.textContent = theme === 'dark' ? '☀️' : '🌙';
  toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
}

$('groupList').addEventListener('click', (event) => {
  const target = event.target.closest('.group-btn');
  if (!target) return;
  curGroup = target.dataset.group;
  renderGroupList();
  renderAlgoList();
  renderAlgo();
});

$('algoList').addEventListener('click', (event) => {
  const target = event.target.closest('.algo');
  if (!target) return;
  cur = target.dataset.id;
  renderAlgoList();
  renderAlgo();
});

$('presetList').addEventListener('click', (event) => {
  const target = event.target.closest('.preset-btn');
  if (!target) return;
  const preset = PRESETS[Number(target.dataset.index)];
  $('input').value = preset.value;
  run();
  $('input').focus();
});

$('input').addEventListener('input', run);
$('encBtn').onclick = async () => {
  mode = 'enc';
  await run();
  log();
};
$('decBtn').onclick = async () => {
  mode = 'dec';
  await run();
  log();
};
$('copyBtn').onclick = async (event) => {
  try {
    await navigator.clipboard.writeText($('output').textContent);
    event.target.textContent = 'Copied';
  } catch {
    event.target.textContent = 'Copy failed';
  }
  setTimeout(() => {
    event.target.textContent = 'Copy result';
  }, 1200);
};
$('copyInputBtn').onclick = async (event) => {
  try {
    await navigator.clipboard.writeText($('input').value);
    event.target.textContent = 'Copied';
  } catch {
    event.target.textContent = 'Copy failed';
  }
  setTimeout(() => {
    event.target.textContent = 'Copy input';
  }, 1200);
};
$('clearBtn').onclick = () => {
  $('input').value = '';
  run();
  $('input').focus();
};
$('clearHist').onclick = () => {
  hist = [];
  renderHist();
};

$('themeToggle').onclick = () => {
  const nextTheme = document.body.dataset.theme === 'light' ? 'dark' : 'light';
  localStorage.setItem('cryptolab-theme', nextTheme);
  applyTheme(nextTheme);
};

const savedTheme = localStorage.getItem('cryptolab-theme') || 'dark';
applyTheme(savedTheme);
renderGroupList();
renderPresetList();
renderAlgoList();
renderHist();
renderAlgo();
