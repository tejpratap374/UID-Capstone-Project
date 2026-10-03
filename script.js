'use strict';

// Alias for DOM lookups to keep the code shorter and more readable.
const $ = (id) => document.getElementById(id);
const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });
const toHex = (bytes) => [...bytes].map((x) => x.toString(16).padStart(2, '0')).join('');

// ---------- basic cipher helpers ----------

// Shift each English letter forward or backward by a fixed number of positions.
const shiftText = (text, shift) =>
  text.replace(/[a-z]/gi, (char) => {
    const base = char <= 'Z' ? 65 : 97;
    return String.fromCharCode((char.charCodeAt(0) - base + (shift % 26) + 26) % 26 + base);
  });

// Vigenère cipher: each letter uses a Caesar shift based on a repeating key.
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

// Rail Fence order: creates the zig-zag path used for transposition.
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

// Rail Fence cipher: reorder characters by row and then read them back.
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

// XOR each byte with a repeating text key.
function xorBytes(bytes, key) {
  if (!key) throw Error('Key cannot be empty.');
  const repeatedKey = te.encode(key);
  return bytes.map((byte, index) => byte ^ repeatedKey[index % repeatedKey.length]);
}

// Base64 helpers for text-safe encoding and decoding.
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

// Each algorithm exposes the same interface: name, options, encrypt/decrypt logic,
// and descriptive metadata used in the UI.
const A = {
  caesar: {
    name: 'Caesar',
    opts: [{ id: 'shift', label: 'Shift', type: 'number', value: 3 }],
    enc: (text, options) => shiftText(text, +options.shift || 0),
    dec: (text, options) => shiftText(text, -(+options.shift || 0)),
    badge: ['broken', 'Broken'],
    what: 'Replaces each letter with the one a fixed number of places further along the alphabet. Attributed to Julius Caesar, who used a shift of 3.',
    secure: 'There are only 25 usable keys, so an attacker can try them all in a blink. Letter-frequency analysis breaks it even faster. Use it for learning and puzzles only.'
  },
  vigenere: {
    name: 'Vigenère',
    opts: [{ id: 'key', label: 'Key (letters)', type: 'text', value: 'KEY' }],
    enc: (text, options) => vigenere(text, options.key, 1),
    dec: (text, options) => vigenere(text, options.key, -1),
    badge: ['broken', 'Broken'],
    what: 'Applies a different Caesar shift to each letter, cycling through the letters of a keyword. Once called "le chiffre indéchiffrable".',
    secure: 'Broken since the 1860s. The Kasiski examination and index of coincidence reveal the key length, which reduces the cipher to several Caesar ciphers. Only a key as long as the message and never reused (a one-time pad) would be unbreakable.'
  },
  railfence: {
    name: 'Rail Fence',
    opts: [{ id: 'rails', label: 'Rails', type: 'number', value: 3 }],
    enc: (text, options) => railFence(text, +options.rails, false),
    dec: (text, options) => railFence(text, +options.rails, true),
    badge: ['broken', 'Broken'],
    what: 'A transposition cipher. It writes the text in a zig-zag across several rows (rails), then reads each row in turn. Letters keep their identity but change position.',
    secure: 'The key space is tiny (one number up to the message length), and letter frequencies are unchanged, so it falls to brute force immediately.'
  },
  rot13: {
    name: 'ROT13',
    opts: [],
    enc: (text) => shiftText(text, 13),
    dec: (text) => shiftText(text, 13),
    badge: ['broken', 'Not encryption'],
    what: 'A Caesar cipher with a fixed shift of 13. Applying it twice returns the original text, so encrypt and decrypt are the same operation.',
    secure: 'It has no key, so it protects nothing. It is used to hide spoilers and punchlines from a casual glance, not from anyone who wants to read them.'
  },
  base64: {
    name: 'Base64',
    opts: [],
    enc: (text) => b64enc(text),
    dec: (text) => b64dec(text),
    badge: ['enc', 'Encoding only'],
    what: 'Converts binary data into 64 printable characters so it can travel through text-only systems such as email, JSON and URLs.',
    secure: 'Base64 is an encoding, not encryption. It has no key and anyone can reverse it. Never use it to hide passwords or secrets, a mistake that regularly shows up in real breaches.'
  },
  xor: {
    name: 'XOR',
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
    secure: 'XOR with a short repeating key is easily broken: if any plaintext is guessable, XOR-ing it with the ciphertext reveals the key. XOR is only secure as a one-time pad, where the key is truly random, as long as the message, and never reused. It is a building block inside AES and stream ciphers.'
  },
  sha256: {
    name: 'SHA-256',
    opts: [],
    hash: true,
    enc: async (text) => toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(text)))),
    badge: ['ok', 'Secure hash'],
    what: 'A one-way hash function from the SHA-2 family. It turns any input into a fixed 256-bit fingerprint. A tiny change in the input gives a completely different output.',
    secure: 'No practical collision or preimage attacks are known, so it is safe for integrity checks and digital signatures. It is too fast for storing passwords: use a slow, salted function such as Argon2, bcrypt or scrypt instead. It cannot be decrypted, only guessed and compared.'
  }
};

// ---------- state and UI ----------

let cur = 'caesar';
let mode = 'enc';
let hist = [];

const bytes = (text) => te.encode(text).length;
const opts = () => Object.fromEntries([...document.querySelectorAll('#opts input')].map((input) => [input.id, input.value]));

// Render the selected algorithm form and its informational panel.
function renderAlgo() {
  const algorithm = A[cur];
  $('title').textContent = algorithm.name;
  $('opts').innerHTML = algorithm.opts
    .map(
      (option) =>
        `<label for="${option.id}">${option.label}</label><input id="${option.id}" type="${option.type}" value="${option.value}" ${option.type === 'number' ? 'min="1"' : ''}>`
    )
    .join('');

  $('opts').querySelectorAll('input').forEach((input) => input.addEventListener('input', run));
  $('decBtn').disabled = !!algorithm.hash;
  if (algorithm.hash) mode = 'enc';

  $('aboutBody').innerHTML = `<span class="badge ${algorithm.badge[0]}">${algorithm.badge[1]}</span>
    <p><b>What it does.</b> ${algorithm.what}</p>
    <p><b>Secure today?</b> ${algorithm.secure}</p>`;

  document.querySelectorAll('.algo').forEach((button) => {
    button.classList.toggle('on', button.dataset.id === cur);
  });

  run();
}

// Run the current operation and update the output and byte counters.
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

  $('inCount').textContent = `${[...inputText].length} chars · ${bytes(inputText)} bytes`;
  const outputText = output.classList.contains('err') ? '' : output.textContent;
  $('outCount').textContent = `${[...outputText].length} chars · ${bytes(outputText)} bytes`;
}

// Record a successful action in the history panel for quick re-use.
function log() {
  const output = $('output');
  if (!$('input').value || output.classList.contains('err')) return;

  hist.unshift({ id: cur, mode, input: $('input').value, output: output.textContent });
  hist = hist.slice(0, 15);
  renderHist();
}

// Draw the recent history list.
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

$('algoList').innerHTML = Object.entries(A)
  .map(([id, algorithm]) => `<button class="algo" data-id="${id}">${algorithm.name}</button>`)
  .join('');

$('algoList').addEventListener('click', (event) => {
  if (event.target.dataset.id) {
    cur = event.target.dataset.id;
    renderAlgo();
  }
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
$('clearBtn').onclick = () => {
  $('input').value = '';
  run();
  $('input').focus();
};
$('clearHist').onclick = () => {
  hist = [];
  renderHist();
};

renderHist();
renderAlgo();
