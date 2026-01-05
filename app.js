
// --- Caesar Cipher Helpers ---
function caesarShiftChar(ch, shift) {
  const A = 'A'.charCodeAt(0), Z = 'Z'.charCodeAt(0);
  const a = 'a'.charCodeAt(0), z = 'z'.charCodeAt(0);
  const code = ch.charCodeAt(0);

  if (code >= A && code <= Z) {
    return String.fromCharCode(((code - A + shift) % 26 + 26) % 26 + A);
  }
  if (code >= a && code <= z) {
    return String.fromCharCode(((code - a + shift) % 26 + 26) % 26 + a);
  }
  return ch;
}
function caesarEncrypt(text, shift) {
  return text.split('').map(ch => caesarShiftChar(ch, shift)).join('');
}
function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, -shift);
}

// --- AES using CryptoJS ---
// We'll support simple password-based key (PBKDF2 would be better, but keeping demo simple)
function aesEncrypt(text, password, mode = 'CFB') {
  // Derive key via SHA256 (CryptoJS) for demo — not best practice for production
  const key = CryptoJS.SHA256(password);
  const iv = CryptoJS.lib.WordArray.random(16);

  let cipherText;
  switch (mode) {
    case 'CBC':
      cipherText = CryptoJS.AES.encrypt(text, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      break;
    case 'CTR':
      cipherText = CryptoJS.AES.encrypt(text, key, { iv, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding });
      break;
    case 'CFB':
    default:
      cipherText = CryptoJS.AES.encrypt(text, key, { iv, mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.NoPadding });
      break;
  }

  // Return Base64 of iv + ciphertext for convenience
  const combined = iv.clone().concat(cipherText.ciphertext);
  return CryptoJS.enc.Base64.stringify(combined);
}

function aesDecrypt(b64Data, password, mode = 'CFB') {
  try {
    const raw = CryptoJS.enc.Base64.parse(b64Data);
    const iv = CryptoJS.lib.WordArray.create(raw.words.slice(0, 4), 16); // 16 bytes = 4 words
    const ct = CryptoJS.lib.WordArray.create(raw.words.slice(4), raw.sigBytes - 16);

    const key = CryptoJS.SHA256(password);

    let decrypted;
    switch (mode) {
      case 'CBC':
        decrypted = CryptoJS.AES.decrypt({ ciphertext: ct }, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
        break;
      case 'CTR':
        decrypted = CryptoJS.AES.decrypt({ ciphertext: ct }, key, { iv, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding });
        break;
      case 'CFB':
      default:
        decrypted = CryptoJS.AES.decrypt({ ciphertext: ct }, key, { iv, mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.NoPadding });
        break;
    }

    const result = CryptoJS.enc.Utf8.stringify(decrypted);
    if (!result) throw new Error('Bad key or ciphertext');
    return result;
  } catch (e) {
    return '❌ Decryption failed: ' + e.message;
  }
}

// --- UI Logic ---
const algorithmSelect = document.getElementById('algorithm');
const caesarOptions = document.getElementById('caesarOptions');
const aesOptions = document.getElementById('aesOptions');
const inputText = document.getElementById('inputText');
const outputText = document.getElementById('outputText');
const shiftInput = document.getElementById('shift');
const keyInput = document.getElementById('secretKey');
const aesModeSelect = document.getElementById('aesMode');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const copyBtn = document.getElementById('copyBtn');
const clearBtn = document.getElementById('clearBtn');

function updateOptions() {
  const algo = algorithmSelect.value;
  if (algo === 'caesar') {
    caesarOptions.classList.remove('hidden');
    aesOptions.classList.add('hidden');
  } else {
    aesOptions.classList.remove('hidden');
    caesarOptions.classList.add('hidden');
  }
}
algorithmSelect.addEventListener('change', updateOptions);
updateOptions();

encryptBtn.addEventListener('click', () => {
  const algo = algorithmSelect.value;
  const text = inputText.value;
  if (!text) { outputText.value = '⚠️ Enter text first.'; return; }

  if (algo === 'caesar') {
    const shift = parseInt(shiftInput.value || '3', 10);
    outputText.value = caesarEncrypt(text, shift);
  } else {
    const key = keyInput.value.trim();
    if (!key) { outputText.value = '⚠️ Enter secret key for AES.'; return; }
    const mode = aesModeSelect.value;
    outputText.value = aesEncrypt(text, key, mode);
  }
});

decryptBtn.addEventListener('click', () => {
  const algo = algorithmSelect.value;
  const text = inputText.value;
  if (!text) { outputText.value = '⚠️ Enter text/ciphertext first.'; return; }

  if (algo === 'caesar') {
    const shift = parseInt(shiftInput.value || '3', 10);
    outputText.value = caesarDecrypt(text, shift);
  } else {
    const key = keyInput.value.trim();
    if (!key) { outputText.value = '⚠️ Enter secret key for AES.'; return; }
    const mode = aesModeSelect.value;
    outputText.value = aesDecrypt(text, key, mode);
  }
});

copyBtn.addEventListener('click', async () => {
  const out = outputText.value;
  if (!out) { return; }
  try {
    await navigator.clipboard.writeText(out);
    copyBtn.textContent = '✅ Copied';
    setTimeout(() => (copyBtn.textContent = 'Copy Output'), 1200);
  } catch {
    copyBtn.textContent = '⚠️ Failed';
    setTimeout(() => (copyBtn.textContent = 'Copy Output'), 1200);
  }
});

clearBtn.addEventListener('click', () => {
  inputText.value = '';
  outputText.value = '';
});
