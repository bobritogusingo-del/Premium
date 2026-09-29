// node_modules/@noble/ciphers/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function abool(value, title = "") {
  if (typeof value !== "boolean")
    throw new TypeError(atitle(title) + "expected boolean, got type=" + typeof value);
  return value;
}
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes(value, length, title = "") {
  if (isBytes(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError(label === "object" ? "expected valid options object" : `"${label}" expected object, got type=${typeof value}`);
};
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function overlapBytes(a, b) {
  if (!a.byteLength || !b.byteLength)
    return false;
  return a.buffer === b.buffer && // best we can do, may fail with an obscure Proxy
  a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
  b.byteOffset < a.byteOffset + a.byteLength;
}
function complexOverlapBytes(input, output) {
  if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
    throw new Error("complex overlap of input and output is not supported");
}
function checkOpts(defaults, opts) {
  aobject(defaults, "defaults");
  aobject(opts, "opts");
  const merged = Object.assign(defaults, opts);
  return merged;
}
function equalBytes(a, b) {
  a = abytes(a);
  b = abytes(b);
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function wrapMacConstructor(keyLen, macCons, fromMsg) {
  const mac = macCons;
  const getArgs = fromMsg || (() => []);
  const macC = (msg, key) => mac(key, ...getArgs(msg)).update(msg).digest();
  const tmp = mac(new Uint8Array(keyLen), ...getArgs(new Uint8Array(0)));
  macC.outputLen = tmp.outputLen;
  macC.blockLen = tmp.blockLen;
  macC.create = (key, ...args) => mac(key, ...args);
  return macC;
}
var wrapCipher = /* @__NO_SIDE_EFFECTS__ */ (params, constructor) => {
  function wrappedCipher(key, ...args) {
    abytes(key, void 0, "key");
    if (params.nonceLength !== void 0) {
      const nonce = args[0];
      abytes(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
    }
    const tagl = params.tagLength;
    const aadStart = params.nonceLength !== void 0 ? 1 : 0;
    if (!params.withAAD) {
      for (let i = aadStart; i < args.length; i++)
        if (isBytes(args[i]))
          throw new Error("AAD not supported");
    }
    if (params.withAAD && args[aadStart] !== void 0)
      abytes(args[aadStart], void 0, "AAD");
    const cipher = constructor(key, ...args);
    const checkOutput = (fnLength, output) => {
      if (output !== void 0) {
        if (fnLength !== 2)
          throw new Error("cipher output not supported");
        abytes(output, void 0, "output");
      }
    };
    let called = false;
    const wrCipher = {
      encrypt(data, output) {
        if (called)
          throw new Error("cannot encrypt() twice with same key + nonce");
        called = true;
        abytes(data, void 0, "data");
        checkOutput(cipher.encrypt.length, output);
        return cipher.encrypt(data, output);
      },
      decrypt(data, output) {
        abytes(data, void 0, "data");
        if (tagl && data.length < tagl)
          throw new Error('"ciphertext" expected length >= tagLength=' + tagl);
        checkOutput(cipher.decrypt.length, output);
        return cipher.decrypt(data, output);
      }
    };
    return wrCipher;
  }
  Object.assign(wrappedCipher, params);
  return wrappedCipher;
};
function getOutput(expectedLength, out, onlyAligned = true) {
  if (out === void 0)
    return new Uint8Array(expectedLength);
  abytes(out, expectedLength, "output");
  if (onlyAligned && !isAligned32(out))
    throw new Error("invalid output, must be aligned");
  return out;
}
function u64Lengths(dataLength, aadLength, isLE2) {
  anumber(dataLength);
  anumber(aadLength);
  abool(isLE2);
  const num = new Uint8Array(16);
  const view = createView(num);
  view.setBigUint64(0, BigInt(aadLength), isLE2);
  view.setBigUint64(8, BigInt(dataLength), isLE2);
  return num;
}
function isAligned32(bytes) {
  return bytes.byteOffset % 4 === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes(bytes));
}

// node_modules/@noble/ciphers/_arx.js
var encodeStr = (str) => Uint8Array.from(str.split(""), (c) => c.charCodeAt(0));
var sigma16_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr("expand 16-byte k"))))();
var sigma32_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr("expand 32-byte k"))))();
function rotl(a, b) {
  return a << b | a >>> 32 - b;
}
var BLOCK_LEN = 64;
var BLOCK_LEN32 = 16;
var MAX_COUNTER = /* @__PURE__ */ (() => 2 ** 32 - 1)();
var U32_EMPTY = /* @__PURE__ */ Uint32Array.of();
function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
  const len = data.length;
  const block = new Uint8Array(BLOCK_LEN);
  const b32 = u32(block);
  const isAligned = isLE && isAligned32(data) && isAligned32(output);
  const d32 = isAligned ? u32(data) : U32_EMPTY;
  const o32 = isAligned ? u32(output) : U32_EMPTY;
  if (!isLE) {
    for (let pos = 0; pos < len; counter++) {
      core(sigma, key, nonce, b32, counter, rounds);
      swap32IfBE(b32);
      if (counter >= MAX_COUNTER)
        throw new Error("arx: counter overflow");
      const take = Math.min(BLOCK_LEN, len - pos);
      for (let j = 0, posj; j < take; j++) {
        posj = pos + j;
        output[posj] = data[posj] ^ block[j];
      }
      pos += take;
    }
    return;
  }
  for (let pos = 0; pos < len; counter++) {
    core(sigma, key, nonce, b32, counter, rounds);
    if (counter >= MAX_COUNTER)
      throw new Error("arx: counter overflow");
    const take = Math.min(BLOCK_LEN, len - pos);
    if (isAligned && take === BLOCK_LEN) {
      const pos32 = pos / 4;
      if (pos % 4 !== 0)
        throw new Error("arx: invalid block position");
      for (let j = 0, posj; j < BLOCK_LEN32; j++) {
        posj = pos32 + j;
        o32[posj] = d32[posj] ^ b32[j];
      }
      pos += BLOCK_LEN;
      continue;
    }
    for (let j = 0, posj; j < take; j++) {
      posj = pos + j;
      output[posj] = data[posj] ^ block[j];
    }
    pos += take;
  }
}
function createCipher(core, opts) {
  const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts);
  if (typeof core !== "function")
    throw new Error("core must be a function");
  anumber(counterLength);
  anumber(rounds);
  abool(counterRight);
  abool(allowShortKeys);
  return (key, nonce, data, output, counter = 0) => {
    abytes(key, void 0, "key");
    abytes(nonce, void 0, "nonce");
    abytes(data, void 0, "data");
    const len = data.length;
    const hasOutput = output !== void 0;
    output = getOutput(len, output, false);
    if (hasOutput)
      complexOverlapBytes(data, output);
    anumber(counter);
    if (counter < 0 || counter >= MAX_COUNTER)
      throw new Error("arx: counter overflow");
    const toClean = [];
    let l = key.length;
    let k;
    let sigma;
    if (l === 32) {
      toClean.push(k = copyBytes(key));
      sigma = sigma32_32;
    } else if (l === 16 && allowShortKeys) {
      k = new Uint8Array(32);
      k.set(key);
      k.set(key, 16);
      sigma = sigma16_32;
      toClean.push(k);
    } else {
      abytes(key, 32, "arx key");
      throw new Error("invalid key size");
    }
    if (!isLE || !isAligned32(nonce))
      toClean.push(nonce = copyBytes(nonce));
    let k32 = u32(k);
    if (extendNonceFn) {
      if (nonce.length !== 24)
        throw new Error("arx: extended nonce must be 24 bytes");
      const n16 = nonce.subarray(0, 16);
      if (isLE)
        extendNonceFn(sigma, k32, u32(n16), k32);
      else {
        const sigmaRaw = swap32IfBE(Uint32Array.from(sigma));
        extendNonceFn(sigmaRaw, k32, u32(n16), k32);
        clean(sigmaRaw);
        swap32IfBE(k32);
      }
      nonce = nonce.subarray(16);
    } else if (!isLE)
      swap32IfBE(k32);
    const nonceNcLen = 16 - counterLength;
    if (nonceNcLen !== nonce.length)
      throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
    if (nonceNcLen !== 12) {
      const nc = new Uint8Array(12);
      nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
      nonce = nc;
      toClean.push(nonce);
    }
    const n32 = swap32IfBE(u32(nonce));
    try {
      runCipher(core, sigma, k32, n32, data, output, counter, rounds);
      return output;
    } finally {
      clean(...toClean);
    }
  };
}

// node_modules/@noble/ciphers/_poly1305.js
function u8to16(a, i) {
  return a[i++] & 255 | (a[i++] & 255) << 8;
}
var Poly1305 = class {
  blockLen = 16;
  outputLen = 16;
  buffer = new Uint8Array(16);
  r = new Uint16Array(10);
  // Allocating 1 array with .subarray() here is slower than 3
  h = new Uint16Array(10);
  pad = new Uint16Array(8);
  pos = 0;
  finished = false;
  destroyed = false;
  // Can be speed-up using BigUint64Array, at the cost of complexity
  constructor(key) {
    key = copyBytes(abytes(key, 32, "key"));
    const t0 = u8to16(key, 0);
    const t1 = u8to16(key, 2);
    const t2 = u8to16(key, 4);
    const t3 = u8to16(key, 6);
    const t4 = u8to16(key, 8);
    const t5 = u8to16(key, 10);
    const t6 = u8to16(key, 12);
    const t7 = u8to16(key, 14);
    this.r[0] = t0 & 8191;
    this.r[1] = (t0 >>> 13 | t1 << 3) & 8191;
    this.r[2] = (t1 >>> 10 | t2 << 6) & 7939;
    this.r[3] = (t2 >>> 7 | t3 << 9) & 8191;
    this.r[4] = (t3 >>> 4 | t4 << 12) & 255;
    this.r[5] = t4 >>> 1 & 8190;
    this.r[6] = (t4 >>> 14 | t5 << 2) & 8191;
    this.r[7] = (t5 >>> 11 | t6 << 5) & 8065;
    this.r[8] = (t6 >>> 8 | t7 << 8) & 8191;
    this.r[9] = t7 >>> 5 & 127;
    for (let i = 0; i < 8; i++)
      this.pad[i] = u8to16(key, 16 + 2 * i);
  }
  process(data, offset, isLast = false) {
    const hibit = isLast ? 0 : 1 << 11;
    const { h, r } = this;
    const r0 = r[0];
    const r1 = r[1];
    const r2 = r[2];
    const r3 = r[3];
    const r4 = r[4];
    const r5 = r[5];
    const r6 = r[6];
    const r7 = r[7];
    const r8 = r[8];
    const r9 = r[9];
    const t0 = u8to16(data, offset + 0);
    const t1 = u8to16(data, offset + 2);
    const t2 = u8to16(data, offset + 4);
    const t3 = u8to16(data, offset + 6);
    const t4 = u8to16(data, offset + 8);
    const t5 = u8to16(data, offset + 10);
    const t6 = u8to16(data, offset + 12);
    const t7 = u8to16(data, offset + 14);
    let h0 = h[0] + (t0 & 8191);
    let h1 = h[1] + ((t0 >>> 13 | t1 << 3) & 8191);
    let h2 = h[2] + ((t1 >>> 10 | t2 << 6) & 8191);
    let h3 = h[3] + ((t2 >>> 7 | t3 << 9) & 8191);
    let h4 = h[4] + ((t3 >>> 4 | t4 << 12) & 8191);
    let h5 = h[5] + (t4 >>> 1 & 8191);
    let h6 = h[6] + ((t4 >>> 14 | t5 << 2) & 8191);
    let h7 = h[7] + ((t5 >>> 11 | t6 << 5) & 8191);
    let h8 = h[8] + ((t6 >>> 8 | t7 << 8) & 8191);
    let h9 = h[9] + (t7 >>> 5 | hibit);
    let c = 0;
    let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
    c = d0 >>> 13;
    d0 &= 8191;
    d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
    c += d0 >>> 13;
    d0 &= 8191;
    let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
    c = d1 >>> 13;
    d1 &= 8191;
    d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
    c += d1 >>> 13;
    d1 &= 8191;
    let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
    c = d2 >>> 13;
    d2 &= 8191;
    d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
    c += d2 >>> 13;
    d2 &= 8191;
    let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9);
    c = d3 >>> 13;
    d3 &= 8191;
    d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
    c += d3 >>> 13;
    d3 &= 8191;
    let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    c = d4 >>> 13;
    d4 &= 8191;
    d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
    c += d4 >>> 13;
    d4 &= 8191;
    let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
    c = d5 >>> 13;
    d5 &= 8191;
    d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
    c += d5 >>> 13;
    d5 &= 8191;
    let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
    c = d6 >>> 13;
    d6 &= 8191;
    d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
    c += d6 >>> 13;
    d6 &= 8191;
    let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
    c = d7 >>> 13;
    d7 &= 8191;
    d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
    c += d7 >>> 13;
    d7 &= 8191;
    let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
    c = d8 >>> 13;
    d8 &= 8191;
    d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
    c += d8 >>> 13;
    d8 &= 8191;
    let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
    c = d9 >>> 13;
    d9 &= 8191;
    d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
    c += d9 >>> 13;
    d9 &= 8191;
    c = (c << 2) + c | 0;
    c = c + d0 | 0;
    d0 = c & 8191;
    c = c >>> 13;
    d1 += c;
    h[0] = d0;
    h[1] = d1;
    h[2] = d2;
    h[3] = d3;
    h[4] = d4;
    h[5] = d5;
    h[6] = d6;
    h[7] = d7;
    h[8] = d8;
    h[9] = d9;
  }
  finalize() {
    const { h, pad } = this;
    const g = new Uint16Array(10);
    let c = h[1] >>> 13;
    h[1] &= 8191;
    for (let i = 2; i < 10; i++) {
      h[i] += c;
      c = h[i] >>> 13;
      h[i] &= 8191;
    }
    h[0] += c * 5;
    c = h[0] >>> 13;
    h[0] &= 8191;
    h[1] += c;
    c = h[1] >>> 13;
    h[1] &= 8191;
    h[2] += c;
    g[0] = h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 8191;
    for (let i = 1; i < 10; i++) {
      g[i] = h[i] + c;
      c = g[i] >>> 13;
      g[i] &= 8191;
    }
    g[9] -= 1 << 13;
    let mask = (c ^ 1) - 1;
    for (let i = 0; i < 10; i++)
      g[i] &= mask;
    mask = ~mask;
    for (let i = 0; i < 10; i++)
      h[i] = h[i] & mask | g[i];
    h[0] = (h[0] | h[1] << 13) & 65535;
    h[1] = (h[1] >>> 3 | h[2] << 10) & 65535;
    h[2] = (h[2] >>> 6 | h[3] << 7) & 65535;
    h[3] = (h[3] >>> 9 | h[4] << 4) & 65535;
    h[4] = (h[4] >>> 12 | h[5] << 1 | h[6] << 14) & 65535;
    h[5] = (h[6] >>> 2 | h[7] << 11) & 65535;
    h[6] = (h[7] >>> 5 | h[8] << 8) & 65535;
    h[7] = (h[8] >>> 8 | h[9] << 5) & 65535;
    let f = h[0] + pad[0];
    h[0] = f & 65535;
    for (let i = 1; i < 8; i++) {
      f = (h[i] + pad[i] | 0) + (f >>> 16) | 0;
      h[i] = f & 65535;
    }
    clean(g);
  }
  update(data) {
    aexists(this);
    abytes(data);
    data = copyBytes(data);
    const { buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(data, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(buffer, 0, false);
        this.pos = 0;
      }
    }
    return this;
  }
  destroy() {
    this.destroyed = true;
    clean(this.h, this.r, this.buffer, this.pad);
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, h } = this;
    let { pos } = this;
    if (pos) {
      buffer[pos++] = 1;
      for (; pos < 16; pos++)
        buffer[pos] = 0;
      this.process(buffer, 0, true);
    }
    this.finalize();
    let opos = 0;
    for (let i = 0; i < 8; i++) {
      out[opos++] = h[i] >>> 0;
      out[opos++] = h[i] >>> 8;
    }
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
};
var poly1305 = /* @__PURE__ */ wrapMacConstructor(32, (key) => new Poly1305(key));

// node_modules/@noble/ciphers/chacha.js
function chachaCore(s, k, n, out, cnt, rounds = 20) {
  let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let r = 0; r < rounds; r += 2) {
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 7);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 7);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 7);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 7);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 7);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 7);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 7);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 7);
  }
  let oi = 0;
  out[oi++] = y00 + x00 | 0;
  out[oi++] = y01 + x01 | 0;
  out[oi++] = y02 + x02 | 0;
  out[oi++] = y03 + x03 | 0;
  out[oi++] = y04 + x04 | 0;
  out[oi++] = y05 + x05 | 0;
  out[oi++] = y06 + x06 | 0;
  out[oi++] = y07 + x07 | 0;
  out[oi++] = y08 + x08 | 0;
  out[oi++] = y09 + x09 | 0;
  out[oi++] = y10 + x10 | 0;
  out[oi++] = y11 + x11 | 0;
  out[oi++] = y12 + x12 | 0;
  out[oi++] = y13 + x13 | 0;
  out[oi++] = y14 + x14 | 0;
  out[oi++] = y15 + x15 | 0;
}
var chacha20 = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  allowShortKeys: false
});
var ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
var updatePadded = (h, msg) => {
  h.update(msg);
  const leftover = msg.length % 16;
  if (leftover)
    h.update(ZEROS16.subarray(leftover));
};
var ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
function computeTag(fn, key, nonce, ciphertext, AAD) {
  if (AAD !== void 0)
    abytes(AAD, void 0, "AAD");
  const authKey = fn(key, nonce, ZEROS32);
  const lengths = u64Lengths(ciphertext.length, AAD ? AAD.length : 0, true);
  const h = poly1305.create(authKey);
  if (AAD)
    updatePadded(h, AAD);
  updatePadded(h, ciphertext);
  h.update(lengths);
  const res = h.digest();
  clean(authKey, lengths);
  return res;
}
var _poly1305_aead = (xorStream) => (key, nonce, AAD) => {
  const tagLength = 16;
  return {
    encrypt(plaintext, output) {
      const plength = plaintext.length;
      output = getOutput(plength + tagLength, output, false);
      output.set(plaintext);
      const oPlain = output.subarray(0, -tagLength);
      xorStream(key, nonce, oPlain, oPlain, 1);
      const tag = computeTag(xorStream, key, nonce, oPlain, AAD);
      output.set(tag, plength);
      clean(tag);
      return output;
    },
    decrypt(ciphertext, output) {
      output = getOutput(ciphertext.length - tagLength, output, false);
      const data = ciphertext.subarray(0, -tagLength);
      const passedTag = ciphertext.subarray(-tagLength);
      const tag = computeTag(xorStream, key, nonce, data, AAD);
      if (!equalBytes(passedTag, tag)) {
        clean(tag);
        throw new Error("invalid tag");
      }
      output.set(ciphertext.subarray(0, -tagLength));
      xorStream(key, nonce, output, output, 1);
      clean(tag);
      return output;
    }
  };
};
var chacha20poly1305 = /* @__PURE__ */ wrapCipher(
  { blockSize: 64, nonceLength: 12, tagLength: 16, withAAD: true },
  /* @__PURE__ */ _poly1305_aead(chacha20)
);

// src/crypt5.ts
var MARKER = "asajzqxt";
var RSA_N = "x1KI0JR-rT9gwb0OSBuDjOajW-T7BdLhsel6CbJyRKmcKnKedB1LVTpjRr2YbQBBtb_RwUKcCfXJJnltCJzfO9cfKhAP21ihUunXND3jQUs06gdLmwskbmGhjGu23vYo_AOmezo4iJWXHhOhM3Jzw5NRdadlehuyUIDv3bozrhPWOb_IkODSRwVOw_sqcDTYPGTiC5vYLNcaB-J2t8_AgEKiYUOWa-TDNM2XOv9jnATPIVju2rKr5o25RcQbOKLm7ISiSyGTe3WmWgbGQDLZcs32xfykb7zrvc6UtXNe7IscUd7vATdfvM167X2p1MHBVj0Ou0zhhArZSFo6muc8_h5E_fHnEHqcPovIaW99CE7f1jY2p7KADUhCepw55JnE9vIvmiPV0nnoP6E8oCMLhoIND-Od9_hqOd4Kimhhu-5D-LmYIjGl9uLtRseKfaXXKjfttv66-z4lzryULVhOO0Mh14IAu4BhBLkOA5VjRAsTAerLse4oMf6qHjS3lmayBdpG7s0h8QM4MEyRoNcABZ3ccMNyJRYe2uIPdj-hheGkQPW3_LMfdhthQnxcSyg6NqNhZUuwF66feyY1cSsPSnk2_b1TBxTappOfpvBsuDjEDWshXlwd6uSmxAvSiTxwSHU5yzYOH1zxBnJgqrq7KdrCNVUWCcTkf479JYIDB8E";
var ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
var LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
var encoder = new TextEncoder();
function b64(bytes) {
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text);
}
function b64urlBytes(value) {
  const text = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(text, (c) => c.charCodeAt(0));
}
function randomChars(alphabet, count) {
  const bytes = crypto.getRandomValues(new Uint8Array(count));
  return Uint8Array.from(bytes, (b) => alphabet.charCodeAt(b % alphabet.length));
}
function swapPairs(value) {
  const out = value.slice();
  for (let i = 0; i + 1 < out.length; i += 2) [out[i], out[i + 1]] = [out[i + 1], out[i]];
  return out;
}
function blockSwap(value) {
  const out = value.slice();
  for (let i = 0; i + 3 < out.length; i += 4) {
    [out[i], out[i + 2]] = [out[i + 2], out[i]];
    [out[i + 1], out[i + 3]] = [out[i + 3], out[i + 1]];
  }
  return out;
}
function toBigInt(bytes) {
  let n = 0n;
  for (const byte of bytes) n = n << 8n | BigInt(byte);
  return n;
}
function toBytes(value, size) {
  const out = new Uint8Array(size);
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(value & 255n);
    value >>= 8n;
  }
  return out;
}
function modPow(base, exponent, modulus) {
  let out = 1n;
  while (exponent) {
    if (exponent & 1n) out = out * base % modulus;
    base = base * base % modulus;
    exponent >>= 1n;
  }
  return out;
}
function rsaEncrypt(data) {
  const modulus = toBigInt(b64urlBytes(RSA_N));
  const size = 512;
  if (data.length > size - 11) throw new Error("crypt5 RSA payload too long");
  const ps = new Uint8Array(size - data.length - 3);
  do {
    crypto.getRandomValues(ps);
  } while (ps.some((x) => x === 0));
  const padded = new Uint8Array(size);
  padded[1] = 2;
  padded.set(ps, 2);
  padded[2 + ps.length] = 0;
  padded.set(data, 3 + ps.length);
  return toBytes(modPow(toBigInt(padded), 65537n, modulus), size);
}
function encryptHappCrypt5(plaintext) {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const salt = randomChars(ALNUM, 8);
  const tag = randomChars(LETTERS, 2);
  const nonce = randomChars(ALNUM, 12);
  const rsaValue = Uint8Array.from(key, (b, i) => b ^ salt[i % salt.length]);
  const rsaBlob = b64(rsaEncrypt(swapPairs(encoder.encode(b64(rsaValue)))));
  const encrypted = chacha20poly1305(key, nonce).encrypt(swapPairs(encoder.encode(b64(encoder.encode(plaintext)))));
  const encryptedB64 = b64(encrypted);
  const body = encoder.encode(String.fromCharCode(...nonce) + String.fromCharCode(...tag) + String.fromCharCode(...salt) + encryptedB64.length + ":" + encryptedB64 + rsaBlob);
  const pre = encoder.encode(MARKER.slice(0, 4) + String.fromCharCode(...body) + MARKER.slice(4));
  return "happ://crypt5/" + String.fromCharCode(...blockSwap(pre));
}

// src/index.ts
var PRODUCTS = {
  premium: { 1: 250, 3: 660, 6: 1200, 12: 2160 }
};
var DURATIONS = [1, 3, 6, 12];
var MEMBER_STATUSES = /* @__PURE__ */ new Set(["creator", "administrator", "member"]);
var HAPP_SUBSCRIPTION_ENDPOINT = "https://telegram-vpn-bot.bobritogusingo.workers.dev/subscription/{INSTALL_CODE}";
var WORKER_URL = "https://telegram-vpn-bot.bobritogusingo.workers.dev";
function happConfig(env, _plan) {
  const keys = ["HAPP_PREMIUM_PROVIDER_CODE", "HAPP_PREMIUM_AUTH_KEY"];
  requireConfig(env, keys);
  const limit = env.HAPP_INSTALL_LIMIT ? Number(env.HAPP_INSTALL_LIMIT) : 2;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("HAPP_INSTALL_LIMIT must be an integer from 1 to 100");
  const base = env.HAPP_INSTALL_URL_BASE?.trim() || void 0;
  const [providerKey, authKey] = keys;
  return { provider: env[providerKey], auth: env[authKey], limit, base };
}
function randomInstallCode() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}
function findField(value, names) {
  if (!value || typeof value !== "object") return void 0;
  const record = value;
  for (const name of names) if (record[name] !== void 0) return record[name];
  for (const child of Object.values(record)) {
    const found = findField(child, names);
    if (found !== void 0) return found;
  }
  return void 0;
}
function buildHappPlainLink(code) {
  const url = HAPP_SUBSCRIPTION_ENDPOINT.replace("{INSTALL_CODE}", encodeURIComponent(code));
  return `${url}#BananchikiVpn?installid=${encodeURIComponent(code)}`;
}
function buildHappLink(_sourceUrl, code) {
  return encryptHappCrypt5(buildHappPlainLink(code));
}
function parseHappInstall(payload, fallbackCode, base) {
  const rc = findField(payload, ["rc"]);
  if (rc !== void 0 && ![1, "1", true, "success", "ok"].includes(rc)) throw new Error(`Happ rejected install creation: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
  const rawId = findField(payload, ["id", "install_id", "installId"]);
  const rawCode = findField(payload, ["install_code", "installCode", "code"]);
  const rawLink = findField(payload, ["url", "link", "install_url", "installUrl", "subscription_url", "subscriptionUrl"]);
  const id = Number(rawId);
  const code = typeof rawCode === "string" ? rawCode : fallbackCode;
  const link = typeof rawLink === "string" ? rawLink : base ? buildHappLink(base, code) : "";
  if (!Number.isSafeInteger(id) || id <= 0 || !code || !link) throw new Error("Happ response did not contain a usable install id and public link; configure HAPP_INSTALL_URL_BASE with the original subscription URL");
  return { id, code, link };
}
async function happRequest(env, plan, path, method = "GET", body) {
  const config = happConfig(env, plan);
  const url = new URL(`https://happ-proxy.com${path}`);
  url.searchParams.set("provider_code", config.provider);
  url.searchParams.set("auth_key", config.auth);
  const response = await fetch(url, { method, headers: body ? { "content-type": "application/json" } : void 0, ...body ? { body: JSON.stringify(body) } : {} });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Happ returned non-JSON response (${response.status})`);
  }
  if (!response.ok) throw new Error(`Happ HTTP error: ${response.status}`);
  return payload;
}
var happSubscriptionProvider = {
  async ensureSubscription(env, subscription, note) {
    const config = happConfig(env, subscription.plan);
    if (subscription.happ_install_id && subscription.happ_install_link) {
      const payload = await happRequest(env, subscription.plan, `/api/update-install?id=${encodeURIComponent(String(subscription.happ_install_id))}&status=10`);
      const rc = findField(payload, ["rc"]);
      if (rc !== void 0 && ![0, "0", 1, "1", true, "success", "ok"].includes(rc)) throw new Error(`Happ rejected install activation: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
      const code2 = subscription.happ_install_code ?? "";
      const link = code2 && config.base ? buildHappLink(config.base, code2) : subscription.happ_install_link;
      return { id: subscription.happ_install_id, code: code2, link };
    }
    const code = subscription.happ_install_code ?? randomInstallCode();
    const path = `/api/add-install?install_limit=${config.limit}&install_code=${encodeURIComponent(code)}&note=${encodeURIComponent(note)}`;
    return parseHappInstall(await happRequest(env, subscription.plan, path), code, config.base);
  },
  async disableSubscription(env, plan, id) {
    const payload = await happRequest(env, plan, `/api/update-install?id=${encodeURIComponent(String(id))}&status=5`);
    const rc = findField(payload, ["rc"]);
    if (rc !== void 0 && ![0, "0", true, "success", "ok"].includes(rc)) throw new Error(`Happ rejected install disable: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
  }
};
async function reissueHappSubscription(env, userId, plan) {
  const previous = await getActiveSubscription(env, userId, plan);
  if (!previous) throw new Error(`No active ${plan.toUpperCase()} subscription to reissue`);
  const config = happConfig(env, plan);
  const code = randomInstallCode();
  const payload = await happRequest(
    env,
    plan,
    `/api/add-install?install_limit=${config.limit}&install_code=${encodeURIComponent(code)}&note=${encodeURIComponent("User-requested Happ reissue")}`
  );
  const replacement = parseHappInstall(payload, code, config.base);
  const result = await env.DB.prepare(
    `UPDATE subscriptions
     SET happ_install_id = ?, happ_install_code = ?, happ_install_link = ?, happ_status = 'active', happ_last_error = NULL, updated_at = datetime('now')
     WHERE user_id = ? AND plan = ? AND expiration_at IS NOT NULL AND expiration_at > datetime('now')`
  ).bind(replacement.id, replacement.code, replacement.link, userId, plan).run();
  if (Number(result.meta.changes ?? 0) !== 1) {
    try {
      await happSubscriptionProvider.disableSubscription(env, plan, replacement.id);
    } catch (error) {
      console.error("Could not disable unused replacement Happ install", error);
    }
    throw new Error("Subscription changed while the replacement link was being created");
  }
  if (previous.happ_install_id) {
    try {
      await happSubscriptionProvider.disableSubscription(env, plan, previous.happ_install_id);
    } catch (error) {
      console.error(`Could not disable previous Happ install ${previous.happ_install_id}`, error);
    }
  }
}
async function getSubscription(env, userId, plan) {
  return env.DB.prepare("SELECT * FROM subscriptions WHERE user_id = ? AND plan = ?").bind(userId, plan).first();
}
async function getActiveSubscription(env, userId, plan) {
  return env.DB.prepare("SELECT * FROM subscriptions WHERE user_id = ? AND plan = ? AND expiration_at IS NOT NULL AND expiration_at > datetime('now')").bind(userId, plan).first();
}
function isRenewalSubscription(subscription) {
  if (!subscription?.expiration_at) return false;
  const expiration = (/* @__PURE__ */ new Date(`${subscription.expiration_at.replace(" ", "T")}Z`)).getTime();
  return Number.isFinite(expiration) && expiration > Date.now() - 7 * 864e5;
}
async function deliverSubscription(env, userId, plan, note) {
  let reservation = await getActiveSubscription(env, userId, plan);
  if (!reservation) throw new Error(`No active ${plan.toUpperCase()} subscription to deliver`);
  if (!reservation.happ_install_id) {
    const code = reservation.happ_install_code ?? randomInstallCode();
    const result = await env.DB.prepare(
      `UPDATE subscriptions SET happ_install_code = ?, happ_status = 'creating', updated_at = datetime('now')
       WHERE user_id = ? AND plan = ? AND happ_install_id IS NULL
         AND (happ_status IS NULL OR happ_status = 'error'
              OR (happ_status = 'creating' AND updated_at <= datetime('now', '-5 minutes')))
         AND expiration_at IS NOT NULL AND expiration_at > datetime('now')`
    ).bind(code, userId, plan).run();
    if (Number(result.meta.changes ?? 0) === 0) {
      const fresh = await getActiveSubscription(env, userId, plan);
      if (fresh?.happ_install_id && fresh.happ_install_link) return fresh.happ_install_link;
      throw new Error(`${plan.toUpperCase()} Happ installation is being created; retry delivery`);
    }
    reservation = await getActiveSubscription(env, userId, plan) ?? reservation;
  }
  try {
    const install = await happSubscriptionProvider.ensureSubscription(env, reservation, note);
    await env.DB.prepare(`UPDATE subscriptions SET happ_install_id = ?, happ_install_code = ?, happ_install_link = ?, happ_status = 'active', updated_at = datetime('now') WHERE user_id = ? AND plan = ?`).bind(install.id, install.code, install.link, userId, plan).run();
    return install.link;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await env.DB.prepare(
      "UPDATE subscriptions SET happ_status = 'error', happ_last_error = ?, updated_at = datetime('now') WHERE user_id = ? AND plan = ? AND happ_status = 'creating'"
    ).bind(message.slice(0, 1e3), userId, plan).run();
    throw error;
  }
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}
function textResponse(body, status = 200) {
  return new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}
async function fetchPremiumSource(env) {
  const sourceUrl = happConfig(env, "premium").base;
  if (!sourceUrl) throw new Error("HAPP_INSTALL_URL_BASE is required");
  const source = new URL(sourceUrl);
  if (source.protocol !== "https:" || source.username || source.password) throw new Error("Invalid Happ subscription source URL");
  const response = await fetch(source.toString(), { headers: { accept: "application/json, text/plain;q=0.9, */*;q=0.1" } });
  if (!response.ok) throw new Error(`Subscription source failed: ${response.status}`);
  return response;
}
function makeExpiredSubscriptionNotice(sourceText) {
  const parsed = JSON.parse(sourceText);
  if (!Array.isArray(parsed) || parsed.length === 0 || !parsed[0] || typeof parsed[0] !== "object") {
    throw new Error("Premium source is not a JSON subscription array");
  }
  const template = parsed[0];
  const notices = ["\u26D4 \u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 \u0437\u0430\u043A\u043E\u043D\u0447\u0438\u043B\u0430\u0441\u044C", "\u{1F504} \u0415\u0451 \u043C\u043E\u0436\u043D\u043E \u043F\u0440\u043E\u0434\u043B\u0438\u0442\u044C", "\u{1F916} \u0412 \u043D\u0430\u0448\u0435\u043C \u0431\u043E\u0442\u0435"];
  return JSON.stringify(notices.map((remarks) => {
    const notice = JSON.parse(JSON.stringify(template));
    notice.remarks = remarks;
    if (!Array.isArray(notice.outbounds) || notice.outbounds.length === 0) throw new Error("Premium source has no outbounds");
    notice.outbounds = notice.outbounds.map((outbound) => {
      const tag = outbound && typeof outbound === "object" ? outbound.tag : void 0;
      if (typeof tag !== "string" || tag.length === 0) throw new Error("Premium source has an invalid outbound tag");
      return { tag, protocol: "blackhole" };
    });
    return notice;
  }));
}
async function serveHappSubscription(env, installCode) {
  if (!/^[A-Za-z0-9]{8,128}$/.test(installCode)) return textResponse("Not found", 404);
  const subscription = await env.DB.prepare(
    `SELECT expiration_at, happ_status FROM subscriptions
     WHERE plan = 'premium' AND happ_install_code = ? AND expiration_at IS NOT NULL`
  ).bind(installCode).first();
  if (!subscription?.expiration_at) return textResponse("Subscription inactive", 403);
  const expiresAt = (/* @__PURE__ */ new Date(`${subscription.expiration_at.replace(" ", "T")}Z`)).getTime();
  if (!Number.isFinite(expiresAt)) throw new Error("Invalid subscription expiry");
  const source = await fetchPremiumSource(env);
  const headers = new Headers();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  if (expiresAt <= Date.now()) {
    const sourceText = await source.text();
    return new Response(makeExpiredSubscriptionNotice(sourceText), { status: 200, headers });
  }
  if (subscription.happ_status !== "active") return textResponse("Subscription inactive", 403);
  headers.set("content-type", source.headers.get("content-type") || "application/json; charset=utf-8");
  headers.set("subscription-userinfo", `expire=${Math.floor(expiresAt / 1e3)}`);
  return new Response(source.body, { status: 200, headers });
}
function escapeHtml(value) {
  return value.replace(/[&<>"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[character]);
}
async function yoomoneyPaymentPage(env, orderId, paymentType) {
  requireConfig(env, ["YOOMONEY_RECEIVER"]);
  if (paymentType !== "AC" && paymentType !== "PC") return textResponse("Payment method not found", 404);
  const order = await env.DB.prepare("SELECT id, amount_rub, status FROM orders WHERE id = ?").bind(orderId).first();
  if (!order) return textResponse("Order not found", 404);
  if (order.status !== "pending") return textResponse("\u042D\u0442\u043E\u0442 \u0437\u0430\u043A\u0430\u0437 \u0443\u0436\u0435 \u043E\u043F\u043B\u0430\u0447\u0435\u043D \u0438\u043B\u0438 \u043E\u0442\u043C\u0435\u043D\u0451\u043D. \u0412\u0435\u0440\u043D\u0438\u0442\u0435\u0441\u044C \u0432 \u0431\u043E\u0442, \u0447\u0442\u043E\u0431\u044B \u0441\u043E\u0437\u0434\u0430\u0442\u044C \u043D\u043E\u0432\u044B\u0439 \u0437\u0430\u043A\u0430\u0437.", 409);
  const fields = {
    receiver: env.YOOMONEY_RECEIVER,
    label: order.id,
    "quickpay-form": "button",
    paymentType,
    sum: String(order.amount_rub),
    targets: "\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 PREMIUM"
  };
  const inputs = Object.entries(fields).map(
    ([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`
  ).join("");
  const methodName = paymentType === "AC" ? "\u043A\u0430\u0440\u0442\u043E\u0439" : "\u0438\u0437 \u043A\u043E\u0448\u0435\u043B\u044C\u043A\u0430 \u042EMoney";
  return new Response(`<!doctype html><html lang="ru"><meta charset="utf-8"><title>\u041F\u0435\u0440\u0435\u0445\u043E\u0434 \u043A \u043E\u043F\u043B\u0430\u0442\u0435</title><body><p>\u041F\u0435\u0440\u0435\u043D\u0430\u043F\u0440\u0430\u0432\u043B\u044F\u0435\u043C \u043A \u043E\u043F\u043B\u0430\u0442\u0435 ${methodName}\u2026</p><form id="payment" method="post" action="https://yoomoney.ru/quickpay/confirm.xml">${inputs}<button type="submit">\u041F\u0435\u0440\u0435\u0439\u0442\u0438 \u043A \u043E\u043F\u043B\u0430\u0442\u0435</button></form><script>document.getElementById('payment').submit()<\/script></body></html>`, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }
  });
}
function requireConfig(env, keys) {
  for (const key of keys) {
    const value = env[key];
    if (typeof value !== "string" || value.trim() === "" || value.includes("REPLACE_WITH")) {
      throw new Error(`Missing configuration: ${String(key)}`);
    }
  }
}
async function telegramApi(env, method, payload) {
  requireConfig(env, ["TELEGRAM_BOT_TOKEN"]);
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  if (!response.ok || !data.ok) {
    throw new Error(`Telegram ${method} failed: ${data.description ?? response.status}`);
  }
  return data.result;
}
async function sendMessage(env, chatId, text, replyMarkup) {
  await telegramApi(env, "sendMessage", {
    chat_id: chatId,
    text,
    ...replyMarkup ? { reply_markup: replyMarkup } : {}
  });
}
function protectedLinkBlock(link) {
  return `<blockquote expandable><code>${escapeHtml(link)}</code></blockquote>`;
}
function happPlatformKeyboard(showReissue = false, showDevices = false) {
  const rows = [
    [
      { text: "\u{1F916} Android \u2014 Happ", callback_data: "happ:android" },
      { text: "\u{1F34E} iPhone/iPad \u2014 Happ", callback_data: "happ:ios" }
    ]
  ];
  if (showDevices) rows.push([{ text: "\u{1F4F1} \u0423\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430", callback_data: "happ:devices" }]);
  if (showReissue) rows.push([{ text: "\u{1F504} \u041F\u0435\u0440\u0435\u0432\u044B\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0441\u0441\u044B\u043B\u043A\u0443", callback_data: "happ:reissue" }]);
  rows.push([{ text: "\u{1F4D6} \u041D\u0443\u0436\u043D\u0430 \u0438\u043D\u0441\u0442\u0440\u0443\u043A\u0446\u0438\u044F", callback_data: "happ:guide" }]);
  return { inline_keyboard: rows };
}
async function sendSubscriptionChoice(env, chatId, header, showReissue = false, showDevices = false) {
  await telegramApi(env, "sendMessage", {
    chat_id: chatId,
    text: `${escapeHtml(header)}

\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u043E \u2014 \u0431\u043E\u0442 \u043F\u0440\u0438\u0448\u043B\u0451\u0442 \u043F\u043E\u0434\u0445\u043E\u0434\u044F\u0449\u0443\u044E \u0441\u0441\u044B\u043B\u043A\u0443.`,
    parse_mode: "HTML",
    reply_markup: happPlatformKeyboard(showReissue, showDevices)
  });
}
async function sendSubscriptionLink(env, chatId, header, link) {
  await telegramApi(env, "sendMessage", {
    chat_id: chatId,
    text: `${escapeHtml(header)}

${protectedLinkBlock(link)}`,
    parse_mode: "HTML",
    reply_markup: { inline_keyboard: [[{ text: "\u{1F4D6} \u041D\u0443\u0436\u043D\u0430 \u0438\u043D\u0441\u0442\u0440\u0443\u043A\u0446\u0438\u044F", callback_data: "happ:guide" }]] }
  });
}
async function sendPlatformSubscriptionLink(env, chatId, telegramId, platform) {
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  const config = happConfig(env, "premium");
  if (!subscription?.happ_install_code || !config.base) {
    await sendMessage(env, chatId, "\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043D\u0430\u0439\u0442\u0438 \u0430\u043A\u0442\u0438\u0432\u043D\u0443\u044E \u0441\u0441\u044B\u043B\u043A\u0443. \u041E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 /menu \u0435\u0449\u0451 \u0440\u0430\u0437 \u0447\u0435\u0440\u0435\u0437 \u043C\u0438\u043D\u0443\u0442\u0443.");
    return;
  }
  const link = platform === "android" ? buildHappLink(config.base, subscription.happ_install_code) : buildHappPlainLink(subscription.happ_install_code);
  const device = platform === "android" ? "Android (Happ)" : "iPhone/iPad (Happ)";
  await sendSubscriptionLink(env, chatId, `\u0421\u0441\u044B\u043B\u043A\u0430 \u0434\u043B\u044F ${device}:`, link);
}
var deviceActionTableReady = null;
async function ensureDeviceActionTable(env) {
  if (!deviceActionTableReady) {
    deviceActionTableReady = env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS happ_device_actions (
        token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, install_code TEXT NOT NULL,
        hwid TEXT NOT NULL, expires_at TEXT NOT NULL
      )`
    ).run().then(() => void 0).catch((error) => {
      deviceActionTableReady = null;
      throw error;
    });
  }
  await deviceActionTableReady;
}
function collectHappDevices(value, output = /* @__PURE__ */ new Map()) {
  if (Array.isArray(value)) {
    for (const item of value) collectHappDevices(item, output);
  } else if (value && typeof value === "object") {
    const record = value;
    const hwid = typeof record.hwid === "string" ? record.hwid.trim() : "";
    const rawName = record.device_name ?? record.deviceName;
    const name = typeof rawName === "string" && rawName.trim() ? rawName.trim() : null;
    if (hwid) {
      const previous = output.get(hwid);
      output.set(hwid, { hwid, name: name ?? previous?.name ?? null });
    }
    for (const item of Object.values(record)) collectHappDevices(item, output);
  }
  return output;
}
async function listHappDevices(env, subscription) {
  if (!subscription.happ_install_code && !subscription.happ_install_id) return [];
  const selector = subscription.happ_install_code ? `install_code=${encodeURIComponent(subscription.happ_install_code)}` : `install_id=${encodeURIComponent(String(subscription.happ_install_id))}`;
  const payload = await happRequest(env, subscription.plan, `/api/list-hwid?${selector}`);
  const rc = findField(payload, ["rc"]);
  if (rc !== void 0 && ![1, "1", true, "success", "ok"].includes(rc)) {
    throw new Error(`Happ rejected device list: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
  }
  return [...collectHappDevices(payload).values()];
}
function deviceLabel(device) {
  return device.name ?? "\u041D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u043E\u0435 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u043E";
}
async function sendHappDevices(env, chatId, telegramId) {
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  if (!subscription?.happ_install_code) {
    await sendMessage(env, chatId, "\u0410\u043A\u0442\u0438\u0432\u043D\u0430\u044F \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 \u0438\u043B\u0438 \u0435\u0451 \u0441\u0441\u044B\u043B\u043A\u0430 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u0430. \u041E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 /menu \u0435\u0449\u0451 \u0440\u0430\u0437 \u0447\u0435\u0440\u0435\u0437 \u043C\u0438\u043D\u0443\u0442\u0443.");
    return;
  }
  const devices = await listHappDevices(env, subscription);
  const limit = happConfig(env, "premium").limit;
  if (devices.length === 0) {
    await sendMessage(env, chatId, `\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0451\u043D\u043D\u044B\u0445 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432 \u043D\u0435\u0442. \u0414\u043E\u0441\u0442\u0443\u043F\u043D\u043E: ${limit} \u0438\u0437 ${limit}.`);
    return;
  }
  await ensureDeviceActionTable(env);
  const rows = [];
  for (const device of devices) {
    const token = randomInstallCode();
    await env.DB.prepare(
      `INSERT OR REPLACE INTO happ_device_actions (token, user_id, install_code, hwid, expires_at)
       VALUES (?, ?, ?, ?, datetime('now', '+10 minutes'))`
    ).bind(token, telegramId, subscription.happ_install_code, device.hwid).run();
    rows.push([{ text: `\u041E\u0442\u043A\u043B\u044E\u0447\u0438\u0442\u044C ${deviceLabel(device)}`, callback_data: `happ:device:remove:${token}` }]);
  }
  await sendMessage(env, chatId, `\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0451\u043D\u043D\u044B\u0435 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430: ${devices.length} \u0438\u0437 ${limit}

\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u043E, \u043A\u043E\u0442\u043E\u0440\u043E\u0435 \u0445\u043E\u0442\u0438\u0442\u0435 \u043E\u0442\u043A\u043B\u044E\u0447\u0438\u0442\u044C:`, { inline_keyboard: rows });
}
async function removeHappDevice(env, telegramId, token) {
  if (!/^[A-Za-z0-9]{12}$/.test(token)) return false;
  await ensureDeviceActionTable(env);
  const action = await env.DB.prepare(
    `SELECT token, install_code, hwid FROM happ_device_actions
     WHERE token = ? AND user_id = ? AND expires_at > datetime('now')`
  ).bind(token, telegramId).first();
  if (!action) return false;
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  if (!subscription?.happ_install_code || subscription.happ_install_code !== action.install_code) return false;
  const devices = await listHappDevices(env, subscription);
  if (!devices.some((device) => device.hwid === action.hwid)) return false;
  const payload = await happRequest(
    env,
    subscription.plan,
    `/api/delete-hwid?install_code=${encodeURIComponent(subscription.happ_install_code)}&hwid=${encodeURIComponent(action.hwid)}`
  );
  const rc = findField(payload, ["rc"]);
  if (rc !== void 0 && ![1, "1", true, "success", "ok"].includes(rc)) {
    throw new Error(`Happ rejected device removal: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
  }
  await env.DB.prepare("DELETE FROM happ_device_actions WHERE token = ?").bind(token).run();
  return true;
}
async function answerCallback(env, callbackQueryId, text) {
  try {
    await telegramApi(env, "answerCallbackQuery", {
      callback_query_id: callbackQueryId,
      ...text ? { text } : {}
    });
  } catch (error) {
    console.error("answerCallbackQuery failed", error);
  }
}
async function upsertUser(env, user) {
  await env.DB.prepare(
    `INSERT INTO users (telegram_id, username, first_name)
     VALUES (?, ?, ?)
     ON CONFLICT(telegram_id) DO UPDATE SET
       username = excluded.username,
       first_name = excluded.first_name,
       updated_at = datetime('now')`
  ).bind(user.id, user.username ?? null, user.first_name ?? null).run();
}
async function getUser(env, telegramId) {
  return env.DB.prepare("SELECT * FROM users WHERE telegram_id = ?").bind(telegramId).first();
}
async function isChannelMember(env, telegramId) {
  try {
    requireConfig(env, ["CHANNEL_ID"]);
    const member = await telegramApi(env, "getChatMember", {
      chat_id: env.CHANNEL_ID,
      user_id: telegramId
    });
    return MEMBER_STATUSES.has(member.status) || member.status === "restricted" && member.is_member === true;
  } catch (error) {
    console.error(`getChatMember failed for channel ${env.CHANNEL_ID}: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}
function membershipKeyboard(env) {
  const buttons = [];
  if (env.CHANNEL_INVITE_URL && !env.CHANNEL_INVITE_URL.includes("REPLACE_WITH")) {
    buttons.push([{ text: "\u041F\u043E\u0434\u043F\u0438\u0441\u0430\u0442\u044C\u0441\u044F \u043D\u0430 \u043A\u0430\u043D\u0430\u043B", url: env.CHANNEL_INVITE_URL }]);
  }
  buttons.push([{ text: "\u042F \u043F\u043E\u0434\u043F\u0438\u0441\u0430\u043B\u0441\u044F \u2014 \u043F\u0440\u043E\u0432\u0435\u0440\u0438\u0442\u044C", callback_data: "check_membership" }]);
  return { inline_keyboard: buttons };
}
async function sendMembershipPrompt(env, chatId) {
  const invite = env.CHANNEL_INVITE_URL && !env.CHANNEL_INVITE_URL.includes("REPLACE_WITH") ? `
\u0421\u0441\u044B\u043B\u043A\u0430 \u043D\u0430 \u043A\u0430\u043D\u0430\u043B: ${env.CHANNEL_INVITE_URL}` : "";
  await sendMessage(
    env,
    chatId,
    `\u0427\u0442\u043E\u0431\u044B \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u044C\u0441\u044F \u0431\u043E\u0442\u043E\u043C, \u043F\u043E\u0434\u043F\u0438\u0448\u0438\u0442\u0435\u0441\u044C \u043D\u0430 \u043D\u0430\u0448 \u043A\u0430\u043D\u0430\u043B, \u0430 \u0437\u0430\u0442\u0435\u043C \u043D\u0430\u0436\u043C\u0438\u0442\u0435 \xAB\u042F \u043F\u043E\u0434\u043F\u0438\u0441\u0430\u043B\u0441\u044F \u2014 \u043F\u0440\u043E\u0432\u0435\u0440\u0438\u0442\u044C\xBB.${invite}`,
    membershipKeyboard(env)
  );
}
async function ensureMembership(env, chatId, telegramId) {
  const member = await isChannelMember(env, telegramId);
  if (!member) await sendMembershipPrompt(env, chatId);
  return member;
}
function planKeyboard() {
  return { inline_keyboard: [
    [{ text: "\u0412\u044B\u0431\u0440\u0430\u0442\u044C \u0441\u0440\u043E\u043A Premium", callback_data: "plan:premium" }],
    [{ text: "\u041F\u043E\u043F\u0440\u043E\u0431\u043E\u0432\u0430\u0442\u044C \u0431\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u043E \u2014 3 \u0434\u043D\u044F", callback_data: "trial" }]
  ] };
}
function durationKeyboard(plan) {
  return {
    inline_keyboard: DURATIONS.map((duration) => [
      { text: `${duration} \u043C\u0435\u0441. \u2014 ${PRODUCTS[plan][duration]} \u20BD`, callback_data: `duration:${plan}:${duration}` }
    ])
  };
}
function adminKeyboard() {
  return { inline_keyboard: [
    [{ text: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u0441\u043A\u0438\u0434\u043E\u0447\u043D\u044B\u0439 \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434", callback_data: "admin:promo:discount" }],
    [{ text: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u043D\u0430 \u0434\u043D\u0438", callback_data: "admin:promo:days" }],
    [{ text: "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u0431\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u044B\u0435 \u0434\u043D\u0438", callback_data: "admin:promo:free_days" }],
    [{ text: "\u{1F4CB} \u0421\u043F\u0438\u0441\u043E\u043A \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434\u043E\u0432", callback_data: "admin:promo:hub" }]
  ] };
}
function isAdmin(env, telegramId) {
  return Boolean(env.ADMIN_TELEGRAM_ID && String(telegramId) === env.ADMIN_TELEGRAM_ID);
}
function normalizePromoCode(value) {
  const code = value.trim().toUpperCase();
  return /^[A-Z0-9_-]{3,32}$/.test(code) ? code : null;
}
function promoPrice(days, discountPercent) {
  return Math.max(1, Math.round(250 * days / 30 * (100 - discountPercent) / 100));
}
function parsePromoExpiry(value) {
  if (!value) return null;
  const match = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(value);
  if (!match) return void 0;
  const [, dayText, monthText, yearText] = match;
  const day = Number(dayText);
  const month = Number(monthText);
  const year = Number(yearText);
  const check = new Date(Date.UTC(year, month - 1, day));
  if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) return void 0;
  return `${yearText}-${monthText}-${dayText} 20:59:59`;
}
async function setInputSession(env, userId, kind) {
  await env.DB.prepare(`INSERT INTO input_sessions (user_id, kind, expires_at)
    VALUES (?, ?, datetime('now', '+10 minutes'))
    ON CONFLICT(user_id) DO UPDATE SET kind = excluded.kind, expires_at = excluded.expires_at`).bind(userId, kind).run();
}
async function takeInputSession(env, userId) {
  const session = await env.DB.prepare("SELECT kind, expires_at FROM input_sessions WHERE user_id = ? AND expires_at > datetime('now')").bind(userId).first();
  if (session) await env.DB.prepare("DELETE FROM input_sessions WHERE user_id = ?").bind(userId).run();
  return session ?? null;
}
async function getPromoCode(env, code) {
  return env.DB.prepare(`SELECT code, discount_percent, duration_days, max_activations, activation_count, active, free_grant,
      unlimited_activations, expires_at
    FROM promo_codes
    WHERE code = ? AND active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`).bind(code).first();
}
async function reservePromo(env, userId, code) {
  const existing = await env.DB.prepare("SELECT code FROM promo_reservations WHERE user_id = ?").bind(userId).first();
  if (existing) {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM promo_reservations WHERE user_id = ?").bind(userId),
      env.DB.prepare("UPDATE promo_codes SET activation_count = MAX(0, activation_count - 1), updated_at = datetime('now') WHERE code = ?").bind(existing.code)
    ]);
  }
  const result = await env.DB.prepare(`UPDATE promo_codes SET activation_count = activation_count + 1, updated_at = datetime('now')
    WHERE code = ? AND active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
      AND (unlimited_activations = 1 OR activation_count < max_activations)
      AND NOT EXISTS (SELECT 1 FROM orders WHERE promo_code = ? AND user_id = ? AND status = 'paid')
      AND NOT EXISTS (SELECT 1 FROM activation_logs WHERE user_id = ? AND details LIKE ?)`).bind(code, code, userId, userId, `Free promo ${code}:%`).run();
  if (Number(result.meta.changes ?? 0) !== 1) return false;
  await env.DB.batch([
    env.DB.prepare("INSERT INTO promo_reservations (user_id, code) VALUES (?, ?)").bind(userId, code),
    // Entries are audit data only; they must never lock a user out after an
    // unfinished checkout.
    env.DB.prepare("INSERT OR IGNORE INTO promo_entries (promo_code, user_id) VALUES (?, ?)").bind(code, userId)
  ]);
  return true;
}
function formatPromoExpiry(expiresAt) {
  return expiresAt ? expiresAt.slice(0, 10).split("-").reverse().join(".") : "\u0431\u0435\u0437 \u0434\u0430\u0442\u044B \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F";
}
function formatPromoLimit(promo) {
  return promo.unlimited_activations === 1 ? "\u221E" : String(promo.max_activations);
}
function promoKind(promo) {
  if (promo.free_grant === 1) return `${promo.duration_days} \u0431\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u044B\u0445 \u0434\u043D\u0435\u0439`;
  return promo.duration_days ? `${promo.duration_days} \u0434\u043D\u0435\u0439, \u0441\u043A\u0438\u0434\u043A\u0430 ${promo.discount_percent}%` : `\u0441\u043A\u0438\u0434\u043A\u0430 ${promo.discount_percent}%`;
}
function promoCurrentWhere(alias = "") {
  const p = alias ? `${alias}.` : "";
  return `${p}active = 1 AND (${p}expires_at IS NULL OR ${p}expires_at > datetime('now')) AND (${p}unlimited_activations = 1 OR ${p}activation_count < ${p}max_activations)`;
}
function promoExpiredWhere(alias = "") {
  const p = alias ? `${alias}.` : "";
  return `NOT (${promoCurrentWhere(alias)}) AND COALESCE(CASE WHEN ${p}expires_at IS NOT NULL AND ${p}expires_at <= datetime('now') THEN ${p}expires_at ELSE ${p}updated_at END, ${p}created_at) > datetime('now', '-3 days')`;
}
async function sendPromoHub(env, chatId) {
  const [current, expired] = await env.DB.batch([
    env.DB.prepare(`SELECT COUNT(*) AS count FROM promo_codes p WHERE ${promoCurrentWhere("p")}`),
    env.DB.prepare(`SELECT COUNT(*) AS count FROM promo_codes p WHERE ${promoExpiredWhere("p")}`)
  ]);
  const currentCount = Number(current.results?.[0]?.count ?? 0);
  const expiredCount = Number(expired.results?.[0]?.count ?? 0);
  await sendMessage(env, chatId, "\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434\u044B", { inline_keyboard: [
    [{ text: `\u2705 \u0414\u0435\u0439\u0441\u0442\u0432\u0443\u044E\u0449\u0438\u0435 (${currentCount})`, callback_data: "admin:promo:list:current:0" }],
    [{ text: `\u231B \u0418\u0441\u0442\u0451\u043A\u0448\u0438\u0435 \u0437\u0430 3 \u0434\u043D\u044F (${expiredCount})`, callback_data: "admin:promo:list:expired:0" }]
  ] });
}
async function sendPromoList(env, chatId, category, page) {
  const safePage = Math.max(0, Math.min(1e3, page));
  const pageSize = 10;
  const where = category === "current" ? promoCurrentWhere("p") : promoExpiredWhere("p");
  const countRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM promo_codes p WHERE ${where}`).first();
  const total = Number(countRow?.count ?? 0);
  const title = category === "current" ? "\u0414\u0435\u0439\u0441\u0442\u0432\u0443\u044E\u0449\u0438\u0435 \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434\u044B" : "\u0418\u0441\u0442\u0451\u043A\u0448\u0438\u0435 \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434\u044B \u0437\u0430 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u0435 3 \u0434\u043D\u044F";
  if (total === 0) {
    await sendMessage(env, chatId, `${title}: \u043D\u0435\u0442.`);
    return;
  }
  const lastPage = Math.max(0, Math.ceil(total / pageSize) - 1);
  const currentPage = Math.min(safePage, lastPage);
  const result = await env.DB.prepare(`SELECT p.code, p.discount_percent, p.duration_days, p.max_activations, p.activation_count, p.active, p.free_grant,
      p.unlimited_activations, p.expires_at, p.created_at, p.updated_at,
      (SELECT COUNT(*) FROM orders o WHERE o.promo_code = p.code AND o.status = 'paid') AS paid_orders
    FROM promo_codes p WHERE ${where}
    ORDER BY p.updated_at DESC, p.created_at DESC, p.code ASC LIMIT ? OFFSET ?`).bind(pageSize, currentPage * pageSize).all();
  const rows = result.results.map((promo) => [{
    text: `${category === "current" ? "\u2705" : "\u231B"} ${promo.code} \xB7 ${promo.activation_count}/${formatPromoLimit(promo)}`,
    callback_data: `admin:promo:view:${promo.code}:${category}`
  }]);
  const navigation = [];
  if (currentPage > 0) navigation.push({ text: "\u2039 \u041D\u0430\u0437\u0430\u0434", callback_data: `admin:promo:list:${category}:${currentPage - 1}` });
  if (currentPage < lastPage) navigation.push({ text: "\u0412\u043F\u0435\u0440\u0451\u0434 \u203A", callback_data: `admin:promo:list:${category}:${currentPage + 1}` });
  if (navigation.length) rows.push(navigation);
  rows.push([{ text: "\u2039 \u041A \u0440\u0430\u0437\u0434\u0435\u043B\u0430\u043C", callback_data: "admin:promo:hub" }]);
  await sendMessage(env, chatId, `${title}: ${total}
\u0421\u0442\u0440\u0430\u043D\u0438\u0446\u0430 ${currentPage + 1} \u0438\u0437 ${lastPage + 1}

\u041D\u0430\u0436\u043C\u0438\u0442\u0435 \u043D\u0430 \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434, \u0447\u0442\u043E\u0431\u044B \u043E\u0442\u043A\u0440\u044B\u0442\u044C \u0438\u043D\u0444\u043E\u0440\u043C\u0430\u0446\u0438\u044E:`, { inline_keyboard: rows });
}
async function getPromoEnteredUsers(env, code) {
  const result = await env.DB.prepare(`SELECT e.user_id, u.username, u.first_name, e.entered_at AS used_at, '\u0432\u0432\u0451\u043B \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434' AS usage_type
    FROM promo_entries e JOIN users u ON u.telegram_id = e.user_id
    WHERE e.promo_code = ? ORDER BY e.entered_at DESC LIMIT 20`).bind(code).all();
  return result.results;
}
async function getPromoPurchasers(env, code) {
  const result = await env.DB.prepare(`SELECT user_id, username, first_name, used_at, usage_type FROM (
      SELECT o.user_id, u.username, u.first_name, o.paid_at AS used_at, '\u043E\u043F\u043B\u0430\u0442\u0438\u043B \u0437\u0430\u043A\u0430\u0437' AS usage_type
      FROM orders o JOIN users u ON u.telegram_id = o.user_id
      WHERE o.promo_code = ? AND o.status = 'paid'
      UNION ALL
      SELECT a.user_id, u.username, u.first_name, a.created_at AS used_at, '\u043F\u043E\u043B\u0443\u0447\u0438\u043B \u0431\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u044B\u0435 \u0434\u043D\u0438' AS usage_type
      FROM activation_logs a JOIN users u ON u.telegram_id = a.user_id WHERE a.details LIKE ?
    ) ORDER BY used_at DESC LIMIT 1000`).bind(code, `Free promo ${code}:%`).all();
  return result.results;
}
async function formatPromoPeople(env, users, emptyText) {
  if (!users.length) return emptyText;
  const lines = [];
  for (const user of users) {
    const subscription = await getSubscription(env, user.user_id, "premium");
    let devices = "\u043D\u0435\u0442 \u0434\u0430\u043D\u043D\u044B\u0445";
    if (subscription?.happ_install_code || subscription?.happ_install_id) {
      try {
        const happDevices = await listHappDevices(env, subscription);
        devices = happDevices.length ? happDevices.map(deviceLabel).join(", ") : "\u043D\u0435\u0442";
      } catch {
        devices = "\u043D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043F\u043E\u043B\u0443\u0447\u0438\u0442\u044C";
      }
    }
    const account = user.username ? `@${user.username}` : user.first_name ? escapeHtml(user.first_name) : "\u0431\u0435\u0437 \u0438\u043C\u0435\u043D\u0438";
    lines.push(`\u2022 ${account} \xB7 ID <code>${user.user_id}</code>
  ${user.usage_type}; ${formatPromoExpiry(user.used_at)}
  \u0423\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430: ${escapeHtml(devices)}`);
  }
  return lines.join("\n");
}
function formatPaidPromoUsersQuotes(users) {
  if (!users.length) return ["\u041F\u043E\u043A\u0430 \u043D\u0435\u0442 \u0443\u0441\u043F\u0435\u0448\u043D\u044B\u0445 \u043F\u043E\u043A\u0443\u043F\u043E\u043A \u0438\u043B\u0438 \u0432\u044B\u0434\u0430\u0447."];
  const chunks = [];
  let lines = [];
  let length = 0;
  for (const user of users) {
    const account = user.username ? `@${escapeHtml(user.username)}` : user.first_name ? escapeHtml(user.first_name) : "\u0431\u0435\u0437 \u0438\u043C\u0435\u043D\u0438";
    const line = `\u2022 ${account} \xB7 <code>${user.user_id}</code> \u2014 ${user.usage_type}`;
    if (lines.length && length + line.length + 1 > 3e3) {
      chunks.push(`<blockquote expandable>${lines.join("\n")}</blockquote>`);
      lines = [];
      length = 0;
    }
    lines.push(line);
    length += line.length + 1;
  }
  if (lines.length) chunks.push(`<blockquote expandable>${lines.join("\n")}</blockquote>`);
  return chunks;
}
async function sendPromoInfo(env, chatId, code, category = "current") {
  const promo = await env.DB.prepare(`SELECT p.code, p.discount_percent, p.duration_days, p.max_activations, p.activation_count,
      p.active, p.free_grant, p.unlimited_activations, p.expires_at, p.created_at, p.updated_at,
      (SELECT COUNT(*) FROM orders o WHERE o.promo_code = p.code AND o.status = 'paid') AS paid_orders
    FROM promo_codes p WHERE p.code = ?`).bind(code).first();
  if (!promo) {
    await sendMessage(env, chatId, "\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D.");
    return;
  }
  const current = promo.active === 1 && (promo.expires_at === null || (/* @__PURE__ */ new Date(`${promo.expires_at.replace(" ", "T")}Z`)).getTime() > Date.now()) && (promo.unlimited_activations === 1 || promo.activation_count < promo.max_activations);
  const status = current ? "\u0430\u043A\u0442\u0438\u0432\u0435\u043D" : "\u0438\u0441\u0442\u0451\u043A \u0438\u043B\u0438 \u043E\u0442\u043A\u043B\u044E\u0447\u0451\u043D";
  const [enteredUsers, purchasers] = await Promise.all([
    getPromoEnteredUsers(env, promo.code),
    getPromoPurchasers(env, promo.code)
  ]);
  const entered = await formatPromoPeople(env, enteredUsers, "\u041F\u043E\u043A\u0430 \u043D\u0438\u043A\u0442\u043E \u043D\u0435 \u0432\u0432\u043E\u0434\u0438\u043B \u043A\u043E\u0434.");
  const enteredQuote = enteredUsers.length ? `<blockquote expandable>${entered}</blockquote>` : entered;
  const paidUserQuotes = formatPaidPromoUsersQuotes(purchasers);
  const back = `admin:promo:list:${category}:0`;
  const keyboard = current ? { inline_keyboard: [[{ text: "\u{1F5D1} \u0423\u0434\u0430\u043B\u0438\u0442\u044C \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434", callback_data: `admin:promo:delete:${promo.code}` }], [{ text: "\u{1F4CB} \u041A \u0441\u043F\u0438\u0441\u043A\u0443", callback_data: back }]] } : { inline_keyboard: [[{ text: "\u{1F4CB} \u041A \u0441\u043F\u0438\u0441\u043A\u0443", callback_data: back }]] };
  await telegramApi(env, "sendMessage", {
    chat_id: chatId,
    parse_mode: "HTML",
    text: `\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434: <code>${escapeHtml(promo.code)}</code>

\u0421\u0442\u0430\u0442\u0443\u0441: ${status}
\u0423\u0441\u043B\u043E\u0432\u0438\u044F: ${escapeHtml(promoKind(promo))}
\u0410\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u0438: ${promo.activation_count} \u0438\u0437 ${formatPromoLimit(promo)}
\u041E\u043F\u043B\u0430\u0447\u0435\u043D\u043D\u044B\u0435 \u043F\u043E\u043A\u0443\u043F\u043A\u0438: ${promo.paid_orders}
\u0414\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u0434\u043E: ${formatPromoExpiry(promo.expires_at)}
\u0421\u043E\u0437\u0434\u0430\u043D: ${formatPromoExpiry(promo.created_at)}

<b>\u041A\u0442\u043E \u0432\u0432\u0451\u043B \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434:</b>
${enteredQuote}

<b>\u041A\u0442\u043E \u043A\u0443\u043F\u0438\u043B \u0438\u043B\u0438 \u043F\u043E\u043B\u0443\u0447\u0438\u043B \u0434\u043D\u0438:</b>
${paidUserQuotes[0]}`,
    reply_markup: keyboard
  });
  for (let index = 1; index < paidUserQuotes.length; index += 1) {
    await telegramApi(env, "sendMessage", {
      chat_id: chatId,
      parse_mode: "HTML",
      text: `<b>\u041A\u0442\u043E \u043A\u0443\u043F\u0438\u043B \u0438\u043B\u0438 \u043F\u043E\u043B\u0443\u0447\u0438\u043B \u0434\u043D\u0438 \u2014 \u043F\u0440\u043E\u0434\u043E\u043B\u0436\u0435\u043D\u0438\u0435:</b>
${paidUserQuotes[index]}`
    });
  }
}
async function takePromoReservation(env, userId, code) {
  const result = await env.DB.prepare("DELETE FROM promo_reservations WHERE user_id = ? AND code = ?").bind(userId, code).run();
  return Number(result.meta.changes ?? 0) === 1;
}
async function sendPlans(env, chatId, telegramId) {
  const user = await getUser(env, telegramId);
  const trialText = user?.trial_activated ? "\n\u041F\u0440\u043E\u0431\u043D\u044B\u0439 \u043F\u0435\u0440\u0438\u043E\u0434 \u0443\u0436\u0435 \u0430\u043A\u0442\u0438\u0432\u0438\u0440\u043E\u0432\u0430\u043D." : "\n\u0414\u043E\u0441\u0442\u0443\u043F\u0435\u043D \u0431\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u044B\u0439 \u043F\u0440\u043E\u0431\u043D\u044B\u0439 \u043F\u0435\u0440\u0438\u043E\u0434 \u043D\u0430 3 \u0434\u043D\u044F (\u043E\u0434\u0438\u043D \u0440\u0430\u0437 \u043D\u0430 \u0430\u043A\u043A\u0430\u0443\u043D\u0442).";
  await sendMessage(
    env,
    chatId,
    `Premium \u2014 \u0435\u0434\u0438\u043D\u0430\u044F \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 \u0431\u0435\u0437 \u043B\u0438\u0448\u043D\u0438\u0445 \u0440\u0430\u0437\u0432\u0438\u043B\u043E\u043A.${trialText}

\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0443 \u043C\u043E\u0436\u043D\u043E \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u043D\u0430 2 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430.

\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0443\u0434\u043E\u0431\u043D\u044B\u0439 \u0441\u0440\u043E\u043A \u0438\u043B\u0438 \u043D\u0430\u0447\u043D\u0438\u0442\u0435 \u0441 \u0442\u0440\u0451\u0445 \u0431\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u044B\u0445 \u0434\u043D\u0435\u0439.`,
    planKeyboard()
  );
}
async function sendSubscriptionStatus(env, chatId, telegramId) {
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  if (!subscription?.expiration_at) {
    await sendMessage(env, chatId, "\u0421\u0435\u0439\u0447\u0430\u0441 \u0443 \u0432\u0430\u0441 \u043D\u0435\u0442 \u0430\u043A\u0442\u0438\u0432\u043D\u043E\u0439 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0438 Premium.");
    return;
  }
  const expiration = /* @__PURE__ */ new Date(`${subscription.expiration_at.replace(" ", "T")}Z`);
  const days = Math.max(1, Math.ceil((expiration.getTime() - Date.now()) / 864e5));
  const date = subscription.expiration_at.slice(0, 10).split("-").reverse().join(".");
  let current = subscription;
  if (!current.happ_install_code) {
    try {
      await deliverSubscription(env, telegramId, "premium", "Regenerated Happ installation");
      current = await getActiveSubscription(env, telegramId, "premium") ?? current;
    } catch (error) {
      console.error(`Could not regenerate Happ installation for ${telegramId}`, error);
    }
  }
  const header = `\u0410\u043A\u0442\u0438\u0432\u043D\u0430\u044F \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0430: Premium
\u041E\u0441\u0442\u0430\u043B\u043E\u0441\u044C: ${days} \u0434\u043D.
\u0414\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u0434\u043E: ${date}`;
  if (current.happ_install_code) await sendSubscriptionChoice(env, chatId, `${header}

\u0412\u0430\u0448\u0430 \u0441\u0441\u044B\u043B\u043A\u0430 Happ:`, true, true);
  else await sendMessage(env, chatId, `${header}

\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043F\u043E\u0434\u0433\u043E\u0442\u043E\u0432\u0438\u0442\u044C \u0441\u0441\u044B\u043B\u043A\u0443. \u041F\u043E\u043F\u0440\u043E\u0431\u0443\u0439\u0442\u0435 \u0441\u043D\u043E\u0432\u0430 \u0447\u0435\u0440\u0435\u0437 \u043C\u0438\u043D\u0443\u0442\u0443.`);
}
async function createYooKassaPayment(env, orderId, amountRub) {
  requireConfig(env, ["YOOKASSA_SHOP_ID", "YOOKASSA_SECRET_KEY"]);
  const authorization = btoa(`${env.YOOKASSA_SHOP_ID}:${env.YOOKASSA_SECRET_KEY}`);
  const response = await fetch("https://api.yookassa.ru/v3/payments", {
    method: "POST",
    headers: { authorization: `Basic ${authorization}`, "content-type": "application/json", "Idempotence-Key": orderId },
    body: JSON.stringify({
      amount: { value: amountRub.toFixed(2), currency: "RUB" },
      capture: true,
      confirmation: { type: "redirect", return_url: `${WORKER_URL}/` },
      metadata: { order_id: orderId }
    })
  });
  let payment;
  try {
    payment = await response.json();
  } catch {
    throw new Error(`YooKassa returned non-JSON response (${response.status})`);
  }
  if (!response.ok) throw new Error(`YooKassa payment creation failed (${response.status})`);
  const confirmation = payment && typeof payment === "object" ? payment.confirmation : null;
  const confirmationUrl = confirmation && typeof confirmation === "object" ? confirmation.confirmation_url : null;
  if (typeof confirmationUrl !== "string" || !confirmationUrl.startsWith("https://")) throw new Error("YooKassa response did not include a valid confirmation URL");
  return confirmationUrl;
}
async function createOrder(env, chatId, telegramId, plan, duration, options) {
  requireConfig(env, ["YOOKASSA_SHOP_ID", "YOOKASSA_SECRET_KEY"]);
  const amount = options?.amountRub ?? PRODUCTS[plan][duration];
  const durationDays = options?.durationDays ?? null;
  const displayPeriod = options?.displayPeriod ?? `${duration} \u043C\u0435\u0441.`;
  const renewal = isRenewalSubscription(await getSubscription(env, telegramId, plan));
  const orderId = crypto.randomUUID();
  const placeholderUrl = `${WORKER_URL}/`;
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO orders (id, user_id, plan, duration_months, duration_days, amount_rub, promo_code, quickpay_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(orderId, telegramId, plan, duration, durationDays, amount, options?.promoCode ?? null, placeholderUrl),
    env.DB.prepare("UPDATE users SET updated_at = datetime('now') WHERE telegram_id = ?").bind(telegramId)
  ]);
  let paymentUrl;
  try {
    paymentUrl = await createYooKassaPayment(env, orderId, amount);
  } catch (error) {
    await env.DB.prepare("UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending'").bind(orderId).run();
    throw error;
  }
  await env.DB.prepare("UPDATE orders SET quickpay_url = ? WHERE id = ? AND status = 'pending'").bind(paymentUrl, orderId).run();
  await sendMessage(
    env,
    chatId,
    `${options?.testOrder ? "\u0422\u0435\u0441\u0442\u043E\u0432\u044B\u0439 \u0437\u0430\u043A\u0430\u0437" : renewal ? "\u0417\u0430\u043A\u0430\u0437 \u043D\u0430 \u043F\u0440\u043E\u0434\u043B\u0435\u043D\u0438\u0435" : "\u041F\u043E\u043A\u0443\u043F\u043A\u0430 Premium"}: ${displayPeriod} \u2014 ${amount} \u20BD.

\u041F\u043E\u0441\u043B\u0435 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043D\u0438\u044F \u043F\u043B\u0430\u0442\u0435\u0436\u0430 \u0431\u043E\u0442 ${renewal ? "\u043F\u0440\u043E\u0434\u043B\u0438\u0442 \u0434\u043E\u0441\u0442\u0443\u043F" : "\u043E\u0444\u043E\u0440\u043C\u0438\u0442 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0443"} \u0438 \u043F\u0440\u0438\u0448\u043B\u0451\u0442 \u0441\u0441\u044B\u043B\u043A\u0443 \u043D\u0430 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0443.`,
    { inline_keyboard: [[{ text: "\u041E\u043F\u043B\u0430\u0442\u0438\u0442\u044C \u0447\u0435\u0440\u0435\u0437 \u042EKassa", url: paymentUrl }]] }
  );
}
async function activateFreePromoDays(env, chatId, telegramId, code, days) {
  const wasActive = isRenewalSubscription(await getSubscription(env, telegramId, "premium"));
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO subscriptions (user_id, plan, expiration_at)
       VALUES (?, 'premium', datetime('now', ?))
       ON CONFLICT(user_id, plan) DO UPDATE SET
         expiration_at = datetime(CASE WHEN subscriptions.expiration_at > datetime('now') THEN subscriptions.expiration_at ELSE datetime('now') END, ?),
         updated_at = datetime('now')`
    ).bind(telegramId, `+${days} days`, `+${days} days`),
    // The existing production schema records non-trial grants as "payment";
    // the details field preserves that this was a free promo issue.
    env.DB.prepare("INSERT INTO activation_logs (user_id, order_id, event_type, details) VALUES (?, NULL, 'payment', ?)").bind(telegramId, `Free promo ${code}: ${days} days`)
  ]);
  await deliverSubscription(env, telegramId, "premium", `Telegram promo ${code}`);
  const status = wasActive ? `\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 \u043F\u0440\u043E\u0434\u043B\u0435\u043D\u0430 \u043D\u0430 ${days} \u0434\u043D\u0435\u0439.` : `Premium \u0430\u043A\u0442\u0438\u0432\u0438\u0440\u043E\u0432\u0430\u043D \u043D\u0430 ${days} \u0434\u043D\u0435\u0439.`;
  await sendSubscriptionChoice(env, chatId, `\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 ${code} \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D \u2014 ${status}

\u0412\u0430\u0448\u0430 \u0441\u0441\u044B\u043B\u043A\u0430 \u043D\u0430 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0443:`);
}
async function activateTrial(env, chatId, telegramId) {
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE subscriptions
       SET happ_install_id = NULL, happ_install_code = NULL, happ_install_link = NULL,
           happ_status = NULL, updated_at = datetime('now')
       WHERE user_id = ? AND plan = 'premium' AND happ_status = 'disabled'
         AND expiration_at IS NOT NULL AND expiration_at <= datetime('now', '-7 days')
         AND EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 0)`
    ).bind(telegramId, telegramId),
    env.DB.prepare(
      `INSERT INTO subscriptions (user_id, plan, expiration_at)
       SELECT ?, 'premium', datetime(
         COALESCE((SELECT CASE WHEN expiration_at > datetime('now') THEN expiration_at ELSE datetime('now') END
                   FROM subscriptions WHERE user_id = ? AND plan = 'premium'), datetime('now')),
         '+3 days'
       )
       WHERE EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 0)
       ON CONFLICT(user_id, plan) DO UPDATE SET
         expiration_at = datetime(CASE WHEN subscriptions.expiration_at > datetime('now') THEN subscriptions.expiration_at ELSE datetime('now') END, '+3 days'),
         updated_at = datetime('now')`
    ).bind(telegramId, telegramId, telegramId),
    env.DB.prepare("UPDATE users SET trial_activated = 1, updated_at = datetime('now') WHERE telegram_id = ? AND trial_activated = 0").bind(telegramId),
    env.DB.prepare(
      `INSERT OR IGNORE INTO activation_logs (user_id, order_id, event_type, details)
       SELECT ?, NULL, 'trial', 'free 3-day Premium trial'
       WHERE EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 1)`
    ).bind(telegramId, telegramId)
  ]);
  const changed = Number(results[2]?.meta?.changes ?? 0) > 0;
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  if (!subscription) {
    await sendMessage(env, chatId, "\u0411\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u044B\u0439 \u043F\u0440\u043E\u0431\u043D\u044B\u0439 \u043F\u0435\u0440\u0438\u043E\u0434 \u0443\u0436\u0435 \u0431\u044B\u043B \u0430\u043A\u0442\u0438\u0432\u0438\u0440\u043E\u0432\u0430\u043D \u0440\u0430\u043D\u0435\u0435.");
    return;
  }
  await deliverSubscription(env, telegramId, "premium", "Telegram Premium trial");
  const prefix = changed ? "\u041F\u0440\u043E\u0431\u043D\u044B\u0439 \u043F\u0435\u0440\u0438\u043E\u0434 \u0430\u043A\u0442\u0438\u0432\u0438\u0440\u043E\u0432\u0430\u043D." : "\u041F\u0440\u043E\u0431\u043D\u044B\u0439 \u043F\u0435\u0440\u0438\u043E\u0434 \u0443\u0436\u0435 \u0430\u043A\u0442\u0438\u0432\u0438\u0440\u043E\u0432\u0430\u043D; \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u043C \u0434\u043E\u0441\u0442\u0443\u043F.";
  await sendSubscriptionChoice(env, chatId, [prefix, "\u0422\u0430\u0440\u0438\u0444: Premium", "\u0421\u0440\u043E\u043A: 3 \u0434\u043D\u044F (\u043F\u0440\u043E\u0431\u043D\u044B\u0439 \u043F\u0435\u0440\u0438\u043E\u0434)", "", "\u0421\u0441\u044B\u043B\u043A\u0430 \u043D\u0430 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0443 Happ:"].join("\n"));
}
var rateLimitTableReady = null;
async function allowTelegramAction(env, userId) {
  if (!rateLimitTableReady) {
    rateLimitTableReady = env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS telegram_rate_limits (user_id INTEGER PRIMARY KEY, window_started_ms INTEGER NOT NULL, action_count INTEGER NOT NULL)"
    ).run().then(() => void 0).catch((error) => {
      rateLimitTableReady = null;
      throw error;
    });
  }
  try {
    await rateLimitTableReady;
    const now = Date.now();
    const result = await env.DB.prepare(
      `INSERT INTO telegram_rate_limits (user_id, window_started_ms, action_count) VALUES (?, ?, 1)
       ON CONFLICT(user_id) DO UPDATE SET
         action_count = CASE WHEN ? - window_started_ms >= 2000 THEN 1 ELSE action_count + 1 END,
         window_started_ms = CASE WHEN ? - window_started_ms >= 2000 THEN excluded.window_started_ms ELSE window_started_ms END
       RETURNING action_count`
    ).bind(userId, now, now, now).first();
    return (result?.action_count ?? 1) <= 3;
  } catch (error) {
    console.error("Rate-limit check failed", error);
    return true;
  }
}
async function rejectFrequentAction(env, chatId) {
  await sendMessage(env, chatId, "\u0421\u043B\u0438\u0448\u043A\u043E\u043C \u0447\u0430\u0441\u0442\u043E. \u041F\u043E\u0434\u043E\u0436\u0434\u0438\u0442\u0435 \u043F\u0430\u0440\u0443 \u0441\u0435\u043A\u0443\u043D\u0434.");
}
function parseDuration(value) {
  const duration = Number(value);
  return DURATIONS.includes(duration) ? duration : null;
}
async function handleCallback(env, callback) {
  const chatId = callback.message?.chat.id ?? callback.from.id;
  const data = callback.data ?? "";
  await upsertUser(env, callback.from);
  await answerCallback(env, callback.id);
  const exemptFromRateLimit = data === "promo:redeem" || data.startsWith("promo_duration:") || data.startsWith("duration:");
  if (!isAdmin(env, callback.from.id) && !exemptFromRateLimit && !await allowTelegramAction(env, callback.from.id)) {
    await rejectFrequentAction(env, chatId);
    return;
  }
  if (data === "admin:promo:hub") {
    if (!isAdmin(env, callback.from.id)) {
      await sendMessage(env, chatId, "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0443.");
      return;
    }
    await sendPromoHub(env, chatId);
    return;
  }
  if (data.startsWith("admin:promo:list:")) {
    if (!isAdmin(env, callback.from.id)) {
      await sendMessage(env, chatId, "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0443.");
      return;
    }
    const [, , , categoryRaw, pageRaw] = data.split(":");
    const category = categoryRaw === "expired" ? "expired" : "current";
    const page = Number(pageRaw);
    await sendPromoList(env, chatId, category, Number.isInteger(page) && page >= 0 ? page : 0);
    return;
  }
  if (data.startsWith("admin:promo:view:")) {
    if (!isAdmin(env, callback.from.id)) {
      await sendMessage(env, chatId, "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0443.");
      return;
    }
    const [, , , codeRaw, categoryRaw] = data.split(":");
    const code = normalizePromoCode(codeRaw ?? "");
    if (!code) {
      await sendMessage(env, chatId, "\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D.");
      return;
    }
    await sendPromoInfo(env, chatId, code, categoryRaw === "expired" ? "expired" : "current");
    return;
  }
  if (data.startsWith("admin:promo:delete:")) {
    if (!isAdmin(env, callback.from.id)) {
      await sendMessage(env, chatId, "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0443.");
      return;
    }
    const code = normalizePromoCode(data.slice("admin:promo:delete:".length));
    if (!code) {
      await sendMessage(env, chatId, "\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D.");
      return;
    }
    const result = await env.DB.prepare("UPDATE promo_codes SET active = 0, updated_at = datetime('now') WHERE code = ? AND active = 1").bind(code).run();
    await sendMessage(env, chatId, Number(result.meta.changes ?? 0) === 1 ? `\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 ${code} \u0443\u0434\u0430\u043B\u0451\u043D \u0438 \u0431\u043E\u043B\u044C\u0448\u0435 \u043D\u0435 \u043F\u0440\u0438\u043C\u0435\u043D\u044F\u0435\u0442\u0441\u044F.` : "\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u0443\u0436\u0435 \u0443\u0434\u0430\u043B\u0451\u043D \u0438\u043B\u0438 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D.");
    return;
  }
  if (data === "admin:promo:discount" || data === "admin:promo:days" || data === "admin:promo:free_days") {
    if (!isAdmin(env, callback.from.id)) {
      await sendMessage(env, chatId, "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0443.");
      return;
    }
    const freeDays = data === "admin:promo:free_days";
    const days = data === "admin:promo:days";
    await setInputSession(env, callback.from.id, freeDays ? "admin_promo_free_days" : days ? "admin_promo_days" : "admin_promo_discount");
    await sendMessage(env, chatId, freeDays ? "\u041E\u0442\u043F\u0440\u0430\u0432\u044C\u0442\u0435: \u041A\u041E\u0414 \u041A\u041E\u041B\u0418\u0427\u0415\u0421\u0422\u0412\u041E_\u0414\u041D\u0415\u0419 \u041A\u041E\u041B\u0418\u0427\u0415\u0421\u0422\u0412\u041E_\u0410\u041A\u0422\u0418\u0412\u0410\u0426\u0418\u0419 [\u0414\u0414.\u041C\u041C.\u0413\u0413\u0413\u0413]\n0 \u0430\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u0439 = \u0431\u0435\u0437 \u043B\u0438\u043C\u0438\u0442\u0430. \u0414\u0430\u0442\u0430 \u043D\u0435\u043E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u0430.\n\u041F\u0440\u0438\u043C\u0435\u0440: GIFT7 7 0 31.12.2026" : days ? "\u041E\u0442\u043F\u0440\u0430\u0432\u044C\u0442\u0435: \u041A\u041E\u0414 \u041A\u041E\u041B\u0418\u0427\u0415\u0421\u0422\u0412\u041E_\u0414\u041D\u0415\u0419 \u0421\u041A\u0418\u0414\u041A\u0410_\u041F\u0420\u041E\u0426\u0415\u041D\u0422\u041E\u0412 \u041A\u041E\u041B\u0418\u0427\u0415\u0421\u0422\u0412\u041E_\u0410\u041A\u0422\u0418\u0412\u0410\u0426\u0418\u0419 [\u0414\u0414.\u041C\u041C.\u0413\u0413\u0413\u0413]\n0 \u0430\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u0439 = \u0431\u0435\u0437 \u043B\u0438\u043C\u0438\u0442\u0430. \u0414\u0430\u0442\u0430 \u043D\u0435\u043E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u0430.\n\u041F\u0440\u0438\u043C\u0435\u0440: PROMO14 14 25 30 31.12.2026" : "\u041E\u0442\u043F\u0440\u0430\u0432\u044C\u0442\u0435: \u041A\u041E\u0414 \u0421\u041A\u0418\u0414\u041A\u0410_\u041F\u0420\u041E\u0426\u0415\u041D\u0422\u041E\u0412 \u041A\u041E\u041B\u0418\u0427\u0415\u0421\u0422\u0412\u041E_\u0410\u041A\u0422\u0418\u0412\u0410\u0426\u0418\u0419 [\u0414\u0414.\u041C\u041C.\u0413\u0413\u0413\u0413]\n0 \u0430\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u0439 = \u0431\u0435\u0437 \u043B\u0438\u043C\u0438\u0442\u0430. \u0414\u0430\u0442\u0430 \u043D\u0435\u043E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u0430.\n\u041F\u0440\u0438\u043C\u0435\u0440: SALE20 20 0 31.12.2026");
    return;
  }
  if (data === "promo:redeem") {
    await setInputSession(env, callback.from.id, "redeem_promo");
    await sendMessage(env, chatId, "\u041E\u0442\u043F\u0440\u0430\u0432\u044C\u0442\u0435 \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u043E\u0434\u043D\u0438\u043C \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0435\u043C.");
    return;
  }
  if (data === "happ:devices") {
    if (!await ensureMembership(env, chatId, callback.from.id)) return;
    try {
      await sendHappDevices(env, chatId, callback.from.id);
    } catch (error) {
      console.error(`Could not list Happ devices for ${callback.from.id}`, error);
      await sendMessage(env, chatId, "\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043F\u043E\u043B\u0443\u0447\u0438\u0442\u044C \u0441\u043F\u0438\u0441\u043E\u043A \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432. \u041F\u043E\u043F\u0440\u043E\u0431\u0443\u0439\u0442\u0435 \u0447\u0435\u0440\u0435\u0437 \u043C\u0438\u043D\u0443\u0442\u0443.");
    }
    return;
  }
  if (data.startsWith("happ:device:remove:")) {
    if (!await ensureMembership(env, chatId, callback.from.id)) return;
    const token = data.slice("happ:device:remove:".length);
    await sendMessage(env, chatId, "\u0412\u044B \u0443\u0432\u0435\u0440\u0435\u043D\u044B?", { inline_keyboard: [[
      { text: "\u0414\u0430", callback_data: `happ:device:confirm:${token}` },
      { text: "\u041D\u0435\u0442", callback_data: "happ:cancel" }
    ]] });
    return;
  }
  if (data.startsWith("happ:device:confirm:")) {
    if (!await ensureMembership(env, chatId, callback.from.id)) return;
    try {
      const removed = await removeHappDevice(env, callback.from.id, data.slice("happ:device:confirm:".length));
      if (!removed) {
        await sendMessage(env, chatId, "\u042D\u0442\u0430 \u043A\u043D\u043E\u043F\u043A\u0430 \u0443\u0441\u0442\u0430\u0440\u0435\u043B\u0430. \u041E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 \xAB\u{1F4F1} \u0423\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430\xBB \u0435\u0449\u0451 \u0440\u0430\u0437.");
        return;
      }
      await sendMessage(env, chatId, "\u0423\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u043E \u043E\u0442\u043A\u043B\u044E\u0447\u0435\u043D\u043E.");
      await sendHappDevices(env, chatId, callback.from.id);
    } catch (error) {
      console.error(`Could not remove Happ device for ${callback.from.id}`, error);
      await sendMessage(env, chatId, "\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043E\u0442\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u043E. \u041F\u043E\u043F\u0440\u043E\u0431\u0443\u0439\u0442\u0435 \u0447\u0435\u0440\u0435\u0437 \u043C\u0438\u043D\u0443\u0442\u0443.");
    }
    return;
  }
  if (data === "happ:reissue") {
    if (!await ensureMembership(env, chatId, callback.from.id)) return;
    await sendMessage(env, chatId, "\u0412\u044B \u0443\u0432\u0435\u0440\u0435\u043D\u044B?", { inline_keyboard: [[
      { text: "\u0414\u0430", callback_data: "happ:reissue:confirm" },
      { text: "\u041D\u0435\u0442", callback_data: "happ:cancel" }
    ]] });
    return;
  }
  if (data === "happ:reissue:confirm") {
    if (!await ensureMembership(env, chatId, callback.from.id)) return;
    try {
      await reissueHappSubscription(env, callback.from.id, "premium");
      await sendSubscriptionChoice(env, chatId, "\u0421\u0441\u044B\u043B\u043A\u0430 \u043F\u0435\u0440\u0435\u0432\u044B\u043F\u0443\u0449\u0435\u043D\u0430. \u0421\u0442\u0430\u0440\u0430\u044F \u0441\u0441\u044B\u043B\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u0435 \u043D\u0435 \u0440\u0430\u0431\u043E\u0442\u0430\u0435\u0442.");
    } catch (error) {
      console.error(`Could not reissue Happ subscription for ${callback.from.id}`, error);
      await sendMessage(env, chatId, "\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043F\u0435\u0440\u0435\u0432\u044B\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0441\u0441\u044B\u043B\u043A\u0443. \u041F\u043E\u043F\u0440\u043E\u0431\u0443\u0439\u0442\u0435 \u0447\u0435\u0440\u0435\u0437 \u043C\u0438\u043D\u0443\u0442\u0443.");
    }
    return;
  }
  if (data === "happ:cancel") {
    await sendMessage(env, chatId, "\u041E\u0442\u043C\u0435\u043D\u0435\u043D\u043E.");
    return;
  }
  if (data === "happ:android" || data === "happ:ios") {
    if (!await ensureMembership(env, chatId, callback.from.id)) return;
    await sendPlatformSubscriptionLink(env, chatId, callback.from.id, data === "happ:android" ? "android" : "ios");
    return;
  }
  if (data === "happ:guide") {
    await sendMessage(
      env,
      chatId,
      "\u041A\u0430\u043A \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C Happ:\n\n1. \u0423\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0435 \u043F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u0435:\n\u2022 Android \u2014 Happ \u0438\u0437 Google Play (Play \u041C\u0430\u0440\u043A\u0435\u0442).\n\u2022 iPhone/iPad (iOS) \u2014 \u043E\u0431\u044B\u0447\u043D\u044B\u0439 Happ \u0438\u0437 App Store.\n\n2. \u0412 \u0431\u043E\u0442\u0435 \u0432\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u043A\u043D\u043E\u043F\u043A\u0443 \u0441\u0432\u043E\u0435\u0433\u043E \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430.\n3. \u041D\u0430\u0436\u043C\u0438\u0442\u0435 \u043D\u0430 \u043C\u043E\u043D\u043E\u0448\u0438\u0440\u0438\u043D\u043D\u0443\u044E \u0441\u0441\u044B\u043B\u043A\u0443 \u2014 \u043E\u043D\u0430 \u0441\u043A\u043E\u043F\u0438\u0440\u0443\u0435\u0442\u0441\u044F \u0432 \u0431\u0443\u0444\u0435\u0440 \u043E\u0431\u043C\u0435\u043D\u0430.\n4. \u041E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 Happ \u0438 \u043D\u0430\u0436\u043C\u0438\u0442\u0435 \xAB+\xBB.\n5. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \xAB\u0418\u043C\u043F\u043E\u0440\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0438\u0437 \u0431\u0443\u0444\u0435\u0440\u0430 \u043E\u0431\u043C\u0435\u043D\u0430\xBB, \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0438 \u0432\u043A\u043B\u044E\u0447\u0438\u0442\u0435 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u0438\u0435.\n\n\u041D\u0435 \u043F\u0435\u0440\u0435\u0434\u0430\u0432\u0430\u0439\u0442\u0435 \u0432\u0430\u0448\u0443 \u0441\u0441\u044B\u043B\u043A\u0443 \u0434\u0440\u0443\u0433\u0438\u043C \u043B\u044E\u0434\u044F\u043C."
    );
    return;
  }
  if (data === "check_membership") {
    if (await ensureMembership(env, chatId, callback.from.id)) {
      await sendMessage(env, chatId, "\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043D\u0430.");
      await sendPlans(env, chatId, callback.from.id);
    }
    return;
  }
  if (!await ensureMembership(env, chatId, callback.from.id)) return;
  if (data === "trial") {
    await activateTrial(env, chatId, callback.from.id);
    return;
  }
  if (data === "plans") {
    await sendPlans(env, chatId, callback.from.id);
    return;
  }
  if (data.startsWith("plan:")) {
    const plan = data.slice("plan:".length);
    if (plan === "premium") {
      await sendMessage(env, chatId, `Premium \u2014 \u0432\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0441\u0440\u043E\u043A \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0438.

\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0443 \u043C\u043E\u0436\u043D\u043E \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u043D\u0430 2 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430:`, durationKeyboard(plan));
    }
    return;
  }
  if (data.startsWith("promo_duration:")) {
    const [, code, durationValue] = data.split(":");
    const promo = code ? await getPromoCode(env, code) : null;
    const duration = durationValue ? parseDuration(durationValue) : null;
    if (!promo || promo.duration_days || !duration) {
      await sendMessage(env, chatId, "\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u043D\u0435\u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0442\u0435\u043B\u0435\u043D.");
      return;
    }
    if (!await takePromoReservation(env, callback.from.id, promo.code)) {
      await sendMessage(env, chatId, "\u0421\u043D\u0430\u0447\u0430\u043B\u0430 \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u0437\u0430\u043D\u043E\u0432\u043E.");
      return;
    }
    const amount = Math.max(1, Math.round(PRODUCTS.premium[duration] * (100 - promo.discount_percent) / 100));
    await createOrder(env, chatId, callback.from.id, "premium", duration, { amountRub: amount, displayPeriod: `${duration} \u043C\u0435\u0441. \u0441\u043E \u0441\u043A\u0438\u0434\u043A\u043E\u0439 ${promo.discount_percent}%`, promoCode: promo.code });
    return;
  }
  if (data.startsWith("duration:")) {
    const [, planValue, durationValue] = data.split(":");
    if (planValue === "premium" && durationValue) {
      const duration = parseDuration(durationValue);
      if (duration) await createOrder(env, chatId, callback.from.id, planValue, duration);
    }
  }
}
function isCommand(text, command) {
  const first = text.trim().split(/\s+/)[0].toLowerCase();
  return first === command || first.startsWith(`${command}@`);
}
async function sendOrders(env, chatId) {
  const result = await env.DB.prepare(
    `SELECT id, user_id, plan, duration_months, amount_rub, status, created_at, paid_at
     FROM orders ORDER BY created_at DESC LIMIT 20`
  ).all();
  if (result.results.length === 0) {
    await sendMessage(env, chatId, "\u0417\u0430\u043A\u0430\u0437\u043E\u0432 \u043F\u043E\u043A\u0430 \u043D\u0435\u0442.");
    return;
  }
  const lines = result.results.map(
    (order) => `${order.status.toUpperCase()} ${order.id}
user ${order.user_id} \xB7 ${order.plan.toUpperCase()} ${order.duration_months}\u043C \xB7 ${order.amount_rub} \u20BD \xB7 ${order.created_at}`
  );
  await sendMessage(env, chatId, `\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u0435 \u0437\u0430\u043A\u0430\u0437\u044B:

${lines.join("\n\n")}`);
}
async function handleMessage(env, message) {
  if (!message.from || !message.text || message.from.is_bot) return;
  const text = message.text.trim();
  await upsertUser(env, message.from);
  const promoInput = isCommand(text, "/promo") || Boolean(await env.DB.prepare(
    "SELECT 1 FROM input_sessions WHERE user_id = ? AND kind = 'redeem_promo' AND expires_at > datetime('now')"
  ).bind(message.from.id).first());
  if (!isAdmin(env, message.from.id) && !promoInput && !await allowTelegramAction(env, message.from.id)) {
    await rejectFrequentAction(env, message.chat.id);
    return;
  }
  if (isCommand(text, "/admin")) {
    await env.DB.prepare("DELETE FROM input_sessions WHERE user_id = ?").bind(message.from.id).run();
    if (!isAdmin(env, message.from.id)) await sendMessage(env, message.chat.id, "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0443.");
    else await sendMessage(env, message.chat.id, "\u0410\u0434\u043C\u0438\u043D-\u043F\u0430\u043D\u0435\u043B\u044C \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434\u043E\u0432:", adminKeyboard());
    return;
  }
  const session = await takeInputSession(env, message.from.id);
  if (session) {
    if (session.kind === "redeem_promo") {
      const code = normalizePromoCode(text);
      const promo = code ? await getPromoCode(env, code) : null;
      if (!promo) {
        await sendMessage(env, message.chat.id, "\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D \u0438\u043B\u0438 \u043E\u0442\u043A\u043B\u044E\u0447\u0451\u043D.");
        return;
      }
      if (!await reservePromo(env, message.from.id, promo.code)) {
        await sendMessage(env, message.chat.id, "\u042D\u0442\u043E\u0442 \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u0443\u0436\u0435 \u0431\u044B\u043B \u0443\u0441\u043F\u0435\u0448\u043D\u043E \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D \u043D\u0430 \u0432\u0430\u0448\u0435\u043C \u0430\u043A\u043A\u0430\u0443\u043D\u0442\u0435 \u0438\u043B\u0438 \u0435\u0433\u043E \u043B\u0438\u043C\u0438\u0442 \u0437\u0430\u043A\u043E\u043D\u0447\u0438\u043B\u0441\u044F.");
        return;
      }
      if (promo.duration_days) {
        if (promo.free_grant === 1) {
          await takePromoReservation(env, message.from.id, promo.code);
          await activateFreePromoDays(env, message.chat.id, message.from.id, promo.code, promo.duration_days);
        } else {
          const amount = promoPrice(promo.duration_days, promo.discount_percent);
          await createOrder(env, message.chat.id, message.from.id, "premium", 1, { amountRub: amount, durationDays: promo.duration_days, displayPeriod: `${promo.duration_days} \u0434\u043D\u0435\u0439 \u0441\u043E \u0441\u043A\u0438\u0434\u043A\u043E\u0439 ${promo.discount_percent}%`, promoCode: promo.code });
          await takePromoReservation(env, message.from.id, promo.code);
        }
      } else {
        const buttons = DURATIONS.map((duration) => [{ text: `${duration} \u043C\u0435\u0441. \u2014 ${Math.max(1, Math.round(PRODUCTS.premium[duration] * (100 - promo.discount_percent) / 100))} \u20BD`, callback_data: `promo_duration:${promo.code}:${duration}` }]);
        await sendMessage(env, message.chat.id, `\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 ${promo.code} \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D: \u0441\u043A\u0438\u0434\u043A\u0430 ${promo.discount_percent}%. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0441\u0440\u043E\u043A:`, { inline_keyboard: buttons });
      }
      return;
    }
    if ((session.kind === "admin_promo_discount" || session.kind === "admin_promo_days" || session.kind === "admin_promo_free_days") && isAdmin(env, message.from.id)) {
      const parts = text.trim().split(/\s+/);
      const code = normalizePromoCode(parts[0] ?? "");
      const freeDays = session.kind === "admin_promo_free_days";
      const hasDays = session.kind === "admin_promo_days" || freeDays;
      const days = hasDays ? Number(parts[1]) : null;
      const percentIndex = session.kind === "admin_promo_days" ? 2 : 1;
      const activationIndex = freeDays ? 2 : session.kind === "admin_promo_days" ? 3 : 2;
      const expiryIndex = activationIndex + 1;
      const expectedParts = [activationIndex + 1, activationIndex + 2];
      const percent = freeDays ? 99 : Number(parts[percentIndex]);
      const activations = Number(parts[activationIndex]);
      const expiry = parsePromoExpiry(parts[expiryIndex]);
      if (!code || !expectedParts.includes(parts.length) || !Number.isInteger(percent) || !freeDays && (percent < 1 || percent > 99) || !Number.isInteger(activations) || activations < 0 || activations > 1e5 || expiry === void 0 || days !== null && (!Number.isInteger(days) || days < 1 || days > 3650)) {
        await sendMessage(env, message.chat.id, freeDays ? "\u041D\u0435\u0432\u0435\u0440\u043D\u044B\u0439 \u0444\u043E\u0440\u043C\u0430\u0442. \u041F\u0440\u0438\u043C\u0435\u0440: GIFT7 7 0 31.12.2026" : session.kind === "admin_promo_days" ? "\u041D\u0435\u0432\u0435\u0440\u043D\u044B\u0439 \u0444\u043E\u0440\u043C\u0430\u0442. \u041F\u0440\u0438\u043C\u0435\u0440: PROMO14 14 25 30 31.12.2026" : "\u041D\u0435\u0432\u0435\u0440\u043D\u044B\u0439 \u0444\u043E\u0440\u043C\u0430\u0442. \u041F\u0440\u0438\u043C\u0435\u0440: SALE20 20 0 31.12.2026");
        return;
      }
      const unlimited = activations === 0 ? 1 : 0;
      const storedLimit = unlimited ? 1 : activations;
      await env.DB.prepare(`INSERT INTO promo_codes (code, discount_percent, duration_days, max_activations, activation_count, active, free_grant, unlimited_activations, expires_at, created_by)
        VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?, ?) ON CONFLICT(code) DO UPDATE SET discount_percent = excluded.discount_percent, duration_days = excluded.duration_days, max_activations = excluded.max_activations, activation_count = 0, active = 1, free_grant = excluded.free_grant, unlimited_activations = excluded.unlimited_activations, expires_at = excluded.expires_at, created_by = excluded.created_by, updated_at = datetime('now')`).bind(code, percent, days, storedLimit, freeDays ? 1 : 0, unlimited, expiry, message.from.id).run();
      const description = freeDays ? `${days} \u0431\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u044B\u0445 \u0434\u043D\u0435\u0439` : days === null ? `\u0441\u043A\u0438\u0434\u043A\u0430 ${percent}% \u043D\u0430 \u043E\u0431\u044B\u0447\u043D\u044B\u0435 \u0442\u0430\u0440\u0438\u0444\u044B` : `${days} \u0434\u043D\u0435\u0439, \u0441\u043A\u0438\u0434\u043A\u0430 ${percent}%, \u0446\u0435\u043D\u0430 ${promoPrice(days, percent)} \u20BD`;
      const limitText = unlimited ? "\u0431\u0435\u0437 \u043B\u0438\u043C\u0438\u0442\u0430" : String(activations);
      const expiryText = expiry ? ` \u0414\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u0434\u043E: ${formatPromoExpiry(expiry)}.` : " \u0411\u0435\u0437 \u0434\u0430\u0442\u044B \u043E\u043A\u043E\u043D\u0447\u0430\u043D\u0438\u044F.";
      await telegramApi(env, "sendMessage", {
        chat_id: message.chat.id,
        text: `\u041F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u0441\u043E\u0437\u0434\u0430\u043D:
<code>${code}</code>

${escapeHtml(description)}. \u0410\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u0439: ${limitText}.${expiryText}`,
        parse_mode: "HTML"
      });
      return;
    }
  }
  if (isCommand(text, "/admin")) {
    if (!isAdmin(env, message.from.id)) await sendMessage(env, message.chat.id, "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0443.");
    else await sendMessage(env, message.chat.id, "\u0410\u0434\u043C\u0438\u043D-\u043F\u0430\u043D\u0435\u043B\u044C \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434\u043E\u0432:", adminKeyboard());
    return;
  }
  if (isCommand(text, "/orders")) {
    if (env.ADMIN_TELEGRAM_ID && String(message.from.id) === env.ADMIN_TELEGRAM_ID) {
      await sendOrders(env, message.chat.id);
    } else {
      await sendMessage(env, message.chat.id, "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430 \u0442\u043E\u043B\u044C\u043A\u043E \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0443.");
    }
    return;
  }
  if (isCommand(text, "/promo")) {
    await setInputSession(env, message.from.id, "redeem_promo");
    await sendMessage(env, message.chat.id, "\u041E\u0442\u043F\u0440\u0430\u0432\u044C\u0442\u0435 \u043F\u0440\u043E\u043C\u043E\u043A\u043E\u0434 \u043E\u0434\u043D\u0438\u043C \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0435\u043C.");
    return;
  }
  if (isCommand(text, "/start")) {
    await sendMessage(env, message.chat.id, "\u041F\u0440\u0438\u0432\u0435\u0442! \u{1F44B}\n\n\u0414\u043E\u0431\u0440\u043E \u043F\u043E\u0436\u0430\u043B\u043E\u0432\u0430\u0442\u044C \u0432 BananchikiVpn. \u0421\u0435\u0440\u0432\u0438\u0441 \u043F\u043E\u043C\u043E\u0433\u0430\u0435\u0442 \u0441 \u0434\u043E\u0441\u0442\u0443\u043F\u043E\u043C \u043A \u0438\u043D\u0442\u0435\u0440\u043D\u0435\u0442\u0443 \u043F\u0440\u0438 \u0431\u0435\u043B\u044B\u0445 \u0441\u043F\u0438\u0441\u043A\u0430\u0445 \u0438 \u043E\u0433\u0440\u0430\u043D\u0438\u0447\u0435\u043D\u0438\u044F\u0445 \u0441\u0435\u0442\u0438.");
    if (!await ensureMembership(env, message.chat.id, message.from.id)) return;
    await sendPlans(env, message.chat.id, message.from.id);
    return;
  }
  if (isCommand(text, "/menu")) {
    if (!await ensureMembership(env, message.chat.id, message.from.id)) return;
    await sendSubscriptionStatus(env, message.chat.id, message.from.id);
    return;
  }
  if (isCommand(text, "/sub")) {
    if (!await ensureMembership(env, message.chat.id, message.from.id)) return;
    await sendMessage(env, message.chat.id, "Premium \u2014 \u0432\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0441\u0440\u043E\u043A \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0438.\n\n\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0443 \u043C\u043E\u0436\u043D\u043E \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u043D\u0430 2 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430:", durationKeyboard("premium"));
    return;
  }
  if (isCommand(text, "/plans") || isCommand(text, "/buy")) {
    if (!await ensureMembership(env, message.chat.id, message.from.id)) return;
    await sendPlans(env, message.chat.id, message.from.id);
    return;
  }
  if (isCommand(text, "/trial")) {
    if (!await ensureMembership(env, message.chat.id, message.from.id)) return;
    await activateTrial(env, message.chat.id, message.from.id);
    return;
  }
  await sendMessage(
    env,
    message.chat.id,
    "\u041D\u0430\u043F\u0438\u0448\u0438\u0442\u0435 /start \u2014 \u044F \u043F\u0440\u043E\u0432\u0435\u0440\u044E \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0443 \u043D\u0430 \u043A\u0430\u043D\u0430\u043B \u0438 \u043F\u043E\u043C\u043E\u0433\u0443 \u043E\u0444\u043E\u0440\u043C\u0438\u0442\u044C Premium. \u041E\u0434\u0438\u043D \u0440\u0430\u0437 \u043C\u043E\u0436\u043D\u043E \u043D\u0430\u0447\u0430\u0442\u044C \u0441 \u0431\u0435\u0441\u043F\u043B\u0430\u0442\u043D\u044B\u0445 \u0442\u0440\u0451\u0445 \u0434\u043D\u0435\u0439."
  );
}
function rubleKopeks(value) {
  if (!/^\d+(?:\.\d{1,2})?$/.test(value)) return null;
  const [whole, fraction = ""] = value.split(".");
  const result = Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
  return Number.isSafeInteger(result) ? result : null;
}
function constantTimeEqual(left, right) {
  let difference = left.length ^ right.length;
  const max = Math.max(left.length, right.length);
  for (let index = 0; index < max; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}
async function sha1Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function signedYoomoneyString(params, secret) {
  return [
    params.get("notification_type") ?? "",
    params.get("operation_id") ?? "",
    params.get("amount") ?? "",
    params.get("currency") ?? "",
    params.get("datetime") ?? "",
    params.get("sender") ?? "",
    params.get("codepro") ?? "",
    secret,
    params.get("label") ?? ""
  ].join("&");
}
async function fulfilPaidOrder(env, order) {
  const buyer = await getUser(env, order.user_id);
  if (!buyer) throw new Error("order owner does not exist");
  const link = await deliverSubscription(env, buyer.telegram_id, order.plan, `YooMoney ${order.plan.toUpperCase()} ${order.duration_months}m`);
  return { buyer, link };
}
async function finalizePaidOrder(env, order, notification) {
  const { operationId, amount, currency, notificationType, paymentDatetime, sender, codepro, label, rawHash } = notification;
  const existingPayment = await env.DB.prepare("SELECT order_id, operation_id FROM payments WHERE operation_id = ?").bind(operationId).first();
  if (existingPayment && existingPayment.order_id !== order.id) throw new Error("operation already belongs to another order");
  if (order.status === "paid") {
    if (order.operation_id === operationId || existingPayment?.order_id === order.id) {
      await fulfilPaidOrder(env, order);
      return "OK";
    }
    throw new Error("order is already paid with another operation");
  }
  if (order.status !== "pending") throw new Error("order is not payable");
  const buyer = await getUser(env, order.user_id);
  if (!buyer) throw new Error("order owner does not exist");
  const renewal = isRenewalSubscription(await getSubscription(env, order.user_id, order.plan));
  const results = await env.DB.batch([
    env.DB.prepare(`INSERT OR IGNORE INTO payments
      (order_id, operation_id, amount, currency, notification_type, payment_datetime, sender, codepro, label, raw_sha1)
      SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM orders WHERE id = ? AND status = 'pending')
      AND NOT EXISTS (SELECT 1 FROM payments WHERE operation_id = ?)`).bind(order.id, operationId, amount, currency, notificationType, paymentDatetime, sender, codepro, label, rawHash, order.id, operationId),
    env.DB.prepare(`UPDATE orders SET status = 'paid', paid_at = datetime('now'), operation_id = ?
      WHERE id = ? AND status = 'pending' AND EXISTS (SELECT 1 FROM payments WHERE operation_id = ? AND order_id = ?)`).bind(operationId, order.id, operationId, order.id),
    env.DB.prepare(`UPDATE subscriptions SET happ_install_id = NULL, happ_install_code = NULL, happ_install_link = NULL,
      happ_status = NULL, updated_at = datetime('now') WHERE user_id = ? AND plan = ? AND happ_status = 'disabled'
      AND expiration_at IS NOT NULL AND expiration_at <= datetime('now', '-7 days')`).bind(order.user_id, order.plan),
    env.DB.prepare(`INSERT INTO subscriptions (user_id, plan, expiration_at) VALUES (?, ?, datetime('now', ?))
      ON CONFLICT(user_id, plan) DO UPDATE SET expiration_at = datetime(CASE WHEN subscriptions.expiration_at > datetime('now')
      THEN subscriptions.expiration_at ELSE datetime('now') END, ?), updated_at = datetime('now')`).bind(order.user_id, order.plan, order.duration_days ? `+${order.duration_days} days` : `+${order.duration_months} months`, order.duration_days ? `+${order.duration_days} days` : `+${order.duration_months} months`),
    env.DB.prepare(`INSERT OR IGNORE INTO activation_logs (user_id, order_id, event_type, details)
      SELECT ?, ?, 'payment', ? WHERE EXISTS (SELECT 1 FROM orders WHERE id = ? AND status = 'paid')`).bind(order.user_id, order.id, `${notificationType} operation ${operationId}`, order.id)
  ]);
  if (Number(results[1]?.meta?.changes ?? 0) === 0) return "OK";
  await fulfilPaidOrder(env, order);
  try {
    const period = order.duration_days ? `${order.duration_days} \u0434\u043D\u0435\u0439` : `${order.duration_months} \u043C\u0435\u0441.`;
    const status = renewal ? `\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 \u043F\u0440\u043E\u0434\u043B\u0435\u043D\u0430 \u043D\u0430 ${period}.` : `Premium \u043E\u0444\u043E\u0440\u043C\u043B\u0435\u043D \u043D\u0430 ${period}.`;
    await sendSubscriptionChoice(env, order.user_id, `\u041E\u043F\u043B\u0430\u0442\u0430 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043D\u0430 \u2014 ${status}

\u0412\u0430\u0448\u0430 \u0441\u0441\u044B\u043B\u043A\u0430 \u043D\u0430 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0443:

\u041D\u043E\u043C\u0435\u0440 \u0437\u0430\u043A\u0430\u0437\u0430: ${order.id}`);
  } catch (error) {
    console.error("Could not notify buyer after payment", error);
  }
  return "OK";
}
async function processYoomoneyNotification(env, body) {
  if (body.length > 64 * 1024) throw new Error("notification body is too large");
  requireConfig(env, ["YOOMONEY_NOTIFICATION_SECRET"]);
  const params = new URLSearchParams(body);
  const notificationType = params.get("notification_type");
  const operationId = params.get("operation_id");
  const amount = params.get("amount");
  const withdrawAmount = params.get("withdraw_amount");
  const currency = params.get("currency");
  const paymentDatetime = params.get("datetime");
  const sender = params.get("sender") ?? "";
  const codepro = params.get("codepro") ?? "";
  const unaccepted = params.get("unaccepted") ?? "false";
  const label = params.get("label");
  const receivedHash = params.get("sha1_hash");
  if (!notificationType || !operationId || !amount || !currency || !paymentDatetime || !label || !receivedHash) throw new Error("missing YooMoney notification fields");
  const expectedHash = await sha1Hex(signedYoomoneyString(params, env.YOOMONEY_NOTIFICATION_SECRET));
  if (!constantTimeEqual(expectedHash, receivedHash.toLowerCase())) throw new Error("invalid YooMoney signature");
  if (codepro.toLowerCase() === "true") throw new Error("code-protected payment is not accepted");
  if (unaccepted.toLowerCase() === "true") throw new Error("unaccepted payment is not accepted");
  if (currency !== "643" && currency !== "RUB") throw new Error("unsupported payment currency");
  const order = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(label).first();
  if (!order) throw new Error("unknown order label");
  const receivedKopeks = rubleKopeks(amount);
  const withdrawnKopeks = withdrawAmount ? rubleKopeks(withdrawAmount) : null;
  const expectedKopeks = order.amount_rub * 100;
  if (receivedKopeks !== expectedKopeks && withdrawnKopeks !== expectedKopeks) {
    throw new Error("payment amount does not match order");
  }
  return finalizePaidOrder(env, order, {
    operationId,
    amount,
    currency,
    notificationType,
    paymentDatetime,
    sender,
    codepro,
    label,
    rawHash: receivedHash
  });
}
async function processYooKassaNotification(env, body) {
  if (body.length > 64 * 1024) throw new Error("notification body is too large");
  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    throw new Error("invalid JSON notification");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("invalid notification object");
  const event = payload;
  if (event.event !== "payment.succeeded" || !event.object || typeof event.object !== "object" || Array.isArray(event.object)) throw new Error("unsupported notification");
  const payment = event.object;
  if (payment.status !== "succeeded") throw new Error("payment is not succeeded");
  if (typeof payment.id !== "string" || !payment.id) throw new Error("missing payment id");
  if (!payment.metadata || typeof payment.metadata !== "object" || Array.isArray(payment.metadata)) throw new Error("missing payment metadata");
  const orderId = payment.metadata.order_id;
  if (typeof orderId !== "string" || !orderId) throw new Error("missing order id");
  if (!payment.amount || typeof payment.amount !== "object" || Array.isArray(payment.amount)) throw new Error("missing payment amount");
  const amount = payment.amount;
  if (amount.currency !== "RUB" || typeof amount.value !== "string") throw new Error("unsupported payment currency or amount");
  const order = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(orderId).first();
  if (!order) throw new Error("unknown order id");
  const amountKopeks = rubleKopeks(amount.value);
  if (amountKopeks === null || amountKopeks !== order.amount_rub * 100) throw new Error("payment amount does not match order");
  const paymentDatetime = typeof payment.created_at === "string" ? payment.created_at : (/* @__PURE__ */ new Date()).toISOString();
  return finalizePaidOrder(env, order, {
    operationId: payment.id,
    amount: amount.value,
    currency: "RUB",
    notificationType: "YooKassa",
    paymentDatetime,
    sender: "",
    codepro: "false",
    label: orderId,
    rawHash: ""
  });
}
async function handleTelegramWebhook(env, request) {
  requireConfig(env, ["TELEGRAM_WEBHOOK_SECRET"]);
  if (request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.TELEGRAM_WEBHOOK_SECRET) {
    return textResponse("forbidden", 403);
  }
  let update;
  try {
    update = await request.json();
  } catch {
    return textResponse("invalid json", 400);
  }
  try {
    if (update.callback_query) await handleCallback(env, update.callback_query);
    else if (update.message) await handleMessage(env, update.message);
    return json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Telegram update handling failed: ${message}`, error);
    return json({ ok: true });
  }
}
async function ensureTelegramWebhook(env) {
  requireConfig(env, ["TELEGRAM_BOT_TOKEN", "TELEGRAM_WEBHOOK_SECRET"]);
  const webhookUrl = "https://telegram-vpn-bot.bobritogusingo.workers.dev/telegram";
  await telegramApi(env, "setWebhook", {
    url: webhookUrl,
    secret_token: env.TELEGRAM_WEBHOOK_SECRET,
    allowed_updates: ["message", "callback_query"],
    drop_pending_updates: false
  });
}
async function disableExpiredSubscriptions(env) {
  const expired = await env.DB.prepare(
    `SELECT user_id, plan, happ_install_id FROM subscriptions
     WHERE happ_install_id IS NOT NULL AND happ_status = 'active'
       AND expiration_at IS NOT NULL AND expiration_at <= datetime('now') LIMIT 100`
  ).all();
  for (const subscription of expired.results) {
    if (!subscription.happ_install_id) continue;
    try {
      await env.DB.prepare(
        "UPDATE subscriptions SET happ_status = 'disabled', updated_at = datetime('now') WHERE user_id = ? AND plan = ? AND happ_install_id = ? AND happ_status = 'active'"
      ).bind(subscription.user_id, subscription.plan, subscription.happ_install_id).run();
    } catch (error) {
      console.error(`Could not mark expired ${subscription.plan} subscription for ${subscription.user_id}`, error);
    }
  }
}
var index_default = {
  async scheduled(_controller, env, _ctx) {
    try {
      await ensureTelegramWebhook(env);
    } catch (error) {
      console.error("Could not configure Telegram webhook", error);
    }
    await disableExpiredSubscriptions(env);
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname.startsWith("/subscription/")) {
        return await serveHappSubscription(env, url.pathname.slice("/subscription/".length));
      }
      if (request.method === "GET" && url.pathname.startsWith("/pay/")) {
        const orderId = url.pathname.slice("/pay/".length);
        return await yoomoneyPaymentPage(env, orderId, url.searchParams.get("method"));
      }
      if (request.method === "GET" && url.pathname === "/health") {
        await ensureTelegramWebhook(env);
        const webhookInfo = await telegramApi(env, "getWebhookInfo", {});
        return json({ ok: true, service: "telegram-subscription-bot", webhook: webhookInfo });
      }
      if (request.method === "POST" && url.pathname === "/telegram") {
        return await handleTelegramWebhook(env, request);
      }
      if (request.method === "POST" && url.pathname === "/yookassa") {
        const body = await request.text();
        try {
          return textResponse(await processYooKassaNotification(env, body));
        } catch (error) {
          console.error("YooKassa notification rejected", error);
          return textResponse("invalid notification", 400);
        }
      }
      if (request.method === "POST" && url.pathname === "/yoomoney") {
        const body = await request.text();
        try {
          return textResponse(await processYoomoneyNotification(env, body));
        } catch (error) {
          console.error("YooMoney notification rejected", error);
          return textResponse("invalid notification", 400);
        }
      }
      return json({ error: "Not found" }, 404);
    } catch (error) {
      console.error("Request failed", error);
      return json({ error: "Server configuration or internal error" }, 500);
    }
  }
};
export {
  index_default as default
};
/*! Bundled license information:

@noble/ciphers/utils.js:
  (*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) *)
*/
