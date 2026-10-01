(() => {
  // node_modules/@noble/ciphers/utils.js
  /*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */
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
    if (isBytes(value) && (length === undefined || value.length === length))
      return value;
    if (length !== undefined)
      anumber(length, "length");
    const bytes = isBytes(value);
    const ofLen = length !== undefined ? ` of length ${length}` : "";
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
    abytes(out, undefined, "output");
    const min = instance.outputLen;
    if (!(out.length >= min)) {
      throw new RangeError('"output" expected length >= ' + min);
    }
  }
  function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean(...arrays) {
    for (let i = 0;i < arrays.length; i++) {
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
    for (let i = 0;i < arr.length; i++) {
      arr[i] = byteSwap(arr[i]);
    }
    return arr;
  }
  var swap32IfBE = isLE ? (u) => u : byteSwap32;
  function overlapBytes(a, b) {
    if (!a.byteLength || !b.byteLength)
      return false;
    return a.buffer === b.buffer && a.byteOffset < b.byteOffset + b.byteLength && b.byteOffset < a.byteOffset + a.byteLength;
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
    for (let i = 0;i < a.length; i++)
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
  var wrapCipher = (params, constructor) => {
    function wrappedCipher(key, ...args) {
      abytes(key, undefined, "key");
      if (params.nonceLength !== undefined) {
        const nonce = args[0];
        abytes(nonce, params.varSizeNonce ? undefined : params.nonceLength, "nonce");
      }
      const tagl = params.tagLength;
      const aadStart = params.nonceLength !== undefined ? 1 : 0;
      if (!params.withAAD) {
        for (let i = aadStart;i < args.length; i++)
          if (isBytes(args[i]))
            throw new Error("AAD not supported");
      }
      if (params.withAAD && args[aadStart] !== undefined)
        abytes(args[aadStart], undefined, "AAD");
      const cipher = constructor(key, ...args);
      const checkOutput = (fnLength, output) => {
        if (output !== undefined) {
          if (fnLength !== 2)
            throw new Error("cipher output not supported");
          abytes(output, undefined, "output");
        }
      };
      let called = false;
      const wrCipher = {
        encrypt(data, output) {
          if (called)
            throw new Error("cannot encrypt() twice with same key + nonce");
          called = true;
          abytes(data, undefined, "data");
          checkOutput(cipher.encrypt.length, output);
          return cipher.encrypt(data, output);
        },
        decrypt(data, output) {
          abytes(data, undefined, "data");
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
    if (out === undefined)
      return new Uint8Array(expectedLength);
    abytes(out, expectedLength, "output");
    if (onlyAligned && !isAligned32(out))
      throw new Error("invalid output, must be aligned");
    return out;
  }
  function u64Lengths(dataLength, aadLength, isLE) {
    anumber(dataLength);
    anumber(aadLength);
    abool(isLE);
    const num = new Uint8Array(16);
    const view = createView(num);
    view.setBigUint64(0, BigInt(aadLength), isLE);
    view.setBigUint64(8, BigInt(dataLength), isLE);
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
      for (let pos = 0;pos < len; counter++) {
        core(sigma, key, nonce, b32, counter, rounds);
        swap32IfBE(b32);
        if (counter >= MAX_COUNTER)
          throw new Error("arx: counter overflow");
        const take = Math.min(BLOCK_LEN, len - pos);
        for (let j = 0, posj;j < take; j++) {
          posj = pos + j;
          output[posj] = data[posj] ^ block[j];
        }
        pos += take;
      }
      return;
    }
    for (let pos = 0;pos < len; counter++) {
      core(sigma, key, nonce, b32, counter, rounds);
      if (counter >= MAX_COUNTER)
        throw new Error("arx: counter overflow");
      const take = Math.min(BLOCK_LEN, len - pos);
      if (isAligned && take === BLOCK_LEN) {
        const pos32 = pos / 4;
        if (pos % 4 !== 0)
          throw new Error("arx: invalid block position");
        for (let j = 0, posj;j < BLOCK_LEN32; j++) {
          posj = pos32 + j;
          o32[posj] = d32[posj] ^ b32[j];
        }
        pos += BLOCK_LEN;
        continue;
      }
      for (let j = 0, posj;j < take; j++) {
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
      abytes(key, undefined, "key");
      abytes(nonce, undefined, "nonce");
      abytes(data, undefined, "data");
      const len = data.length;
      const hasOutput = output !== undefined;
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

  class Poly1305 {
    blockLen = 16;
    outputLen = 16;
    buffer = new Uint8Array(16);
    r = new Uint16Array(10);
    h = new Uint16Array(10);
    pad = new Uint16Array(8);
    pos = 0;
    finished = false;
    destroyed = false;
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
      for (let i = 0;i < 8; i++)
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
      for (let i = 2;i < 10; i++) {
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
      for (let i = 1;i < 10; i++) {
        g[i] = h[i] + c;
        c = g[i] >>> 13;
        g[i] &= 8191;
      }
      g[9] -= 1 << 13;
      let mask = (c ^ 1) - 1;
      for (let i = 0;i < 10; i++)
        g[i] &= mask;
      mask = ~mask;
      for (let i = 0;i < 10; i++)
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
      for (let i = 1;i < 8; i++) {
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
      for (let pos = 0;pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          for (;blockLen <= len - pos; pos += blockLen)
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
        for (;pos < 16; pos++)
          buffer[pos] = 0;
        this.process(buffer, 0, true);
      }
      this.finalize();
      let opos = 0;
      for (let i = 0;i < 8; i++) {
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
  }
  var poly1305 = /* @__PURE__ */ wrapMacConstructor(32, (key) => new Poly1305(key));

  // node_modules/@noble/ciphers/chacha.js
  function chachaCore(s, k, n, out, cnt, rounds = 20) {
    let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];
    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
    for (let r = 0;r < rounds; r += 2) {
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
    if (AAD !== undefined)
      abytes(AAD, undefined, "AAD");
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
  var chacha20poly1305 = /* @__PURE__ */ wrapCipher({ blockSize: 64, nonceLength: 12, tagLength: 16, withAAD: true }, /* @__PURE__ */ _poly1305_aead(chacha20));

  // src/crypt5.ts
  var MARKER = "asajzqxt";
  var RSA_N = "x1KI0JR-rT9gwb0OSBuDjOajW-T7BdLhsel6CbJyRKmcKnKedB1LVTpjRr2YbQBBtb_RwUKcCfXJJnltCJzfO9cfKhAP21ihUunXND3jQUs06gdLmwskbmGhjGu23vYo_AOmezo4iJWXHhOhM3Jzw5NRdadlehuyUIDv3bozrhPWOb_IkODSRwVOw_sqcDTYPGTiC5vYLNcaB-J2t8_AgEKiYUOWa-TDNM2XOv9jnATPIVju2rKr5o25RcQbOKLm7ISiSyGTe3WmWgbGQDLZcs32xfykb7zrvc6UtXNe7IscUd7vATdfvM167X2p1MHBVj0Ou0zhhArZSFo6muc8_h5E_fHnEHqcPovIaW99CE7f1jY2p7KADUhCepw55JnE9vIvmiPV0nnoP6E8oCMLhoIND-Od9_hqOd4Kimhhu-5D-LmYIjGl9uLtRseKfaXXKjfttv66-z4lzryULVhOO0Mh14IAu4BhBLkOA5VjRAsTAerLse4oMf6qHjS3lmayBdpG7s0h8QM4MEyRoNcABZ3ccMNyJRYe2uIPdj-hheGkQPW3_LMfdhthQnxcSyg6NqNhZUuwF66feyY1cSsPSnk2_b1TBxTappOfpvBsuDjEDWshXlwd6uSmxAvSiTxwSHU5yzYOH1zxBnJgqrq7KdrCNVUWCcTkf479JYIDB8E";
  var ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  var LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var encoder = new TextEncoder;
  function b64(bytes) {
    let text = "";
    for (const b of bytes)
      text += String.fromCharCode(b);
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
    for (let i = 0;i + 1 < out.length; i += 2)
      [out[i], out[i + 1]] = [out[i + 1], out[i]];
    return out;
  }
  function blockSwap(value) {
    const out = value.slice();
    for (let i = 0;i + 3 < out.length; i += 4) {
      [out[i], out[i + 2]] = [out[i + 2], out[i]];
      [out[i + 1], out[i + 3]] = [out[i + 3], out[i + 1]];
    }
    return out;
  }
  function toBigInt(bytes) {
    let n = 0n;
    for (const byte of bytes)
      n = n << 8n | BigInt(byte);
    return n;
  }
  function toBytes(value, size) {
    const out = new Uint8Array(size);
    for (let i = size - 1;i >= 0; i--) {
      out[i] = Number(value & 255n);
      value >>= 8n;
    }
    return out;
  }
  function modPow(base, exponent, modulus) {
    let out = 1n;
    while (exponent) {
      if (exponent & 1n)
        out = out * base % modulus;
      base = base * base % modulus;
      exponent >>= 1n;
    }
    return out;
  }
  function rsaEncrypt(data) {
    const modulus = toBigInt(b64urlBytes(RSA_N));
    const size = 512;
    if (data.length > size - 11)
      throw new Error("crypt5 RSA payload too long");
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
  var MEMBER_STATUSES = new Set(["creator", "administrator", "member"]);
  var HAPP_SUBSCRIPTION_ENDPOINT = "https://telegram-vpn-bot.bobritogusingo.workers.dev/subscription/{INSTALL_CODE}";
  var WORKER_URL = "https://telegram-vpn-bot.bobritogusingo.workers.dev";
  function happConfig(env, _plan) {
    const keys = ["HAPP_PREMIUM_PROVIDER_CODE", "HAPP_PREMIUM_AUTH_KEY"];
    requireConfig(env, keys);
    const limit = env.HAPP_INSTALL_LIMIT ? Number(env.HAPP_INSTALL_LIMIT) : 2;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100)
      throw new Error("HAPP_INSTALL_LIMIT must be an integer from 1 to 100");
    const base = env.HAPP_INSTALL_URL_BASE?.trim() || undefined;
    const [providerKey, authKey] = keys;
    return { provider: env[providerKey], auth: env[authKey], limit, base };
  }
  function randomInstallCode() {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
  }
  function findField(value, names) {
    if (!value || typeof value !== "object")
      return;
    const record = value;
    for (const name of names)
      if (record[name] !== undefined)
        return record[name];
    for (const child of Object.values(record)) {
      const found = findField(child, names);
      if (found !== undefined)
        return found;
    }
    return;
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
    if (rc !== undefined && ![1, "1", true, "success", "ok"].includes(rc))
      throw new Error(`Happ rejected install creation: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
    const rawId = findField(payload, ["id", "install_id", "installId"]);
    const rawCode = findField(payload, ["install_code", "installCode", "code"]);
    const rawLink = findField(payload, ["url", "link", "install_url", "installUrl", "subscription_url", "subscriptionUrl"]);
    const id = Number(rawId);
    const code = typeof rawCode === "string" ? rawCode : fallbackCode;
    const link = typeof rawLink === "string" ? rawLink : base ? buildHappLink(base, code) : "";
    if (!Number.isSafeInteger(id) || id <= 0 || !code || !link)
      throw new Error("Happ response did not contain a usable install id and public link; configure HAPP_INSTALL_URL_BASE with the original subscription URL");
    return { id, code, link };
  }
  async function happRequest(env, plan, path, method = "GET", body) {
    const config = happConfig(env, plan);
    const url = new URL(`https://happ-proxy.com${path}`);
    url.searchParams.set("provider_code", config.provider);
    url.searchParams.set("auth_key", config.auth);
    const response = await fetch(url, { method, headers: body ? { "content-type": "application/json" } : undefined, ...body ? { body: JSON.stringify(body) } : {} });
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error(`Happ returned non-JSON response (${response.status})`);
    }
    if (!response.ok)
      throw new Error(`Happ HTTP error: ${response.status}`);
    return payload;
  }
  var happSubscriptionProvider = {
    async ensureSubscription(env, subscription, note) {
      const config = happConfig(env, subscription.plan);
      if (subscription.happ_install_id && subscription.happ_install_link) {
        const payload = await happRequest(env, subscription.plan, `/api/update-install?id=${encodeURIComponent(String(subscription.happ_install_id))}&status=10`);
        const rc = findField(payload, ["rc"]);
        if (rc !== undefined && ![0, "0", 1, "1", true, "success", "ok"].includes(rc))
          throw new Error(`Happ rejected install activation: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
        const code = subscription.happ_install_code ?? "";
        const link = code && config.base ? buildHappLink(config.base, code) : subscription.happ_install_link;
        return { id: subscription.happ_install_id, code, link };
      }
      const code = subscription.happ_install_code ?? randomInstallCode();
      const path = `/api/add-install?install_limit=${config.limit}&install_code=${encodeURIComponent(code)}&note=${encodeURIComponent(note)}`;
      return parseHappInstall(await happRequest(env, subscription.plan, path), code, config.base);
    },
    async disableSubscription(env, plan, id) {
      const payload = await happRequest(env, plan, `/api/update-install?id=${encodeURIComponent(String(id))}&status=5`);
      const rc = findField(payload, ["rc"]);
      if (rc !== undefined && ![0, "0", true, "success", "ok"].includes(rc))
        throw new Error(`Happ rejected install disable: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
    }
  };
  async function reissueHappSubscription(env, userId, plan) {
    const previous = await getActiveSubscription(env, userId, plan);
    if (!previous)
      throw new Error(`No active ${plan.toUpperCase()} subscription to reissue`);
    const config = happConfig(env, plan);
    const code = randomInstallCode();
    const payload = await happRequest(env, plan, `/api/add-install?install_limit=${config.limit}&install_code=${encodeURIComponent(code)}&note=${encodeURIComponent("User-requested Happ reissue")}`);
    const replacement = parseHappInstall(payload, code, config.base);
    const result = await env.DB.prepare(`UPDATE subscriptions
     SET happ_install_id = ?, happ_install_code = ?, happ_install_link = ?, happ_status = 'active', happ_last_error = NULL, updated_at = datetime('now')
     WHERE user_id = ? AND plan = ? AND expiration_at IS NOT NULL AND expiration_at > datetime('now')`).bind(replacement.id, replacement.code, replacement.link, userId, plan).run();
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
    if (!subscription?.expiration_at)
      return false;
    const expiration = new Date(`${subscription.expiration_at.replace(" ", "T")}Z`).getTime();
    return Number.isFinite(expiration) && expiration > Date.now() - 7 * 86400000;
  }
  async function deliverSubscription(env, userId, plan, note) {
    let reservation = await getActiveSubscription(env, userId, plan);
    if (!reservation)
      throw new Error(`No active ${plan.toUpperCase()} subscription to deliver`);
    if (!reservation.happ_install_id) {
      const code = reservation.happ_install_code ?? randomInstallCode();
      const result = await env.DB.prepare(`UPDATE subscriptions SET happ_install_code = ?, happ_status = 'creating', updated_at = datetime('now')
       WHERE user_id = ? AND plan = ? AND happ_install_id IS NULL
         AND (happ_status IS NULL OR happ_status = 'error'
              OR (happ_status = 'creating' AND updated_at <= datetime('now', '-5 minutes')))
         AND expiration_at IS NOT NULL AND expiration_at > datetime('now')`).bind(code, userId, plan).run();
      if (Number(result.meta.changes ?? 0) === 0) {
        const fresh = await getActiveSubscription(env, userId, plan);
        if (fresh?.happ_install_id && fresh.happ_install_link)
          return fresh.happ_install_link;
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
      await env.DB.prepare("UPDATE subscriptions SET happ_status = 'error', happ_last_error = ?, updated_at = datetime('now') WHERE user_id = ? AND plan = ? AND happ_status = 'creating'").bind(message.slice(0, 1000), userId, plan).run();
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
    if (!sourceUrl)
      throw new Error("HAPP_INSTALL_URL_BASE is required");
    const source = new URL(sourceUrl);
    if (source.protocol !== "https:" || source.username || source.password)
      throw new Error("Invalid Happ subscription source URL");
    const response = await fetch(source.toString(), { headers: { accept: "application/json, text/plain;q=0.9, */*;q=0.1" } });
    if (!response.ok)
      throw new Error(`Subscription source failed: ${response.status}`);
    return response;
  }
  function makeExpiredSubscriptionNotice(sourceText) {
    const parsed = JSON.parse(sourceText);
    if (!Array.isArray(parsed) || parsed.length === 0 || !parsed[0] || typeof parsed[0] !== "object") {
      throw new Error("Premium source is not a JSON subscription array");
    }
    const template = parsed[0];
    const notices = ["⛔ Подписка закончилась", "\uD83D\uDD04 Её можно продлить", "\uD83E\uDD16 В нашем боте"];
    return JSON.stringify(notices.map((remarks) => {
      const notice = JSON.parse(JSON.stringify(template));
      notice.remarks = remarks;
      if (!Array.isArray(notice.outbounds) || notice.outbounds.length === 0)
        throw new Error("Premium source has no outbounds");
      notice.outbounds = notice.outbounds.map((outbound) => {
        const tag = outbound && typeof outbound === "object" ? outbound.tag : undefined;
        if (typeof tag !== "string" || tag.length === 0)
          throw new Error("Premium source has an invalid outbound tag");
        return { tag, protocol: "blackhole" };
      });
      return notice;
    }));
  }
  async function serveHappSubscription(env, installCode) {
    if (!/^[A-Za-z0-9]{8,128}$/.test(installCode))
      return textResponse("Not found", 404);
    const subscription = await env.DB.prepare(`SELECT expiration_at, happ_status FROM subscriptions
     WHERE plan = 'premium' AND happ_install_code = ? AND expiration_at IS NOT NULL`).bind(installCode).first();
    if (!subscription?.expiration_at)
      return textResponse("Subscription inactive", 403);
    const expiresAt = new Date(`${subscription.expiration_at.replace(" ", "T")}Z`).getTime();
    if (!Number.isFinite(expiresAt))
      throw new Error("Invalid subscription expiry");
    const source = await fetchPremiumSource(env);
    const headers = new Headers;
    headers.set("content-type", "application/json; charset=utf-8");
    headers.set("cache-control", "no-store");
    if (expiresAt <= Date.now()) {
      const sourceText = await source.text();
      return new Response(makeExpiredSubscriptionNotice(sourceText), { status: 200, headers });
    }
    if (subscription.happ_status !== "active")
      return textResponse("Subscription inactive", 403);
    headers.set("content-type", source.headers.get("content-type") || "application/json; charset=utf-8");
    headers.set("subscription-userinfo", `expire=${Math.floor(expiresAt / 1000)}`);
    return new Response(source.body, { status: 200, headers });
  }
  function escapeHtml(value) {
    return value.replace(/[&<>"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[character]);
  }
  async function yoomoneyPaymentPage(env, orderId, paymentType) {
    requireConfig(env, ["YOOMONEY_RECEIVER"]);
    if (paymentType !== "AC" && paymentType !== "PC")
      return textResponse("Payment method not found", 404);
    const order = await env.DB.prepare("SELECT id, amount_rub, status FROM orders WHERE id = ?").bind(orderId).first();
    if (!order)
      return textResponse("Order not found", 404);
    if (order.status !== "pending")
      return textResponse("Этот заказ уже оплачен или отменён. Вернитесь в бот, чтобы создать новый заказ.", 409);
    const fields = {
      receiver: env.YOOMONEY_RECEIVER,
      label: order.id,
      "quickpay-form": "button",
      paymentType,
      sum: String(order.amount_rub),
      targets: "Подписка PREMIUM"
    };
    const inputs = Object.entries(fields).map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`).join("");
    const methodName = paymentType === "AC" ? "картой" : "из кошелька ЮMoney";
    return new Response(`<!doctype html><html lang="ru"><meta charset="utf-8"><title>Переход к оплате</title><body><p>Перенаправляем к оплате ${methodName}…</p><form id="payment" method="post" action="https://yoomoney.ru/quickpay/confirm.xml">${inputs}<button type="submit">Перейти к оплате</button></form><script>document.getElementById('payment').submit()</script></body></html>`, {
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
        { text: "\uD83E\uDD16 Android — Happ", callback_data: "happ:android" },
        { text: "\uD83C\uDF4E iPhone/iPad — Happ", callback_data: "happ:ios" }
      ]
    ];
    if (showDevices)
      rows.push([{ text: "\uD83D\uDCF1 Устройства", callback_data: "happ:devices" }]);
    if (showReissue)
      rows.push([{ text: "\uD83D\uDD04 Перевыпустить ссылку", callback_data: "happ:reissue" }]);
    rows.push([{ text: "\uD83D\uDCD6 Нужна инструкция", callback_data: "happ:guide" }]);
    return { inline_keyboard: rows };
  }
  async function sendSubscriptionChoice(env, chatId, header, showReissue = false, showDevices = false) {
    await telegramApi(env, "sendMessage", {
      chat_id: chatId,
      text: `${escapeHtml(header)}

Выберите устройство — бот пришлёт подходящую ссылку.`,
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
      reply_markup: { inline_keyboard: [[{ text: "\uD83D\uDCD6 Нужна инструкция", callback_data: "happ:guide" }]] }
    });
  }
  async function sendPlatformSubscriptionLink(env, chatId, telegramId, platform) {
    const subscription = await getActiveSubscription(env, telegramId, "premium");
    const config = happConfig(env, "premium");
    if (!subscription?.happ_install_code || !config.base) {
      await sendMessage(env, chatId, "Не удалось найти активную ссылку. Откройте /menu ещё раз через минуту.");
      return;
    }
    const link = platform === "android" ? buildHappLink(config.base, subscription.happ_install_code) : buildHappPlainLink(subscription.happ_install_code);
    const device = platform === "android" ? "Android (Happ)" : "iPhone/iPad (Happ)";
    await sendSubscriptionLink(env, chatId, `Ссылка для ${device}:`, link);
  }
  var deviceActionTableReady = null;
  async function ensureDeviceActionTable(env) {
    if (!deviceActionTableReady) {
      deviceActionTableReady = env.DB.prepare(`CREATE TABLE IF NOT EXISTS happ_device_actions (
        token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, install_code TEXT NOT NULL,
        hwid TEXT NOT NULL, expires_at TEXT NOT NULL
      )`).run().then(() => {
        return;
      }).catch((error) => {
        deviceActionTableReady = null;
        throw error;
      });
    }
    await deviceActionTableReady;
  }
  function collectHappDevices(value, output = new Map) {
    if (Array.isArray(value)) {
      for (const item of value)
        collectHappDevices(item, output);
    } else if (value && typeof value === "object") {
      const record = value;
      const hwid = typeof record.hwid === "string" ? record.hwid.trim() : "";
      const rawName = record.device_name ?? record.deviceName;
      const name = typeof rawName === "string" && rawName.trim() ? rawName.trim() : null;
      if (hwid) {
        const previous = output.get(hwid);
        output.set(hwid, { hwid, name: name ?? previous?.name ?? null });
      }
      for (const item of Object.values(record))
        collectHappDevices(item, output);
    }
    return output;
  }
  async function listHappDevices(env, subscription) {
    if (!subscription.happ_install_code && !subscription.happ_install_id)
      return [];
    const selector = subscription.happ_install_code ? `install_code=${encodeURIComponent(subscription.happ_install_code)}` : `install_id=${encodeURIComponent(String(subscription.happ_install_id))}`;
    const payload = await happRequest(env, subscription.plan, `/api/list-hwid?${selector}`);
    const rc = findField(payload, ["rc"]);
    if (rc !== undefined && ![1, "1", true, "success", "ok"].includes(rc)) {
      throw new Error(`Happ rejected device list: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
    }
    return [...collectHappDevices(payload).values()];
  }
  function deviceLabel(device) {
    return device.name ?? "Неизвестное устройство";
  }
  async function sendHappDevices(env, chatId, telegramId) {
    const subscription = await getActiveSubscription(env, telegramId, "premium");
    if (!subscription?.happ_install_code) {
      await sendMessage(env, chatId, "Активная подписка или её ссылка не найдена. Откройте /menu ещё раз через минуту.");
      return;
    }
    const devices = await listHappDevices(env, subscription);
    const limit = happConfig(env, "premium").limit;
    if (devices.length === 0) {
      await sendMessage(env, chatId, `Подключённых устройств нет. Доступно: ${limit} из ${limit}.`);
      return;
    }
    await ensureDeviceActionTable(env);
    const rows = [];
    for (const device of devices) {
      const token = randomInstallCode();
      await env.DB.prepare(`INSERT OR REPLACE INTO happ_device_actions (token, user_id, install_code, hwid, expires_at)
       VALUES (?, ?, ?, ?, datetime('now', '+10 minutes'))`).bind(token, telegramId, subscription.happ_install_code, device.hwid).run();
      rows.push([{ text: `Отключить ${deviceLabel(device)}`, callback_data: `happ:device:remove:${token}` }]);
    }
    await sendMessage(env, chatId, `Подключённые устройства: ${devices.length} из ${limit}

Выберите устройство, которое хотите отключить:`, { inline_keyboard: rows });
  }
  async function removeHappDevice(env, telegramId, token) {
    if (!/^[A-Za-z0-9]{12}$/.test(token))
      return false;
    await ensureDeviceActionTable(env);
    const action = await env.DB.prepare(`SELECT token, install_code, hwid FROM happ_device_actions
     WHERE token = ? AND user_id = ? AND expires_at > datetime('now')`).bind(token, telegramId).first();
    if (!action)
      return false;
    const subscription = await getActiveSubscription(env, telegramId, "premium");
    if (!subscription?.happ_install_code || subscription.happ_install_code !== action.install_code)
      return false;
    const devices = await listHappDevices(env, subscription);
    if (!devices.some((device) => device.hwid === action.hwid))
      return false;
    const payload = await happRequest(env, subscription.plan, `/api/delete-hwid?install_code=${encodeURIComponent(subscription.happ_install_code)}&hwid=${encodeURIComponent(action.hwid)}`);
    const rc = findField(payload, ["rc"]);
    if (rc !== undefined && ![1, "1", true, "success", "ok"].includes(rc)) {
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
    const existed = await env.DB.prepare("SELECT 1 FROM users WHERE telegram_id = ?").bind(user.id).first();
    await env.DB.prepare(`INSERT INTO users (telegram_id, username, first_name)
     VALUES (?, ?, ?)
     ON CONFLICT(telegram_id) DO UPDATE SET
       username = excluded.username,
       first_name = excluded.first_name,
       updated_at = datetime('now')`).bind(user.id, user.username ?? null, user.first_name ?? null).run();
    return !existed;
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
      buttons.push([{ text: "Подписаться на канал", url: env.CHANNEL_INVITE_URL }]);
    }
    buttons.push([{ text: "Я подписался — проверить", callback_data: "check_membership" }]);
    return { inline_keyboard: buttons };
  }
  async function sendMembershipPrompt(env, chatId) {
    const invite = env.CHANNEL_INVITE_URL && !env.CHANNEL_INVITE_URL.includes("REPLACE_WITH") ? `
Ссылка на канал: ${env.CHANNEL_INVITE_URL}` : "";
    await sendMessage(env, chatId, `Чтобы пользоваться ботом, подпишитесь на наш канал, а затем нажмите «Я подписался — проверить».${invite}`, membershipKeyboard(env));
  }
  async function ensureMembership(env, chatId, telegramId) {
    const member = await isChannelMember(env, telegramId);
    if (!member)
      await sendMembershipPrompt(env, chatId);
    return member;
  }
  function planKeyboard() {
    return { inline_keyboard: [
      [{ text: "Выбрать срок Premium", callback_data: "plan:premium" }],
      [{ text: "Попробовать бесплатно — 3 дня", callback_data: "trial" }]
    ] };
  }
  function durationKeyboard(plan) {
    return {
      inline_keyboard: DURATIONS.map((duration) => [
        { text: `${duration} мес. — ${PRODUCTS[plan][duration]} ₽`, callback_data: `duration:${plan}:${duration}` }
      ])
    };
  }
  function adminKeyboard() {
    return { inline_keyboard: [
      [{ text: "Создать скидочный промокод", callback_data: "admin:promo:discount" }],
      [{ text: "Создать промокод на дни", callback_data: "admin:promo:days" }],
      [{ text: "Создать бесплатные дни", callback_data: "admin:promo:free_days" }],
      [{ text: "\uD83D\uDCCB Список промокодов", callback_data: "admin:promo:hub" }],
      [{ text: "\uD83E\uDD1D Партнёрки", callback_data: "admin:partner:hub" }]
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
  function parsePromoExpiry(value, timeValue) {
    if (!value)
      return timeValue ? undefined : null;
    const match = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(value);
    if (!match)
      return;
    const [, dayText, monthText, yearText] = match;
    const day = Number(dayText);
    const month = Number(monthText);
    const year = Number(yearText);
    const dateCheck = new Date(Date.UTC(year, month - 1, day));
    if (dateCheck.getUTCFullYear() !== year || dateCheck.getUTCMonth() !== month - 1 || dateCheck.getUTCDate() !== day)
      return;
    let hour = 23;
    let minute = 59;
    let second = 59;
    if (timeValue) {
      const time = /^(\d{2}):(\d{2})$/.exec(timeValue);
      if (!time)
        return;
      hour = Number(time[1]);
      minute = Number(time[2]);
      second = 0;
      if (hour > 23 || minute > 59)
        return;
    }
    const utc = new Date(Date.UTC(year, month - 1, day, hour - 3, minute, second));
    return utc.toISOString().slice(0, 19).replace("T", " ");
  }
  async function setInputSession(env, userId, kind) {
    await env.DB.prepare(`INSERT INTO input_sessions (user_id, kind, expires_at)
    VALUES (?, ?, datetime('now', '+10 minutes'))
    ON CONFLICT(user_id) DO UPDATE SET kind = excluded.kind, expires_at = excluded.expires_at`).bind(userId, kind).run();
  }
  async function takeInputSession(env, userId) {
    const session = await env.DB.prepare("SELECT kind, expires_at FROM input_sessions WHERE user_id = ? AND expires_at > datetime('now')").bind(userId).first();
    if (session)
      await env.DB.prepare("DELETE FROM input_sessions WHERE user_id = ?").bind(userId).run();
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
    if (Number(result.meta.changes ?? 0) !== 1)
      return false;
    await env.DB.batch([
      env.DB.prepare("INSERT INTO promo_reservations (user_id, code) VALUES (?, ?)").bind(userId, code),
      env.DB.prepare("INSERT OR IGNORE INTO promo_entries (promo_code, user_id) VALUES (?, ?)").bind(code, userId)
    ]);
    return true;
  }
  function formatPromoExpiry(expiresAt) {
    if (!expiresAt)
      return "без даты окончания";
    const utc = new Date(`${expiresAt.replace(" ", "T")}Z`);
    if (!Number.isFinite(utc.getTime()))
      return expiresAt;
    const msk = new Date(utc.getTime() + 3 * 60 * 60 * 1000);
    const pad = (value) => String(value).padStart(2, "0");
    return `${pad(msk.getUTCDate())}.${pad(msk.getUTCMonth() + 1)}.${msk.getUTCFullYear()} ${pad(msk.getUTCHours())}:${pad(msk.getUTCMinutes())} МСК`;
  }
  function formatPromoLimit(promo) {
    return promo.unlimited_activations === 1 ? "∞" : String(promo.max_activations);
  }
  function promoKind(promo) {
    if (promo.free_grant === 1)
      return `${promo.duration_days} бесплатных дней`;
    return promo.duration_days ? `${promo.duration_days} дней, скидка ${promo.discount_percent}%` : `скидка ${promo.discount_percent}%`;
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
    await sendMessage(env, chatId, "Промокоды", { inline_keyboard: [
      [{ text: `✅ Действующие (${currentCount})`, callback_data: "admin:promo:list:current:0" }],
      [{ text: `⌛ Истёкшие за 3 дня (${expiredCount})`, callback_data: "admin:promo:list:expired:0" }]
    ] });
  }
  async function sendPromoList(env, chatId, category, page) {
    const safePage = Math.max(0, Math.min(1000, page));
    const pageSize = 10;
    const where = category === "current" ? promoCurrentWhere("p") : promoExpiredWhere("p");
    const countRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM promo_codes p WHERE ${where}`).first();
    const total = Number(countRow?.count ?? 0);
    const title = category === "current" ? "Действующие промокоды" : "Истёкшие промокоды за последние 3 дня";
    if (total === 0) {
      await sendMessage(env, chatId, `${title}: нет.`);
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
      text: `${category === "current" ? "✅" : "⌛"} ${promo.code} · ${promo.activation_count}/${formatPromoLimit(promo)}`,
      callback_data: `admin:promo:view:${promo.code}:${category}`
    }]);
    const navigation = [];
    if (currentPage > 0)
      navigation.push({ text: "‹ Назад", callback_data: `admin:promo:list:${category}:${currentPage - 1}` });
    if (currentPage < lastPage)
      navigation.push({ text: "Вперёд ›", callback_data: `admin:promo:list:${category}:${currentPage + 1}` });
    if (navigation.length)
      rows.push(navigation);
    rows.push([{ text: "‹ К разделам", callback_data: "admin:promo:hub" }]);
    await sendMessage(env, chatId, `${title}: ${total}
Страница ${currentPage + 1} из ${lastPage + 1}

Нажмите на промокод, чтобы открыть информацию:`, { inline_keyboard: rows });
  }
  async function getPromoEnteredUsers(env, code) {
    const result = await env.DB.prepare(`SELECT e.user_id, u.username, u.first_name, e.entered_at AS used_at, 'ввёл промокод' AS usage_type
    FROM promo_entries e JOIN users u ON u.telegram_id = e.user_id
    WHERE e.promo_code = ? ORDER BY e.entered_at DESC LIMIT 20`).bind(code).all();
    return result.results;
  }
  async function getPromoPurchasers(env, code) {
    const result = await env.DB.prepare(`SELECT user_id, username, first_name, used_at, usage_type FROM (
      SELECT o.user_id, u.username, u.first_name, o.paid_at AS used_at, 'оплатил заказ' AS usage_type
      FROM orders o JOIN users u ON u.telegram_id = o.user_id
      WHERE o.promo_code = ? AND o.status = 'paid'
      UNION ALL
      SELECT a.user_id, u.username, u.first_name, a.created_at AS used_at, 'получил бесплатные дни' AS usage_type
      FROM activation_logs a JOIN users u ON u.telegram_id = a.user_id WHERE a.details LIKE ?
    ) ORDER BY used_at DESC LIMIT 1000`).bind(code, `Free promo ${code}:%`).all();
    return result.results;
  }
  async function formatPromoPeople(env, users, emptyText) {
    if (!users.length)
      return emptyText;
    const lines = [];
    for (const user of users) {
      const subscription = await getSubscription(env, user.user_id, "premium");
      let devices = "нет данных";
      if (subscription?.happ_install_code || subscription?.happ_install_id) {
        try {
          const happDevices = await listHappDevices(env, subscription);
          devices = happDevices.length ? happDevices.map(deviceLabel).join(", ") : "нет";
        } catch {
          devices = "не удалось получить";
        }
      }
      const account = user.username ? `@${user.username}` : user.first_name ? escapeHtml(user.first_name) : "без имени";
      lines.push(`• ${account} · ID <code>${user.user_id}</code>
  ${user.usage_type}; ${formatPromoExpiry(user.used_at)}
  Устройства: ${escapeHtml(devices)}`);
    }
    return lines.join(`
`);
  }
  function formatPaidPromoUsersQuotes(users) {
    if (!users.length)
      return ["Пока нет успешных покупок или выдач."];
    const chunks = [];
    let lines = [];
    let length = 0;
    for (const user of users) {
      const account = user.username ? `@${escapeHtml(user.username)}` : user.first_name ? escapeHtml(user.first_name) : "без имени";
      const line = `• ${account} · <code>${user.user_id}</code> — ${user.usage_type}`;
      if (lines.length && length + line.length + 1 > 3000) {
        chunks.push(`<blockquote expandable>${lines.join(`
`)}</blockquote>`);
        lines = [];
        length = 0;
      }
      lines.push(line);
      length += line.length + 1;
    }
    if (lines.length)
      chunks.push(`<blockquote expandable>${lines.join(`
`)}</blockquote>`);
    return chunks;
  }
  async function sendPromoInfo(env, chatId, code, category = "current") {
    const promo = await env.DB.prepare(`SELECT p.code, p.discount_percent, p.duration_days, p.max_activations, p.activation_count,
      p.active, p.free_grant, p.unlimited_activations, p.expires_at, p.created_at, p.updated_at,
      (SELECT COUNT(*) FROM orders o WHERE o.promo_code = p.code AND o.status = 'paid') AS paid_orders
    FROM promo_codes p WHERE p.code = ?`).bind(code).first();
    if (!promo) {
      await sendMessage(env, chatId, "Промокод не найден.");
      return;
    }
    const current = promo.active === 1 && (promo.expires_at === null || new Date(`${promo.expires_at.replace(" ", "T")}Z`).getTime() > Date.now()) && (promo.unlimited_activations === 1 || promo.activation_count < promo.max_activations);
    const status = current ? "активен" : "истёк или отключён";
    const [enteredUsers, purchasers] = await Promise.all([
      getPromoEnteredUsers(env, promo.code),
      getPromoPurchasers(env, promo.code)
    ]);
    const entered = await formatPromoPeople(env, enteredUsers, "Пока никто не вводил код.");
    const enteredQuote = enteredUsers.length ? `<blockquote expandable>${entered}</blockquote>` : entered;
    const paidUserQuotes = formatPaidPromoUsersQuotes(purchasers);
    const back = `admin:promo:list:${category}:0`;
    const keyboard = current ? { inline_keyboard: [[{ text: "\uD83D\uDDD1 Удалить промокод", callback_data: `admin:promo:delete:${promo.code}` }], [{ text: "\uD83D\uDCCB К списку", callback_data: back }]] } : { inline_keyboard: [[{ text: "\uD83D\uDCCB К списку", callback_data: back }]] };
    await telegramApi(env, "sendMessage", {
      chat_id: chatId,
      parse_mode: "HTML",
      text: `Промокод: <code>${escapeHtml(promo.code)}</code>

Статус: ${status}
Условия: ${escapeHtml(promoKind(promo))}
Активации: ${promo.activation_count} из ${formatPromoLimit(promo)}
Оплаченные покупки: ${promo.paid_orders}
Действует до: ${formatPromoExpiry(promo.expires_at)}
Создан: ${formatPromoExpiry(promo.created_at)}

<b>Кто ввёл промокод:</b>
${enteredQuote}

<b>Кто купил или получил дни:</b>
${paidUserQuotes[0]}`,
      reply_markup: keyboard
    });
    for (let index = 1;index < paidUserQuotes.length; index += 1) {
      await telegramApi(env, "sendMessage", {
        chat_id: chatId,
        parse_mode: "HTML",
        text: `<b>Кто купил или получил дни — продолжение:</b>
${paidUserQuotes[index]}`
      });
    }
  }
  async function takePromoReservation(env, userId, code) {
    const result = await env.DB.prepare("DELETE FROM promo_reservations WHERE user_id = ? AND code = ?").bind(userId, code).run();
    return Number(result.meta.changes ?? 0) === 1;
  }
  var partnerTablesReady = null;
  async function ensurePartnerTables(env) {
    if (!partnerTablesReady) {
      partnerTablesReady = (async () => {
        const columns = await env.DB.prepare("PRAGMA table_info(orders)").all();
        const existing = new Set(columns.results.map((column) => column.name));
        const additions = [
          ["partner_code", "TEXT"],
          ["partner_percent", "INTEGER"],
          ["partner_label", "TEXT"],
          ["partner_expires_at", "TEXT"],
          ["partner_referral_expires_at", "TEXT"]
        ];
        for (const [name, definition] of additions) {
          if (!existing.has(name))
            await env.DB.prepare(`ALTER TABLE orders ADD COLUMN ${name} ${definition}`).run();
        }
        const partnerColumns = await env.DB.prepare("PRAGMA table_info(partners)").all();
        if (!partnerColumns.results.some((column) => column.name === "deleted_at"))
          await env.DB.prepare("ALTER TABLE partners ADD COLUMN deleted_at TEXT").run();
        if (!partnerColumns.results.some((column) => column.name === "referral_purchase_expires_at"))
          await env.DB.prepare("ALTER TABLE partners ADD COLUMN referral_purchase_expires_at TEXT").run();
        await env.DB.batch([
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partners (
          code TEXT PRIMARY KEY, percent INTEGER NOT NULL CHECK(percent BETWEEN 1 AND 100), payment_label TEXT NOT NULL,
          expires_at TEXT, referral_purchase_expires_at TEXT, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), deleted_at TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_attributions (
          user_id INTEGER PRIMARY KEY REFERENCES users(telegram_id), partner_code TEXT NOT NULL REFERENCES partners(code),
          attributed_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_rewards (
          order_id TEXT PRIMARY KEY REFERENCES orders(id), partner_code TEXT NOT NULL, amount_rub INTEGER NOT NULL,
          percent INTEGER NOT NULL, reward_kopeks INTEGER NOT NULL, payment_label TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`),
          env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_partner_rewards_code ON partner_rewards(partner_code, created_at DESC)"),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_input_sessions (
          user_id INTEGER PRIMARY KEY REFERENCES users(telegram_id), expires_at TEXT NOT NULL
        )`),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_admin_sessions (
          admin_id INTEGER PRIMARY KEY REFERENCES users(telegram_id),
          action TEXT NOT NULL CHECK(action IN ('extend_partner', 'extend_referral')),
          partner_code TEXT NOT NULL REFERENCES partners(code), expires_at TEXT NOT NULL
        )`),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_accesses (
          partner_code TEXT PRIMARY KEY REFERENCES partners(code), user_id INTEGER NOT NULL UNIQUE REFERENCES users(telegram_id),
          granted_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`),
          env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_partner_accesses_user ON partner_accesses(user_id)"),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_access_sessions (
          admin_id INTEGER PRIMARY KEY REFERENCES users(telegram_id), partner_code TEXT NOT NULL REFERENCES partners(code),
          expires_at TEXT NOT NULL
        )`),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_payout_requests (
          id INTEGER PRIMARY KEY AUTOINCREMENT, partner_code TEXT NOT NULL REFERENCES partners(code),
          requester_user_id INTEGER NOT NULL REFERENCES users(telegram_id), message TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )`),
          env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_partner_payout_requests_user_time ON partner_payout_requests(requester_user_id, created_at DESC)"),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_payout_sessions (
          user_id INTEGER PRIMARY KEY REFERENCES users(telegram_id), partner_code TEXT NOT NULL REFERENCES partners(code),
          request_id INTEGER REFERENCES partner_payout_requests(id), mode TEXT NOT NULL DEFAULT 'create', expires_at TEXT NOT NULL
        )`),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_payout_confirm_sessions (
          admin_id INTEGER PRIMARY KEY REFERENCES users(telegram_id), request_id INTEGER NOT NULL REFERENCES partner_payout_requests(id),
          expires_at TEXT NOT NULL
        )`),
          env.DB.prepare(`CREATE TABLE IF NOT EXISTS partner_archive_selections (
          admin_id INTEGER NOT NULL REFERENCES users(telegram_id), partner_code TEXT NOT NULL REFERENCES partners(code),
          selected_at TEXT NOT NULL DEFAULT (datetime('now')), PRIMARY KEY (admin_id, partner_code)
        )`)
        ]);
        const payoutColumns = await env.DB.prepare("PRAGMA table_info(partner_payout_requests)").all();
        const payoutExisting = new Set(payoutColumns.results.map((column) => column.name));
        const payoutAdditions = [["status", "TEXT NOT NULL DEFAULT 'pending'"], ["amount_kopeks", "INTEGER"], ["confirmed_by", "INTEGER"], ["confirmed_at", "TEXT"], ["edited_at", "TEXT"]];
        for (const [name, definition] of payoutAdditions)
          if (!payoutExisting.has(name))
            await env.DB.prepare(`ALTER TABLE partner_payout_requests ADD COLUMN ${name} ${definition}`).run();
        const sessionColumns = await env.DB.prepare("PRAGMA table_info(partner_payout_sessions)").all();
        const sessionExisting = new Set(sessionColumns.results.map((column) => column.name));
        for (const [name, definition] of [["request_id", "INTEGER"], ["mode", "TEXT NOT NULL DEFAULT 'create'"]])
          if (!sessionExisting.has(name))
            await env.DB.prepare(`ALTER TABLE partner_payout_sessions ADD COLUMN ${name} ${definition}`).run();
        await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_partner_payout_requests_status_time ON partner_payout_requests(status, confirmed_at DESC)").run();
      })().catch((error) => {
        partnerTablesReady = null;
        throw error;
      });
    }
    await partnerTablesReady;
  }
  function normalizePartnerCode(value) {
    const code = value.trim().toUpperCase();
    return /^[A-Z0-9_-]{3,20}$/.test(code) ? code : null;
  }
  function normalizePartnerLabel(value) {
    const label = value.trim().replace(/\s+/g, " ");
    return label.length >= 2 && label.length <= 60 && /^[\p{L}\p{N} ._\-/#]+$/u.test(label) ? label : null;
  }
  function partnerCurrentWhere(alias = "") {
    const p = alias ? `${alias}.` : "";
    return `${p}deleted_at IS NULL AND ${p}active = 1 AND (${p}expires_at IS NULL OR ${p}expires_at > datetime('now'))`;
  }
  async function setPartnerInputSession(env, userId) {
    await ensurePartnerTables(env);
    await env.DB.prepare(`INSERT INTO partner_input_sessions (user_id, expires_at) VALUES (?, datetime('now', '+10 minutes'))
    ON CONFLICT(user_id) DO UPDATE SET expires_at = excluded.expires_at`).bind(userId).run();
  }
  async function takePartnerInputSession(env, userId) {
    await ensurePartnerTables(env);
    const result = await env.DB.prepare("DELETE FROM partner_input_sessions WHERE user_id = ? AND expires_at > datetime('now')").bind(userId).run();
    return Number(result.meta.changes ?? 0) === 1;
  }
  async function setPartnerAdminSession(env, adminId, action, code) {
    await ensurePartnerTables(env);
    await env.DB.prepare(`INSERT INTO partner_admin_sessions (admin_id, action, partner_code, expires_at) VALUES (?, ?, ?, datetime('now', '+10 minutes'))
    ON CONFLICT(admin_id) DO UPDATE SET action = excluded.action, partner_code = excluded.partner_code, expires_at = excluded.expires_at`).bind(adminId, action, code).run();
  }
  async function takePartnerAdminSession(env, adminId) {
    await ensurePartnerTables(env);
    const session = await env.DB.prepare("SELECT action, partner_code FROM partner_admin_sessions WHERE admin_id = ? AND expires_at > datetime('now')").bind(adminId).first();
    if (session)
      await env.DB.prepare("DELETE FROM partner_admin_sessions WHERE admin_id = ?").bind(adminId).run();
    return session ?? null;
  }
  async function applyPartnerAdminDays(env, chatId, session, rawDays) {
    const days = Number(rawDays.trim());
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      await sendMessage(env, chatId, "Укажите целое число дней от 1 до 3650. Откройте нужное действие ещё раз.");
      return;
    }
    const modifier = `+${days} days`;
    const allowed = `deleted_at IS NULL AND NOT (${partnerArchiveWhere()})`;
    const statement = session.action === "extend_partner" ? `UPDATE partners SET expires_at = datetime(CASE WHEN expires_at IS NULL OR expires_at <= datetime('now') THEN 'now' ELSE expires_at END, ?), active = 1, updated_at = datetime('now') WHERE code = ? AND ${allowed}` : `UPDATE partners SET referral_purchase_expires_at = datetime(CASE WHEN referral_purchase_expires_at IS NULL OR referral_purchase_expires_at <= datetime('now') THEN 'now' ELSE referral_purchase_expires_at END, ?), updated_at = datetime('now') WHERE code = ? AND ${allowed}`;
    const result = await env.DB.prepare(statement).bind(modifier, session.partner_code).run();
    if (!Number(result.meta.changes ?? 0)) {
      await sendMessage(env, chatId, "Эту партнёрку нельзя изменить: она уже в архиве или удалена из панели.");
      return;
    }
    const partner = await env.DB.prepare("SELECT expires_at, referral_purchase_expires_at FROM partners WHERE code = ?").bind(session.partner_code).first();
    const date = session.action === "extend_partner" ? partner?.expires_at : partner?.referral_purchase_expires_at;
    const text = session.action === "extend_partner" ? `Партнёрка ${session.partner_code} продлена до: ${formatPartnerExpiry(date ?? null)}.` : `Учёт покупок рефералов продлён до: ${formatPartnerExpiry(date ?? null)}.`;
    await sendMessage(env, chatId, text);
    await sendPartnerInfo(env, chatId, session.partner_code, "current");
  }
  async function setPartnerAccessSession(env, adminId, code) {
    await ensurePartnerTables(env);
    await env.DB.prepare(`INSERT INTO partner_access_sessions (admin_id, partner_code, expires_at) VALUES (?, ?, datetime('now', '+10 minutes'))
    ON CONFLICT(admin_id) DO UPDATE SET partner_code = excluded.partner_code, expires_at = excluded.expires_at`).bind(adminId, code).run();
  }
  async function takePartnerAccessSession(env, adminId) {
    await ensurePartnerTables(env);
    const session = await env.DB.prepare("SELECT partner_code FROM partner_access_sessions WHERE admin_id = ? AND expires_at > datetime('now')").bind(adminId).first();
    if (session)
      await env.DB.prepare("DELETE FROM partner_access_sessions WHERE admin_id = ?").bind(adminId).run();
    return session?.partner_code ?? null;
  }
  async function getPartnerAccess(env, userId) {
    await ensurePartnerTables(env);
    return env.DB.prepare(`SELECT a.partner_code, a.user_id, u.username, u.first_name, a.granted_at
    FROM partner_accesses a JOIN users u ON u.telegram_id = a.user_id WHERE a.user_id = ?`).bind(userId).first();
  }
  async function setPartnerPayoutSession(env, userId, code, mode = "create", requestId = null) {
    await ensurePartnerTables(env);
    await env.DB.prepare(`INSERT INTO partner_payout_sessions (user_id, partner_code, request_id, mode, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+10 minutes'))
    ON CONFLICT(user_id) DO UPDATE SET partner_code = excluded.partner_code, request_id = excluded.request_id, mode = excluded.mode, expires_at = excluded.expires_at`).bind(userId, code, requestId, mode).run();
  }
  async function takePartnerPayoutSession(env, userId) {
    await ensurePartnerTables(env);
    const session = await env.DB.prepare("SELECT partner_code, request_id, mode FROM partner_payout_sessions WHERE user_id = ? AND expires_at > datetime('now')").bind(userId).first();
    if (session)
      await env.DB.prepare("DELETE FROM partner_payout_sessions WHERE user_id = ?").bind(userId).run();
    return session ?? null;
  }
  async function currentPartnerPayout(env, userId, code) {
    await ensurePartnerTables(env);
    return env.DB.prepare("SELECT id, partner_code, requester_user_id, message, status, amount_kopeks, confirmed_at, edited_at, created_at FROM partner_payout_requests WHERE requester_user_id = ? AND partner_code = ? AND (status = 'pending' OR (status = 'paid' AND confirmed_at > datetime('now', '-3 days'))) ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, COALESCE(confirmed_at, created_at) DESC LIMIT 1").bind(userId, code).first();
  }
  async function claimPartnerAttribution(env, userId, code) {
    await ensurePartnerTables(env);
    await env.DB.prepare(`INSERT OR IGNORE INTO partner_attributions (user_id, partner_code)
    SELECT ?, code FROM partners WHERE code = ? AND ${partnerCurrentWhere()}`).bind(userId, code).run();
  }
  async function getPartnerOrderAttribution(env, userId) {
    await ensurePartnerTables(env);
    return env.DB.prepare(`SELECT p.code, p.percent, p.payment_label, p.expires_at, p.referral_purchase_expires_at
    FROM partner_attributions a JOIN partners p ON p.code = a.partner_code
    WHERE a.user_id = ? AND ${partnerCurrentWhere("p")}
      AND p.referral_purchase_expires_at IS NOT NULL AND p.referral_purchase_expires_at > datetime('now')`).bind(userId).first();
  }
  function formatPartnerExpiry(expiresAt) {
    return expiresAt ? formatPromoExpiry(expiresAt) : "без срока";
  }
  function formatKopeks(kopeks) {
    return `${Math.floor(kopeks / 100)}.${String(kopeks % 100).padStart(2, "0")} ₽`;
  }
  async function partnerAvailableBalance(env, code) {
    await ensurePartnerTables(env);
    const row = await env.DB.prepare(`SELECT COALESCE((SELECT SUM(reward_kopeks) FROM partner_rewards WHERE partner_code = ?), 0) - COALESCE((SELECT SUM(amount_kopeks) FROM partner_payout_requests WHERE partner_code = ? AND status = 'paid'), 0) AS balance`).bind(code, code).first();
    return Math.max(0, Number(row?.balance ?? 0));
  }
  function payoutWhere(category) {
    return category === "pending" ? "r.status = 'pending'" : category === "paid" ? "r.status = 'paid' AND r.confirmed_at > datetime('now', '-7 days')" : "r.status = 'paid' AND r.confirmed_at <= datetime('now', '-7 days')";
  }
  function payoutTitle(category) {
    return category === "pending" ? "Ожидают подтверждения" : category === "paid" ? "Выведены за 7 дней" : "Архив выводов";
  }
  async function sendPayoutHub(env, chatId) {
    await ensurePartnerTables(env);
    const rows = await env.DB.batch(["pending", "paid", "archive"].map((category) => env.DB.prepare(`SELECT COUNT(*) AS count FROM partner_payout_requests r WHERE ${payoutWhere(category)}`)));
    const count = (index) => Number(rows[index].results[0]?.count ?? 0);
    await sendMessage(env, chatId, "Выводы партнёров", { inline_keyboard: [
      [{ text: `⏳ Ожидают (${count(0)})`, callback_data: "admin:payout:list:pending:0" }],
      [{ text: `✅ Выведены (${count(1)})`, callback_data: "admin:payout:list:paid:0" }],
      [{ text: `\uD83D\uDDC3 Архив (${count(2)})`, callback_data: "admin:payout:list:archive:0" }],
      [{ text: "‹ К партнёркам", callback_data: "admin:partner:hub" }]
    ] });
  }
  async function sendPayoutList(env, chatId, category, page) {
    await ensurePartnerTables(env);
    const pageSize = 10;
    const where = payoutWhere(category);
    const total = Number((await env.DB.prepare(`SELECT COUNT(*) AS count FROM partner_payout_requests r WHERE ${where}`).first())?.count ?? 0);
    if (!total) {
      await sendMessage(env, chatId, `${payoutTitle(category)}: нет.`);
      return;
    }
    const last = Math.max(0, Math.ceil(total / pageSize) - 1);
    const current = Math.min(Math.max(0, page), last);
    const result = await env.DB.prepare(`SELECT r.id, r.partner_code, r.requester_user_id, u.username, u.first_name, r.message, r.status, r.amount_kopeks, r.confirmed_at, r.created_at FROM partner_payout_requests r JOIN users u ON u.telegram_id = r.requester_user_id WHERE ${where} ORDER BY COALESCE(r.confirmed_at, r.created_at) DESC LIMIT ? OFFSET ?`).bind(pageSize, current * pageSize).all();
    const buttons = result.results.map((request) => [{ text: `${category === "pending" ? "⏳" : category === "paid" ? "✅" : "\uD83D\uDDC3"} #${request.id} · ${request.partner_code}`, callback_data: `admin:payout:view:${request.id}:${category}` }]);
    const nav = [];
    if (current)
      nav.push({ text: "‹ Назад", callback_data: `admin:payout:list:${category}:${current - 1}` });
    if (current < last)
      nav.push({ text: "Вперёд ›", callback_data: `admin:payout:list:${category}:${current + 1}` });
    if (nav.length)
      buttons.push(nav);
    buttons.push([{ text: "‹ К выводам", callback_data: "admin:payout:hub" }]);
    await sendMessage(env, chatId, `${payoutTitle(category)}: ${total}
Страница ${current + 1} из ${last + 1}`, { inline_keyboard: buttons });
  }
  async function sendPayoutInfo(env, chatId, id, category) {
    await ensurePartnerTables(env);
    const request = await env.DB.prepare("SELECT r.id, r.partner_code, r.requester_user_id, u.username, u.first_name, r.message, r.status, r.amount_kopeks, r.confirmed_at, r.created_at FROM partner_payout_requests r JOIN users u ON u.telegram_id = r.requester_user_id WHERE r.id = ?").bind(id).first();
    if (!request) {
      await sendMessage(env, chatId, "Заявка на вывод не найдена.");
      return;
    }
    const account = request.username ? `@${escapeHtml(request.username)}` : escapeHtml(request.first_name ?? "Без имени");
    const details = request.message ? `<blockquote expandable>${escapeHtml(request.message)}</blockquote>` : "Не указаны.";
    const amount = request.amount_kopeks === null ? "ещё не подтверждена" : formatKopeks(request.amount_kopeks);
    const balance = await partnerAvailableBalance(env, request.partner_code);
    const keyboard = request.status === "pending" ? [[{ text: "✅ Подтвердить вывод", callback_data: `admin:payout:confirm:${request.id}` }], [{ text: "\uD83D\uDCCB К списку", callback_data: `admin:payout:list:${category}:0` }]] : [[{ text: "\uD83D\uDCCB К списку", callback_data: `admin:payout:list:${category}:0` }]];
    await telegramApi(env, "sendMessage", { chat_id: chatId, parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard }, text: `Заявка #<code>${request.id}</code>
Статус: ${request.status === "pending" ? "ожидает" : "выведена"}
Партнёрка: <code>${escapeHtml(request.partner_code)}</code>
Партнёр: ${account} · ID <code>${request.requester_user_id}</code>
Сумма вывода: ${amount}
Доступный баланс сейчас: ${formatKopeks(balance)}
Создана: ${formatPromoExpiry(request.created_at)}
${request.confirmed_at ? `Подтверждена: ${formatPromoExpiry(request.confirmed_at)}
` : ""}
Реквизиты и сообщение:
${details}` });
  }
  async function setPayoutConfirmSession(env, adminId, requestId) {
    await ensurePartnerTables(env);
    await env.DB.prepare("INSERT INTO partner_payout_confirm_sessions (admin_id, request_id, expires_at) VALUES (?, ?, datetime('now', '+10 minutes')) ON CONFLICT(admin_id) DO UPDATE SET request_id = excluded.request_id, expires_at = excluded.expires_at").bind(adminId, requestId).run();
  }
  async function takePayoutConfirmSession(env, adminId) {
    await ensurePartnerTables(env);
    const session = await env.DB.prepare("SELECT request_id FROM partner_payout_confirm_sessions WHERE admin_id = ? AND expires_at > datetime('now')").bind(adminId).first();
    if (session)
      await env.DB.prepare("DELETE FROM partner_payout_confirm_sessions WHERE admin_id = ?").bind(adminId).run();
    return session ?? null;
  }
  async function confirmPartnerPayout(env, chatId, adminId, requestId, rawAmount) {
    if (!/^\d+(?:[.,]\d{1,2})?$/.test(rawAmount.trim())) {
      await sendMessage(env, chatId, "Укажите сумму в рублях, например: 250 или 250.50.");
      return;
    }
    const kopeks = Math.round(Number(rawAmount.replace(",", ".")) * 100);
    if (!Number.isSafeInteger(kopeks) || kopeks < 1) {
      await sendMessage(env, chatId, "Сумма должна быть больше нуля.");
      return;
    }
    const request = await env.DB.prepare("SELECT id, partner_code, requester_user_id FROM partner_payout_requests WHERE id = ? AND status = 'pending'").bind(requestId).first();
    if (!request) {
      await sendMessage(env, chatId, "Заявка уже подтверждена или не найдена.");
      return;
    }
    const changed = await env.DB.prepare(`UPDATE partner_payout_requests SET status = 'paid', amount_kopeks = ?, confirmed_by = ?, confirmed_at = datetime('now') WHERE id = ? AND status = 'pending' AND ? <= COALESCE((SELECT SUM(reward_kopeks) FROM partner_rewards WHERE partner_code = ?), 0) - COALESCE((SELECT SUM(amount_kopeks) FROM partner_payout_requests WHERE partner_code = ? AND status = 'paid'), 0)`).bind(kopeks, adminId, requestId, kopeks, request.partner_code, request.partner_code).run();
    if (!Number(changed.meta.changes ?? 0)) {
      await sendMessage(env, chatId, "Подтверждение невозможно: заявка уже обработана или указанная сумма превышает доступный баланс.");
      return;
    }
    await sendMessage(env, chatId, `Вывод по заявке #${requestId} подтверждён. Списано с баланса партнёра: ${formatKopeks(kopeks)}.`);
    try {
      await sendMessage(env, request.requester_user_id, `✅ Выплата по вашей заявке подтверждена.
Сумма: ${formatKopeks(kopeks)}.
Она списана из партнёрского баланса. Зачисление может занимать до 5 рабочих дней; ускорить его невозможно.`);
    } catch (error) {
      console.error("Could not notify partner about confirmed payout", error);
    }
  }
  function partnerFinishedWhere(alias = "") {
    const p = alias ? `${alias}.` : "";
    return `${p}deleted_at IS NULL AND (( ${p}active = 0 AND ${p}updated_at > datetime('now', '-15 days')) OR (${p}active = 1 AND ${p}expires_at IS NOT NULL AND ${p}expires_at <= datetime('now') AND ${p}expires_at > datetime('now', '-15 days')))`;
  }
  function partnerArchiveWhere(alias = "") {
    const p = alias ? `${alias}.` : "";
    return `${p}deleted_at IS NULL AND (( ${p}active = 0 AND ${p}updated_at <= datetime('now', '-15 days')) OR (${p}active = 1 AND ${p}expires_at IS NOT NULL AND ${p}expires_at <= datetime('now', '-15 days')))`;
  }
  function partnerListWhere(category) {
    return category === "current" ? partnerCurrentWhere() : category === "finished" ? partnerFinishedWhere() : partnerArchiveWhere();
  }
  function partnerListTitle(category) {
    return category === "current" ? "Действующие партнёрки" : category === "finished" ? "Завершённые за 15 дней" : "Архив партнёрок";
  }
  async function sendPartnerHub(env, chatId) {
    await ensurePartnerTables(env);
    const [current, finished, archived] = await env.DB.batch([
      env.DB.prepare(`SELECT COUNT(*) AS count FROM partners WHERE ${partnerCurrentWhere()}`),
      env.DB.prepare(`SELECT COUNT(*) AS count FROM partners WHERE ${partnerFinishedWhere()}`),
      env.DB.prepare(`SELECT COUNT(*) AS count FROM partners WHERE ${partnerArchiveWhere()}`)
    ]);
    const countAt = (result) => Number(result.results[0]?.count ?? 0);
    await sendMessage(env, chatId, `Партнёрки

Вознаграждение начисляется только после успешной оплаты.`, { inline_keyboard: [
      [{ text: "➕ Создать партнёрку", callback_data: "admin:partner:create" }],
      [{ text: `✅ Действующие (${countAt(current)})`, callback_data: "admin:partner:list:current:0" }],
      [{ text: `⌛ Завершённые за 15 дней (${countAt(finished)})`, callback_data: "admin:partner:list:finished:0" }],
      [{ text: `\uD83D\uDDC3 Архив (${countAt(archived)})`, callback_data: "admin:partner:list:archive:0" }],
      [{ text: "\uD83D\uDCB8 Выводы", callback_data: "admin:payout:hub" }]
    ] });
  }
  async function selectedArchivedCodes(env, adminId) {
    const result = await env.DB.prepare("SELECT partner_code FROM partner_archive_selections WHERE admin_id = ?").bind(adminId).all();
    return new Set(result.results.map((row) => row.partner_code));
  }
  async function sendPartnerList(env, chatId, category, page, adminId) {
    await ensurePartnerTables(env);
    const pageSize = 10;
    const where = partnerListWhere(category);
    const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM partners WHERE ${where}`).first();
    const total = Number(totalRow?.count ?? 0);
    if (!total) {
      await sendMessage(env, chatId, category === "archive" ? "Архив пуст." : "Записей пока нет.");
      return;
    }
    const lastPage = Math.max(0, Math.ceil(total / pageSize) - 1);
    const current = Math.min(Math.max(0, page), lastPage);
    const result = await env.DB.prepare(`SELECT code, percent, payment_label, expires_at, referral_purchase_expires_at, active, created_at, updated_at, deleted_at FROM partners WHERE ${where}
    ORDER BY CASE WHEN active = 0 THEN updated_at ELSE expires_at END DESC, code ASC LIMIT ? OFFSET ?`).bind(pageSize, current * pageSize).all();
    const selected = category === "archive" ? await selectedArchivedCodes(env, adminId) : new Set;
    const rows = [];
    for (const partner of result.results) {
      if (category === "archive")
        rows.push([
          { text: selected.has(partner.code) ? "☑️" : "◻️", callback_data: `admin:partner:archive:toggle:${partner.code}:${current}` },
          { text: `${partner.code} · ${partner.percent}%`, callback_data: `admin:partner:view:${partner.code}:${category}` }
        ]);
      else
        rows.push([{ text: `${category === "current" ? "✅" : "⌛"} ${partner.code} · ${partner.percent}%`, callback_data: `admin:partner:view:${partner.code}:${category}` }]);
    }
    if (category === "archive") {
      rows.push([{ text: "☑️ Выбрать все в архиве", callback_data: "admin:partner:archive:selectall" }]);
      rows.push([{ text: `\uD83D\uDDD1 Удалить выбранные (${selected.size})`, callback_data: "admin:partner:archive:delete_selected" }]);
    }
    const nav = [];
    if (current)
      nav.push({ text: "‹ Назад", callback_data: `admin:partner:list:${category}:${current - 1}` });
    if (current < lastPage)
      nav.push({ text: "Вперёд ›", callback_data: `admin:partner:list:${category}:${current + 1}` });
    if (nav.length)
      rows.push(nav);
    rows.push([{ text: "‹ К партнёркам", callback_data: "admin:partner:hub" }]);
    await sendMessage(env, chatId, `${partnerListTitle(category)}: ${total}
Страница ${current + 1} из ${lastPage + 1}`, { inline_keyboard: rows });
  }
  async function sendPartnerInfo(env, chatId, code, category = "current") {
    await ensurePartnerTables(env);
    const partner = await env.DB.prepare("SELECT code, percent, payment_label, expires_at, referral_purchase_expires_at, active, created_at, updated_at, deleted_at FROM partners WHERE code = ? AND deleted_at IS NULL").bind(code).first();
    if (!partner) {
      await sendMessage(env, chatId, "Партнёрка не найдена.");
      return;
    }
    const stats = await env.DB.prepare(`SELECT COUNT(*) AS purchases, COALESCE(SUM(amount_rub), 0) AS turnover, COALESCE(SUM(reward_kopeks), 0) AS reward FROM partner_rewards WHERE partner_code = ?`).bind(code).first();
    const available = await partnerAvailableBalance(env, code);
    const active = partner.active === 1 && (!partner.expires_at || partner.expires_at > new Date().toISOString().slice(0, 19).replace("T", " "));
    const link = `https://t.me/BananchikiVpnBot?start=partner_${partner.code}`;
    const access = await env.DB.prepare(`SELECT a.partner_code, a.user_id, u.username, u.first_name, a.granted_at FROM partner_accesses a JOIN users u ON u.telegram_id = a.user_id WHERE a.partner_code = ?`).bind(code).first();
    const accessText = access ? `
Доступ партнёра: ${access.username ? `@${escapeHtml(access.username)}` : escapeHtml(access.first_name ?? "Без имени")} · <code>${access.user_id}</code>` : `
Доступ партнёра: не выдан`;
    const rows = [];
    if (active)
      rows.push([{ text: "⛔ Отключить партнёрку", callback_data: `admin:partner:disable:${partner.code}` }]);
    if (category === "archive")
      rows.push([{ text: "\uD83D\uDDD1 Выбрать для удаления", callback_data: `admin:partner:archive:toggle:${partner.code}:0` }]);
    else {
      rows.push([{ text: "\uD83D\uDCC5 Продлить партнёрку", callback_data: `admin:partner:extend:${partner.code}` }]);
      rows.push([{ text: partner.referral_purchase_expires_at ? "\uD83D\uDED2 Продлить учёт покупок" : "\uD83D\uDED2 Настроить учёт покупок", callback_data: `admin:partner:referralperiod:${partner.code}` }]);
      rows.push([{ text: access ? "\uD83D\uDC64 Изменить доступ партнёра" : "\uD83D\uDC64 Выдать доступ партнёру", callback_data: `admin:partner:grant:${partner.code}` }]);
    }
    rows.push([{ text: "\uD83D\uDCCB К списку", callback_data: `admin:partner:list:${category}:0` }]);
    await telegramApi(env, "sendMessage", { chat_id: chatId, parse_mode: "HTML", reply_markup: { inline_keyboard: rows }, text: `Партнёрка: <code>${escapeHtml(partner.code)}</code>
Статус: ${active ? "активна" : "завершена или отключена"}
Процент: ${partner.percent}%
Пометка платежа: ${escapeHtml(partner.payment_label)}
Действует до: ${formatPartnerExpiry(partner.expires_at)}
Покупки рефералов учитываются до: ${formatPartnerExpiry(partner.referral_purchase_expires_at)}${accessText}

Ссылка партнёра:
<code>${link}</code>

Успешных покупок: ${Number(stats?.purchases ?? 0)}
Оборот: ${Number(stats?.turnover ?? 0)} ₽
К выплате партнёру: ${formatKopeks(available)}` });
  }
  async function sendPartnerDashboard(env, chatId, userId) {
    const access = await getPartnerAccess(env, userId);
    if (!access) {
      await sendMessage(env, chatId, "Доступ к партнёрской статистике не выдан.");
      return;
    }
    const partner = await env.DB.prepare("SELECT code, percent, payment_label, expires_at, referral_purchase_expires_at, active, created_at, updated_at FROM partners WHERE code = ?").bind(access.partner_code).first();
    if (!partner) {
      await sendMessage(env, chatId, "Партнёрка не найдена.");
      return;
    }
    const stats = await env.DB.prepare(`SELECT COUNT(*) AS purchases, COALESCE(SUM(amount_rub), 0) AS turnover FROM partner_rewards WHERE partner_code = ?`).bind(partner.code).first();
    const available = await partnerAvailableBalance(env, partner.code);
    const active = partner.active === 1 && (!partner.expires_at || partner.expires_at > new Date().toISOString().slice(0, 19).replace("T", " "));
    const link = `https://t.me/BananchikiVpnBot?start=partner_${partner.code}`;
    const payout = await currentPartnerPayout(env, userId, partner.code);
    const statusText = !payout ? "Заявка на вывод: нет" : payout.status === "pending" ? `Заявка на вывод: ожидает (#${payout.id})` : `Заявка на вывод: выведено (${formatKopeks(payout.amount_kopeks ?? 0)}). Она исчезнет из этого раздела через 3 дня.`;
    const keyboard = [];
    if (!payout)
      keyboard.push([{ text: "\uD83D\uDCB8 Запросить вывод средств", callback_data: `partner:payout:start:${partner.code}` }]);
    else if (payout.status === "pending" && !payout.edited_at)
      keyboard.push([{ text: "✏️ Изменить заявку", callback_data: `partner:payout:edit:${payout.id}` }]);
    await telegramApi(env, "sendMessage", { chat_id: chatId, parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard }, text: `Ваша партнёрка: <code>${escapeHtml(partner.code)}</code>
Статус: ${active ? "активна" : "завершена или отключена"}
Процент: ${partner.percent}%
Действует до: ${formatPartnerExpiry(partner.expires_at)}
Покупки рефералов учитываются до: ${formatPartnerExpiry(partner.referral_purchase_expires_at)}
${statusText}

Ваша ссылка:
<code>${link}</code>

Успешных покупок: ${Number(stats?.purchases ?? 0)}
Оборот: ${Number(stats?.turnover ?? 0)} ₽
К выплате: ${formatKopeks(available)}

Отключить партнёрку может только администратор.` });
  }
  function isValidPayoutDetails(value) {
    const digits = (value.match(/\d/g) ?? []).length;
    const letters = (value.match(/\p{L}/gu) ?? []).length;
    return digits >= 10 && digits <= 19 && letters >= 2;
  }
  async function showPartnerPayoutOptions(env, chatId, userId, code) {
    const access = await getPartnerAccess(env, userId);
    if (!access || access.partner_code !== code) {
      await sendMessage(env, chatId, "Доступ к этой партнёрке не выдан.");
      return;
    }
    if (await currentPartnerPayout(env, userId, code)) {
      await sendMessage(env, chatId, "У вас уже есть ожидающая или недавно выведенная заявка. Откройте /partner.");
      return;
    }
    await setPartnerPayoutSession(env, userId, code);
    await sendMessage(env, chatId, `Для выплаты обязательно отправьте одним сообщением номер карты или номер телефона и название банка. При желании добавьте комментарий.

Вывод может занимать до 5 рабочих дней, но обычно происходит быстрее. Ускорить вывод средств невозможно.

Возникли проблемы — обращайтесь к администратору @Olivarqy.`);
  }
  async function startPartnerPayoutEdit(env, chatId, userId, id) {
    const request = await env.DB.prepare("SELECT id, partner_code FROM partner_payout_requests WHERE id = ? AND requester_user_id = ? AND status = 'pending' AND edited_at IS NULL").bind(id, userId).first();
    if (!request) {
      await sendMessage(env, chatId, "Эту заявку уже нельзя изменить. Откройте /partner, чтобы увидеть актуальный статус.");
      return;
    }
    await setPartnerPayoutSession(env, userId, request.partner_code, "edit", request.id);
    await sendMessage(env, chatId, "Отправьте новые реквизиты: номер карты или телефона и название банка. Можно добавить комментарий. Изменить заявку можно только один раз.");
  }
  async function submitPartnerPayout(env, chatId, user, session, note) {
    const access = await getPartnerAccess(env, user.id);
    if (!access || access.partner_code !== session.partner_code) {
      await sendMessage(env, chatId, "Доступ к этой партнёрке не выдан.");
      return;
    }
    let requestId;
    if (session.mode === "edit") {
      const changed = await env.DB.prepare("UPDATE partner_payout_requests SET message = ?, edited_at = datetime('now') WHERE id = ? AND requester_user_id = ? AND partner_code = ? AND status = 'pending' AND edited_at IS NULL").bind(note, session.request_id, user.id, session.partner_code).run();
      if (!Number(changed.meta.changes ?? 0)) {
        await sendMessage(env, chatId, "Заявку уже нельзя изменить. Откройте /partner, чтобы увидеть актуальный статус.");
        return;
      }
      requestId = Number(session.request_id);
    } else {
      const inserted = await env.DB.prepare(`INSERT INTO partner_payout_requests (partner_code, requester_user_id, message)
      SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM partner_payout_requests WHERE requester_user_id = ? AND status = 'pending')
      RETURNING id`).bind(session.partner_code, user.id, note, user.id).first();
      if (!inserted?.id) {
        await sendMessage(env, chatId, "У вас уже есть ожидающая заявка. Откройте /partner.");
        return;
      }
      requestId = inserted.id;
    }
    const adminId = env.ADMIN_TELEGRAM_ID ? Number(env.ADMIN_TELEGRAM_ID) : NaN;
    if (Number.isSafeInteger(adminId)) {
      const account = user.username ? `@${escapeHtml(user.username)}` : escapeHtml(user.first_name || "Без имени");
      await telegramApi(env, "sendMessage", { chat_id: adminId, parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "✅ Подтвердить вывод", callback_data: `admin:payout:confirm:${requestId}` }], [{ text: "\uD83D\uDCCB Открыть в ожидающих", callback_data: `admin:payout:view:${requestId}:pending` }]] }, text: `${session.mode === "edit" ? "✏️ <b>Заявка на вывод изменена</b>" : "\uD83D\uDCB8 <b>Запрос вывода средств</b>"} #${requestId}

Партнёрка: <code>${escapeHtml(session.partner_code)}</code>
Партнёр: ${account} · ID: <code>${user.id}</code>
Реквизиты и сообщение:
<blockquote expandable>${escapeHtml(note)}</blockquote>` });
    }
    await sendMessage(env, chatId, session.mode === "edit" ? "Заявка изменена и снова отправлена администратору." : "Запрос на вывод отправлен администратору.");
  }
  async function createPartnerFromInput(env, chatId, text) {
    const parts = text.trim().split(/\s+/);
    const code = normalizePartnerCode(parts.shift() ?? "");
    const percent = Number(parts.shift());
    let expiry = null;
    if (parts[0] && /^\d{2}\.\d{2}\.\d{4}$/.test(parts[0])) {
      const raw = parts.shift();
      const parsedExpiry = parsePromoExpiry(raw);
      if (parsedExpiry === undefined) {
        await sendMessage(env, chatId, "Неверная дата.");
        return;
      }
      expiry = parsedExpiry;
    }
    const label = normalizePartnerLabel(parts.join(" "));
    if (!code || !Number.isInteger(percent) || percent < 1 || percent > 100 || !label) {
      await sendMessage(env, chatId, "Неверный формат. Пример: PARTNER1 20 31.12.2026 Осень 2026");
      return;
    }
    await ensurePartnerTables(env);
    await env.DB.prepare(`INSERT INTO partners (code, percent, payment_label, expires_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(code) DO UPDATE SET percent = excluded.percent, payment_label = excluded.payment_label, expires_at = excluded.expires_at, active = 1, deleted_at = NULL, updated_at = datetime('now')`).bind(code, percent, label, expiry).run();
    await sendMessage(env, chatId, "Партнёрка создана. Теперь настройте отдельный срок, до которого покупки новых рефералов будут учитываться.");
    await sendPartnerInfo(env, chatId, code, "current");
  }
  async function recordPartnerReward(env, orderId) {
    await ensurePartnerTables(env);
    await env.DB.prepare(`INSERT OR IGNORE INTO partner_rewards (order_id, partner_code, amount_rub, percent, reward_kopeks, payment_label)
    SELECT o.id, o.partner_code, o.amount_rub, o.partner_percent, o.amount_rub * o.partner_percent, o.partner_label
    FROM orders o JOIN partners p ON p.code = o.partner_code
    WHERE o.id = ? AND o.status = 'paid' AND o.partner_code IS NOT NULL AND o.partner_percent IS NOT NULL
      AND o.partner_referral_expires_at IS NOT NULL AND o.partner_referral_expires_at > datetime('now'))`).bind(orderId).run();
  }
  function startPartnerCode(text) {
    const match = /^\/start(?:@[A-Za-z0-9_]+)?\s+partner_([A-Za-z0-9_-]{3,20})$/i.exec(text.trim());
    return match ? normalizePartnerCode(match[1]) : null;
  }
  async function sendPlans(env, chatId, telegramId) {
    const user = await getUser(env, telegramId);
    const trialText = user?.trial_activated ? `
Пробный период уже активирован.` : `
Доступен бесплатный пробный период на 3 дня (один раз на аккаунт).`;
    await sendMessage(env, chatId, `Premium — единая подписка без лишних развилок.${trialText}

Подписку можно подключить на 2 устройства.

Выберите удобный срок или начните с трёх бесплатных дней.`, planKeyboard());
  }
  async function sendSubscriptionStatus(env, chatId, telegramId) {
    const subscription = await getActiveSubscription(env, telegramId, "premium");
    if (!subscription?.expiration_at) {
      await sendMessage(env, chatId, "Сейчас у вас нет активной подписки Premium.");
      return;
    }
    const expiration = new Date(`${subscription.expiration_at.replace(" ", "T")}Z`);
    const days = Math.max(1, Math.ceil((expiration.getTime() - Date.now()) / 86400000));
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
    const header = `Активная подписка: Premium
Осталось: ${days} дн.
Действует до: ${date}`;
    if (current.happ_install_code)
      await sendSubscriptionChoice(env, chatId, `${header}

Ваша ссылка Happ:`, true, true);
    else
      await sendMessage(env, chatId, `${header}

Не удалось подготовить ссылку. Попробуйте снова через минуту.`);
  }
  async function createYooKassaPayment(env, orderId, amountRub, partner) {
    requireConfig(env, ["YOOKASSA_SHOP_ID", "YOOKASSA_SECRET_KEY"]);
    const authorization = btoa(`${env.YOOKASSA_SHOP_ID}:${env.YOOKASSA_SECRET_KEY}`);
    const response = await fetch("https://api.yookassa.ru/v3/payments", {
      method: "POST",
      headers: { authorization: `Basic ${authorization}`, "content-type": "application/json", "Idempotence-Key": orderId },
      body: JSON.stringify({
        amount: { value: amountRub.toFixed(2), currency: "RUB" },
        capture: true,
        confirmation: { type: "redirect", return_url: `${WORKER_URL}/` },
        metadata: { order_id: orderId, ...partner ? { partner_code: partner.code, partner_label: partner.payment_label } : {} },
        ...partner ? { description: `Premium · ${partner.payment_label}` } : {}
      })
    });
    let payment;
    try {
      payment = await response.json();
    } catch {
      throw new Error(`YooKassa returned non-JSON response (${response.status})`);
    }
    if (!response.ok)
      throw new Error(`YooKassa payment creation failed (${response.status})`);
    const confirmation = payment && typeof payment === "object" ? payment.confirmation : null;
    const confirmationUrl = confirmation && typeof confirmation === "object" ? confirmation.confirmation_url : null;
    if (typeof confirmationUrl !== "string" || !confirmationUrl.startsWith("https://"))
      throw new Error("YooKassa response did not include a valid confirmation URL");
    return confirmationUrl;
  }
  async function createOrder(env, chatId, telegramId, plan, duration, options) {
    requireConfig(env, ["YOOKASSA_SHOP_ID", "YOOKASSA_SECRET_KEY"]);
    const amount = options?.amountRub ?? PRODUCTS[plan][duration];
    const durationDays = options?.durationDays ?? null;
    const displayPeriod = options?.displayPeriod ?? `${duration} мес.`;
    const renewal = isRenewalSubscription(await getSubscription(env, telegramId, plan));
    const orderId = crypto.randomUUID();
    const placeholderUrl = `${WORKER_URL}/`;
    const partner = await getPartnerOrderAttribution(env, telegramId);
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO orders (id, user_id, plan, duration_months, duration_days, amount_rub, promo_code, partner_code, partner_percent, partner_label, partner_expires_at, partner_referral_expires_at, quickpay_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(orderId, telegramId, plan, duration, durationDays, amount, options?.promoCode ?? null, partner?.code ?? null, partner?.percent ?? null, partner?.payment_label ?? null, partner?.expires_at ?? null, partner?.referral_purchase_expires_at ?? null, placeholderUrl),
      env.DB.prepare("UPDATE users SET updated_at = datetime('now') WHERE telegram_id = ?").bind(telegramId)
    ]);
    let paymentUrl;
    try {
      paymentUrl = await createYooKassaPayment(env, orderId, amount, partner);
    } catch (error) {
      await env.DB.prepare("UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending'").bind(orderId).run();
      throw error;
    }
    await env.DB.prepare("UPDATE orders SET quickpay_url = ? WHERE id = ? AND status = 'pending'").bind(paymentUrl, orderId).run();
    await sendMessage(env, chatId, `${options?.testOrder ? "Тестовый заказ" : renewal ? "Заказ на продление" : "Покупка Premium"}: ${displayPeriod} — ${amount} ₽.

После подтверждения платежа бот ${renewal ? "продлит доступ" : "оформит подписку"} и пришлёт ссылку на подписку.`, { inline_keyboard: [[{ text: "Оплатить через ЮKassa", url: paymentUrl }]] });
  }
  async function activateFreePromoDays(env, chatId, telegramId, code, days) {
    const wasActive = isRenewalSubscription(await getSubscription(env, telegramId, "premium"));
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO subscriptions (user_id, plan, expiration_at)
       VALUES (?, 'premium', datetime('now', ?))
       ON CONFLICT(user_id, plan) DO UPDATE SET
         expiration_at = datetime(CASE WHEN subscriptions.expiration_at > datetime('now') THEN subscriptions.expiration_at ELSE datetime('now') END, ?),
         updated_at = datetime('now')`).bind(telegramId, `+${days} days`, `+${days} days`),
      env.DB.prepare("INSERT INTO activation_logs (user_id, order_id, event_type, details) VALUES (?, NULL, 'payment', ?)").bind(telegramId, `Free promo ${code}: ${days} days`)
    ]);
    await deliverSubscription(env, telegramId, "premium", `Telegram promo ${code}`);
    const status = wasActive ? `Подписка продлена на ${days} дней.` : `Premium активирован на ${days} дней.`;
    await sendSubscriptionChoice(env, chatId, `Промокод ${code} применён — ${status}

Ваша ссылка на подписку:`);
  }
  async function activateTrial(env, chatId, telegramId) {
    const results = await env.DB.batch([
      env.DB.prepare(`UPDATE subscriptions
       SET happ_install_id = NULL, happ_install_code = NULL, happ_install_link = NULL,
           happ_status = NULL, updated_at = datetime('now')
       WHERE user_id = ? AND plan = 'premium' AND happ_status = 'disabled'
         AND expiration_at IS NOT NULL AND expiration_at <= datetime('now', '-7 days')
         AND EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 0)`).bind(telegramId, telegramId),
      env.DB.prepare(`INSERT INTO subscriptions (user_id, plan, expiration_at)
       SELECT ?, 'premium', datetime(
         COALESCE((SELECT CASE WHEN expiration_at > datetime('now') THEN expiration_at ELSE datetime('now') END
                   FROM subscriptions WHERE user_id = ? AND plan = 'premium'), datetime('now')),
         '+3 days'
       )
       WHERE EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 0)
       ON CONFLICT(user_id, plan) DO UPDATE SET
         expiration_at = datetime(CASE WHEN subscriptions.expiration_at > datetime('now') THEN subscriptions.expiration_at ELSE datetime('now') END, '+3 days'),
         updated_at = datetime('now')`).bind(telegramId, telegramId, telegramId),
      env.DB.prepare("UPDATE users SET trial_activated = 1, updated_at = datetime('now') WHERE telegram_id = ? AND trial_activated = 0").bind(telegramId),
      env.DB.prepare(`INSERT OR IGNORE INTO activation_logs (user_id, order_id, event_type, details)
       SELECT ?, NULL, 'trial', 'free 3-day Premium trial'
       WHERE EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 1)`).bind(telegramId, telegramId)
    ]);
    const changed = Number(results[2]?.meta?.changes ?? 0) > 0;
    const subscription = await getActiveSubscription(env, telegramId, "premium");
    if (!subscription) {
      await sendMessage(env, chatId, "Бесплатный пробный период уже был активирован ранее.");
      return;
    }
    await deliverSubscription(env, telegramId, "premium", "Telegram Premium trial");
    const prefix = changed ? "Пробный период активирован." : "Пробный период уже активирован; восстанавливаем доступ.";
    await sendSubscriptionChoice(env, chatId, [prefix, "Тариф: Premium", "Срок: 3 дня (пробный период)", "", "Ссылка на подписку Happ:"].join(`
`));
  }
  var rateLimitTableReady = null;
  async function allowTelegramAction(env, userId) {
    if (!rateLimitTableReady) {
      rateLimitTableReady = env.DB.prepare("CREATE TABLE IF NOT EXISTS telegram_rate_limits (user_id INTEGER PRIMARY KEY, window_started_ms INTEGER NOT NULL, action_count INTEGER NOT NULL)").run().then(() => {
        return;
      }).catch((error) => {
        rateLimitTableReady = null;
        throw error;
      });
    }
    try {
      await rateLimitTableReady;
      const now = Date.now();
      const result = await env.DB.prepare(`INSERT INTO telegram_rate_limits (user_id, window_started_ms, action_count) VALUES (?, ?, 1)
       ON CONFLICT(user_id) DO UPDATE SET
         action_count = CASE WHEN ? - window_started_ms >= 2000 THEN 1 ELSE action_count + 1 END,
         window_started_ms = CASE WHEN ? - window_started_ms >= 2000 THEN excluded.window_started_ms ELSE window_started_ms END
       RETURNING action_count`).bind(userId, now, now, now).first();
      return (result?.action_count ?? 1) <= 3;
    } catch (error) {
      console.error("Rate-limit check failed", error);
      return true;
    }
  }
  async function rejectFrequentAction(env, chatId) {
    await sendMessage(env, chatId, "Слишком часто. Подождите пару секунд.");
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
    if (data === "admin:partner:hub") {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      await sendPartnerHub(env, chatId);
      return;
    }
    if (data === "admin:partner:create") {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      await setPartnerInputSession(env, callback.from.id);
      await sendMessage(env, chatId, `Отправьте: КОД ПРОЦЕНТ [ДД.ММ.ГГГГ] ПОМЕТКА
Дата необязательна. Пометка может состоять из нескольких слов.
Пример: PARTNER1 20 31.12.2026 Осень 2026`);
      return;
    }
    if (data.startsWith("admin:partner:list:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const parts = data.split(":");
      const category = parts[3] === "finished" ? "finished" : parts[3] === "archive" ? "archive" : "current";
      const page = Number(parts[4] ?? (parts[3] && /^\d+$/.test(parts[3]) ? parts[3] : 0));
      await sendPartnerList(env, chatId, category, Number.isInteger(page) && page >= 0 ? page : 0, callback.from.id);
      return;
    }
    if (data.startsWith("admin:partner:view:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const [, , , codeRaw, categoryRaw] = data.split(":");
      const code = normalizePartnerCode(codeRaw ?? "");
      const category = categoryRaw === "finished" ? "finished" : categoryRaw === "archive" ? "archive" : "current";
      if (!code) {
        await sendMessage(env, chatId, "Партнёрка не найдена.");
        return;
      }
      await sendPartnerInfo(env, chatId, code, category);
      return;
    }
    if (data.startsWith("admin:partner:extend:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const code = normalizePartnerCode(data.slice("admin:partner:extend:".length));
      if (!code) {
        await sendMessage(env, chatId, "Партнёрка не найдена.");
        return;
      }
      await setPartnerAdminSession(env, callback.from.id, "extend_partner", code);
      await sendMessage(env, chatId, "На сколько дней продлить партнёрку? Отправьте целое число от 1 до 3650. Дни добавятся к текущему сроку; если она уже истекла — от сегодняшней даты.");
      return;
    }
    if (data.startsWith("admin:partner:referralperiod:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const code = normalizePartnerCode(data.slice("admin:partner:referralperiod:".length));
      if (!code) {
        await sendMessage(env, chatId, "Партнёрка не найдена.");
        return;
      }
      await setPartnerAdminSession(env, callback.from.id, "extend_referral", code);
      await sendMessage(env, chatId, "На сколько дней учитывать покупки новых рефералов? Отправьте целое число от 1 до 3650. Дни добавятся к уже настроенному сроку; если он не задан или истёк — начнутся с сегодняшней даты.");
      return;
    }
    if (data.startsWith("admin:partner:disable:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const code = normalizePartnerCode(data.slice("admin:partner:disable:".length));
      if (!code) {
        await sendMessage(env, chatId, "Партнёрка не найдена.");
        return;
      }
      const result = await env.DB.prepare("UPDATE partners SET active = 0, updated_at = datetime('now') WHERE code = ? AND active = 1").bind(code).run();
      await sendMessage(env, chatId, Number(result.meta.changes ?? 0) ? `Партнёрка ${code} отключена. Новые оплаты больше не учитываются.` : "Партнёрка уже отключена.");
      return;
    }
    if (data.startsWith("admin:partner:grant:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const code = normalizePartnerCode(data.slice("admin:partner:grant:".length));
      const partner = code ? await env.DB.prepare("SELECT code FROM partners WHERE code = ?").bind(code).first() : null;
      if (!code || !partner) {
        await sendMessage(env, chatId, "Партнёрка не найдена.");
        return;
      }
      await setPartnerAccessSession(env, callback.from.id, code);
      await sendMessage(env, chatId, "Отправьте Telegram ID партнёра. Он должен хотя бы один раз написать боту /start.");
      return;
    }
    if (data.startsWith("partner:dashboard:")) {
      await sendPartnerDashboard(env, chatId, callback.from.id);
      return;
    }
    if (data.startsWith("partner:payout:start:")) {
      const code = normalizePartnerCode(data.slice("partner:payout:start:".length));
      if (!code) {
        await sendMessage(env, chatId, "Партнёрка не найдена.");
        return;
      }
      await showPartnerPayoutOptions(env, chatId, callback.from.id, code);
      return;
    }
    if (data.startsWith("partner:payout:add:")) {
      const code = normalizePartnerCode(data.slice("partner:payout:add:".length));
      if (!code) {
        await sendMessage(env, chatId, "Партнёрка не найдена.");
        return;
      }
      await showPartnerPayoutOptions(env, chatId, callback.from.id, code);
      return;
    }
    if (data.startsWith("partner:payout:edit:")) {
      const id = Number(data.slice("partner:payout:edit:".length));
      if (!Number.isSafeInteger(id) || id < 1) {
        await sendMessage(env, chatId, "Заявка не найдена.");
        return;
      }
      await startPartnerPayoutEdit(env, chatId, callback.from.id, id);
      return;
    }
    if (data.startsWith("partner:payout:skip:")) {
      await sendMessage(env, chatId, "Реквизиты для выплаты теперь обязательны. Нажмите «Запросить вывод средств» и укажите номер карты или телефона вместе с банком.");
      return;
    }
    if (data === "admin:payout:hub") {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      await sendPayoutHub(env, chatId);
      return;
    }
    if (data.startsWith("admin:payout:list:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const [, , , categoryRaw, pageRaw] = data.split(":");
      const category = categoryRaw === "paid" ? "paid" : categoryRaw === "archive" ? "archive" : "pending";
      await sendPayoutList(env, chatId, category, Number(pageRaw) || 0);
      return;
    }
    if (data.startsWith("admin:payout:view:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const [, , , idRaw, categoryRaw] = data.split(":");
      const id = Number(idRaw);
      const category = categoryRaw === "paid" ? "paid" : categoryRaw === "archive" ? "archive" : "pending";
      if (!Number.isSafeInteger(id) || id < 1) {
        await sendMessage(env, chatId, "Заявка не найдена.");
        return;
      }
      await sendPayoutInfo(env, chatId, id, category);
      return;
    }
    if (data.startsWith("admin:payout:confirm:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const id = Number(data.slice("admin:payout:confirm:".length));
      if (!Number.isSafeInteger(id) || id < 1) {
        await sendMessage(env, chatId, "Заявка не найдена.");
        return;
      }
      await setPayoutConfirmSession(env, callback.from.id, id);
      await sendMessage(env, chatId, "Укажите подтверждённую сумму вывода в рублях, например: 250 или 250.50. Она будет списана с баланса партнёра только если доступна.");
      return;
    }
    if (data.startsWith("admin:partner:archive:toggle:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const [, , , , codeRaw, pageRaw] = data.split(":");
      const code = normalizePartnerCode(codeRaw ?? "");
      const page = Number(pageRaw);
      if (!code) {
        await sendMessage(env, chatId, "Партнёрка не найдена.");
        return;
      }
      const valid = await env.DB.prepare(`SELECT code FROM partners WHERE code = ? AND ${partnerArchiveWhere()}`).bind(code).first();
      if (!valid) {
        await sendMessage(env, chatId, "Эта партнёрка больше не находится в архиве.");
        return;
      }
      const exists = await env.DB.prepare("SELECT 1 FROM partner_archive_selections WHERE admin_id = ? AND partner_code = ?").bind(callback.from.id, code).first();
      if (exists)
        await env.DB.prepare("DELETE FROM partner_archive_selections WHERE admin_id = ? AND partner_code = ?").bind(callback.from.id, code).run();
      else
        await env.DB.prepare("INSERT OR IGNORE INTO partner_archive_selections (admin_id, partner_code) VALUES (?, ?)").bind(callback.from.id, code).run();
      await sendPartnerList(env, chatId, "archive", Number.isInteger(page) && page >= 0 ? page : 0, callback.from.id);
      return;
    }
    if (data === "admin:partner:archive:selectall") {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      await env.DB.prepare(`INSERT OR IGNORE INTO partner_archive_selections (admin_id, partner_code) SELECT ?, code FROM partners WHERE ${partnerArchiveWhere()}`).bind(callback.from.id).run();
      await sendPartnerList(env, chatId, "archive", 0, callback.from.id);
      return;
    }
    if (data === "admin:partner:archive:delete_selected") {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const selected = await selectedArchivedCodes(env, callback.from.id);
      if (!selected.size) {
        await sendMessage(env, chatId, "Сначала выберите партнёрки в архиве.");
        return;
      }
      await sendMessage(env, chatId, `Удалить из панели ${selected.size} партнёрк(и)? Подтверждённые оплаты и начисления сохранятся.`, { inline_keyboard: [[
        { text: "Да", callback_data: "admin:partner:archive:confirm_delete" },
        { text: "Нет", callback_data: "admin:partner:list:archive:0" }
      ]] });
      return;
    }
    if (data === "admin:partner:archive:confirm_delete") {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      await ensurePartnerTables(env);
      const selected = await selectedArchivedCodes(env, callback.from.id);
      if (!selected.size) {
        await sendMessage(env, chatId, "Выбранных партнёрок уже нет.");
        return;
      }
      const placeholders = Array.from(selected, () => "?").join(",");
      const codes = Array.from(selected);
      await env.DB.batch([
        env.DB.prepare(`UPDATE partners SET deleted_at = datetime('now') WHERE code IN (${placeholders}) AND ${partnerArchiveWhere()}`).bind(...codes),
        env.DB.prepare(`DELETE FROM partner_accesses WHERE partner_code IN (${placeholders})`).bind(...codes),
        env.DB.prepare("DELETE FROM partner_archive_selections WHERE admin_id = ?").bind(callback.from.id)
      ]);
      await sendMessage(env, chatId, "Выбранные партнёрки удалены из панели. Учёт оплат и начислений сохранён.");
      await sendPartnerList(env, chatId, "archive", 0, callback.from.id);
      return;
    }
    if (data === "admin:promo:hub") {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      await sendPromoHub(env, chatId);
      return;
    }
    if (data.startsWith("admin:promo:list:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
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
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const [, , , codeRaw, categoryRaw] = data.split(":");
      const code = normalizePromoCode(codeRaw ?? "");
      if (!code) {
        await sendMessage(env, chatId, "Промокод не найден.");
        return;
      }
      await sendPromoInfo(env, chatId, code, categoryRaw === "expired" ? "expired" : "current");
      return;
    }
    if (data.startsWith("admin:promo:delete:")) {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const code = normalizePromoCode(data.slice("admin:promo:delete:".length));
      if (!code) {
        await sendMessage(env, chatId, "Промокод не найден.");
        return;
      }
      const result = await env.DB.prepare("UPDATE promo_codes SET active = 0, updated_at = datetime('now') WHERE code = ? AND active = 1").bind(code).run();
      await sendMessage(env, chatId, Number(result.meta.changes ?? 0) === 1 ? `Промокод ${code} удалён и больше не применяется.` : "Промокод уже удалён или не найден.");
      return;
    }
    if (data === "admin:promo:discount" || data === "admin:promo:days" || data === "admin:promo:free_days") {
      if (!isAdmin(env, callback.from.id)) {
        await sendMessage(env, chatId, "Команда доступна только администратору.");
        return;
      }
      const freeDays = data === "admin:promo:free_days";
      const days = data === "admin:promo:days";
      await setInputSession(env, callback.from.id, freeDays ? "admin_promo_free_days" : days ? "admin_promo_days" : "admin_promo_discount");
      await sendMessage(env, chatId, freeDays ? `Отправьте: КОД КОЛИЧЕСТВО_ДНЕЙ КОЛИЧЕСТВО_АКТИВАЦИЙ [ДД.ММ.ГГГГ [ЧЧ:ММ]]
Время указывается по Москве. 0 активаций = без лимита. Дата необязательна.
Пример: GIFT7 7 0 31.12.2026 12:00` : days ? `Отправьте: КОД КОЛИЧЕСТВО_ДНЕЙ СКИДКА_ПРОЦЕНТОВ КОЛИЧЕСТВО_АКТИВАЦИЙ [ДД.ММ.ГГГГ [ЧЧ:ММ]]
Время указывается по Москве. 0 активаций = без лимита. Дата необязательна.
Пример: PROMO14 14 25 30 31.12.2026 12:00` : `Отправьте: КОД СКИДКА_ПРОЦЕНТОВ КОЛИЧЕСТВО_АКТИВАЦИЙ [ДД.ММ.ГГГГ [ЧЧ:ММ]]
Время указывается по Москве. 0 активаций = без лимита. Дата необязательна.
Пример: SALE20 20 0 31.12.2026 12:00`);
      return;
    }
    if (data === "promo:redeem") {
      await setInputSession(env, callback.from.id, "redeem_promo");
      await sendMessage(env, chatId, "Отправьте промокод одним сообщением.");
      return;
    }
    if (data === "happ:devices") {
      if (!await ensureMembership(env, chatId, callback.from.id))
        return;
      try {
        await sendHappDevices(env, chatId, callback.from.id);
      } catch (error) {
        console.error(`Could not list Happ devices for ${callback.from.id}`, error);
        await sendMessage(env, chatId, "Не удалось получить список устройств. Попробуйте через минуту.");
      }
      return;
    }
    if (data.startsWith("happ:device:remove:")) {
      if (!await ensureMembership(env, chatId, callback.from.id))
        return;
      const token = data.slice("happ:device:remove:".length);
      await sendMessage(env, chatId, "Вы уверены?", { inline_keyboard: [[
        { text: "Да", callback_data: `happ:device:confirm:${token}` },
        { text: "Нет", callback_data: "happ:cancel" }
      ]] });
      return;
    }
    if (data.startsWith("happ:device:confirm:")) {
      if (!await ensureMembership(env, chatId, callback.from.id))
        return;
      try {
        const removed = await removeHappDevice(env, callback.from.id, data.slice("happ:device:confirm:".length));
        if (!removed) {
          await sendMessage(env, chatId, "Эта кнопка устарела. Откройте «\uD83D\uDCF1 Устройства» ещё раз.");
          return;
        }
        await sendMessage(env, chatId, "Устройство отключено.");
        await sendHappDevices(env, chatId, callback.from.id);
      } catch (error) {
        console.error(`Could not remove Happ device for ${callback.from.id}`, error);
        await sendMessage(env, chatId, "Не удалось отключить устройство. Попробуйте через минуту.");
      }
      return;
    }
    if (data === "happ:reissue") {
      if (!await ensureMembership(env, chatId, callback.from.id))
        return;
      await sendMessage(env, chatId, "Вы уверены?", { inline_keyboard: [[
        { text: "Да", callback_data: "happ:reissue:confirm" },
        { text: "Нет", callback_data: "happ:cancel" }
      ]] });
      return;
    }
    if (data === "happ:reissue:confirm") {
      if (!await ensureMembership(env, chatId, callback.from.id))
        return;
      try {
        await reissueHappSubscription(env, callback.from.id, "premium");
        await sendSubscriptionChoice(env, chatId, "Ссылка перевыпущена. Старая ссылка больше не работает.");
      } catch (error) {
        console.error(`Could not reissue Happ subscription for ${callback.from.id}`, error);
        await sendMessage(env, chatId, "Не удалось перевыпустить ссылку. Попробуйте через минуту.");
      }
      return;
    }
    if (data === "happ:cancel") {
      await sendMessage(env, chatId, "Отменено.");
      return;
    }
    if (data === "happ:android" || data === "happ:ios") {
      if (!await ensureMembership(env, chatId, callback.from.id))
        return;
      await sendPlatformSubscriptionLink(env, chatId, callback.from.id, data === "happ:android" ? "android" : "ios");
      return;
    }
    if (data === "happ:guide") {
      await sendMessage(env, chatId, `Как подключить Happ:

1. Установите приложение:
• Android — Happ из Google Play (Play Маркет).
• iPhone/iPad (iOS) — обычный Happ из App Store.

2. В боте выберите кнопку своего устройства.
3. Нажмите на моноширинную ссылку — она скопируется в буфер обмена.
4. Откройте Happ и нажмите «+».
5. Выберите «Импортировать из буфера обмена», подтвердите добавление и включите подключение.

Не передавайте вашу ссылку другим людям.`);
      return;
    }
    if (data === "check_membership") {
      if (await ensureMembership(env, chatId, callback.from.id)) {
        await sendMessage(env, chatId, "Подписка подтверждена.");
        await sendPlans(env, chatId, callback.from.id);
      }
      return;
    }
    if (!await ensureMembership(env, chatId, callback.from.id))
      return;
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
        await sendMessage(env, chatId, `Premium — выберите срок подписки.

Подписку можно подключить на 2 устройства:`, durationKeyboard(plan));
      }
      return;
    }
    if (data.startsWith("promo_duration:")) {
      const [, code, durationValue] = data.split(":");
      const promo = code ? await getPromoCode(env, code) : null;
      const duration = durationValue ? parseDuration(durationValue) : null;
      if (!promo || promo.duration_days || !duration) {
        await sendMessage(env, chatId, "Промокод недействителен.");
        return;
      }
      if (!await takePromoReservation(env, callback.from.id, promo.code)) {
        await sendMessage(env, chatId, "Сначала введите промокод заново.");
        return;
      }
      const amount = Math.max(1, Math.round(PRODUCTS.premium[duration] * (100 - promo.discount_percent) / 100));
      await createOrder(env, chatId, callback.from.id, "premium", duration, { amountRub: amount, displayPeriod: `${duration} мес. со скидкой ${promo.discount_percent}%`, promoCode: promo.code });
      return;
    }
    if (data.startsWith("duration:")) {
      const [, planValue, durationValue] = data.split(":");
      if (planValue === "premium" && durationValue) {
        const duration = parseDuration(durationValue);
        if (duration)
          await createOrder(env, chatId, callback.from.id, planValue, duration);
      }
    }
  }
  function isCommand(text, command) {
    const first = text.trim().split(/\s+/)[0].toLowerCase();
    return first === command || first.startsWith(`${command}@`);
  }
  async function sendOrders(env, chatId) {
    const result = await env.DB.prepare(`SELECT id, user_id, plan, duration_months, amount_rub, status, created_at, paid_at
     FROM orders ORDER BY created_at DESC LIMIT 20`).all();
    if (result.results.length === 0) {
      await sendMessage(env, chatId, "Заказов пока нет.");
      return;
    }
    const lines = result.results.map((order) => `${order.status.toUpperCase()} ${order.id}
user ${order.user_id} · ${order.plan.toUpperCase()} ${order.duration_months}м · ${order.amount_rub} ₽ · ${order.created_at}`);
    await sendMessage(env, chatId, `Последние заказы:

${lines.join(`

`)}`);
  }
  async function handleMessage(env, message) {
    if (!message.from || !message.text || message.from.is_bot)
      return;
    const text = message.text.trim();
    const isNewUser = await upsertUser(env, message.from);
    const partnerCode = startPartnerCode(text);
    if (isNewUser && partnerCode)
      await claimPartnerAttribution(env, message.from.id, partnerCode);
    const promoInput = isCommand(text, "/promo") || Boolean(await env.DB.prepare("SELECT 1 FROM input_sessions WHERE user_id = ? AND kind = 'redeem_promo' AND expires_at > datetime('now')").bind(message.from.id).first());
    if (!isAdmin(env, message.from.id) && !promoInput && !await allowTelegramAction(env, message.from.id)) {
      await rejectFrequentAction(env, message.chat.id);
      return;
    }
    if (isCommand(text, "/admin")) {
      await env.DB.prepare("DELETE FROM input_sessions WHERE user_id = ?").bind(message.from.id).run();
      if (!isAdmin(env, message.from.id))
        await sendMessage(env, message.chat.id, "Команда доступна только администратору.");
      else
        await sendMessage(env, message.chat.id, "Админ-панель промокодов:", adminKeyboard());
      return;
    }
    if (isAdmin(env, message.from.id)) {
      const payoutSession = await takePayoutConfirmSession(env, message.from.id);
      if (payoutSession) {
        await confirmPartnerPayout(env, message.chat.id, message.from.id, payoutSession.request_id, text);
        return;
      }
    }
    if (isAdmin(env, message.from.id) && await takePartnerInputSession(env, message.from.id)) {
      await createPartnerFromInput(env, message.chat.id, text);
      return;
    }
    if (isAdmin(env, message.from.id)) {
      const adminSession = await takePartnerAdminSession(env, message.from.id);
      if (adminSession) {
        await applyPartnerAdminDays(env, message.chat.id, adminSession, text);
        return;
      }
      const code = await takePartnerAccessSession(env, message.from.id);
      if (code) {
        const userId = Number(text);
        if (!Number.isSafeInteger(userId) || userId <= 0) {
          await sendMessage(env, message.chat.id, "Нужен числовой Telegram ID. Доступ не выдан.");
          return;
        }
        const partnerUser = await env.DB.prepare("SELECT telegram_id, username, first_name FROM users WHERE telegram_id = ?").bind(userId).first();
        if (!partnerUser) {
          await sendMessage(env, message.chat.id, "Этот аккаунт ещё не писал боту. Пусть партнёр сначала отправит /start, затем повторите выдачу доступа.");
          return;
        }
        await ensurePartnerTables(env);
        await env.DB.prepare(`INSERT INTO partner_accesses (partner_code, user_id) VALUES (?, ?)
        ON CONFLICT(partner_code) DO UPDATE SET user_id = excluded.user_id, granted_at = datetime('now')`).bind(code, userId).run();
        await sendMessage(env, message.chat.id, `Доступ к партнёрке ${code} выдан аккаунту ${partnerUser.username ? `@${partnerUser.username}` : partnerUser.first_name ?? "без имени"} · ${userId}.`);
        await sendPartnerDashboard(env, userId, userId);
        return;
      }
    }
    const payoutSession = await takePartnerPayoutSession(env, message.from.id);
    if (payoutSession) {
      const note = text.trim();
      if (!note || note.length > 1000 || !isValidPayoutDetails(note)) {
        await sendMessage(env, message.chat.id, `Нужны реквизиты для выплаты: номер карты или номер телефона и название банка. Можно добавить комментарий; до 1 000 символов. Откройте /partner и начните заново.

Вывод может занимать до 5 рабочих дней, ускорить его невозможно. При проблемах: @Olivarqy.`);
        return;
      }
      await submitPartnerPayout(env, message.chat.id, message.from, payoutSession, note);
      return;
    }
    const session = await takeInputSession(env, message.from.id);
    if (session) {
      if (session.kind === "redeem_promo") {
        const code = normalizePromoCode(text);
        const promo = code ? await getPromoCode(env, code) : null;
        if (!promo) {
          await sendMessage(env, message.chat.id, "Промокод не найден или отключён.");
          return;
        }
        if (!await reservePromo(env, message.from.id, promo.code)) {
          await sendMessage(env, message.chat.id, "Этот промокод уже был успешно применён на вашем аккаунте или его лимит закончился.");
          return;
        }
        if (promo.duration_days) {
          if (promo.free_grant === 1) {
            await takePromoReservation(env, message.from.id, promo.code);
            await activateFreePromoDays(env, message.chat.id, message.from.id, promo.code, promo.duration_days);
          } else {
            const amount = promoPrice(promo.duration_days, promo.discount_percent);
            await createOrder(env, message.chat.id, message.from.id, "premium", 1, { amountRub: amount, durationDays: promo.duration_days, displayPeriod: `${promo.duration_days} дней со скидкой ${promo.discount_percent}%`, promoCode: promo.code });
            await takePromoReservation(env, message.from.id, promo.code);
          }
        } else {
          const buttons = DURATIONS.map((duration) => [{ text: `${duration} мес. — ${Math.max(1, Math.round(PRODUCTS.premium[duration] * (100 - promo.discount_percent) / 100))} ₽`, callback_data: `promo_duration:${promo.code}:${duration}` }]);
          await sendMessage(env, message.chat.id, `Промокод ${promo.code} применён: скидка ${promo.discount_percent}%. Выберите срок:`, { inline_keyboard: buttons });
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
        const expectedParts = [activationIndex + 1, activationIndex + 2, activationIndex + 3];
        const percent = freeDays ? 99 : Number(parts[percentIndex]);
        const activations = Number(parts[activationIndex]);
        const expiry = parsePromoExpiry(parts[expiryIndex], parts[expiryIndex + 1]);
        if (!code || !expectedParts.includes(parts.length) || !Number.isInteger(percent) || !freeDays && (percent < 1 || percent > 99) || !Number.isInteger(activations) || activations < 0 || activations > 1e5 || expiry === undefined || days !== null && (!Number.isInteger(days) || days < 1 || days > 3650)) {
          await sendMessage(env, message.chat.id, freeDays ? "Неверный формат. Пример: GIFT7 7 0 31.12.2026 12:00" : session.kind === "admin_promo_days" ? "Неверный формат. Пример: PROMO14 14 25 30 31.12.2026 12:00" : "Неверный формат. Пример: SALE20 20 0 31.12.2026 12:00");
          return;
        }
        const unlimited = activations === 0 ? 1 : 0;
        const storedLimit = unlimited ? 1 : activations;
        await env.DB.prepare(`INSERT INTO promo_codes (code, discount_percent, duration_days, max_activations, activation_count, active, free_grant, unlimited_activations, expires_at, created_by)
        VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?, ?) ON CONFLICT(code) DO UPDATE SET discount_percent = excluded.discount_percent, duration_days = excluded.duration_days, max_activations = excluded.max_activations, activation_count = 0, active = 1, free_grant = excluded.free_grant, unlimited_activations = excluded.unlimited_activations, expires_at = excluded.expires_at, created_by = excluded.created_by, updated_at = datetime('now')`).bind(code, percent, days, storedLimit, freeDays ? 1 : 0, unlimited, expiry, message.from.id).run();
        const description = freeDays ? `${days} бесплатных дней` : days === null ? `скидка ${percent}% на обычные тарифы` : `${days} дней, скидка ${percent}%, цена ${promoPrice(days, percent)} ₽`;
        const limitText = unlimited ? "без лимита" : String(activations);
        const expiryText = expiry ? ` Действует до: ${formatPromoExpiry(expiry)}.` : " Без даты окончания.";
        await telegramApi(env, "sendMessage", {
          chat_id: message.chat.id,
          text: `Промокод создан:
<code>${code}</code>

${escapeHtml(description)}. Активаций: ${limitText}.${expiryText}`,
          parse_mode: "HTML"
        });
        return;
      }
    }
    if (isCommand(text, "/admin")) {
      if (!isAdmin(env, message.from.id))
        await sendMessage(env, message.chat.id, "Команда доступна только администратору.");
      else
        await sendMessage(env, message.chat.id, "Админ-панель промокодов:", adminKeyboard());
      return;
    }
    if (isCommand(text, "/orders")) {
      if (env.ADMIN_TELEGRAM_ID && String(message.from.id) === env.ADMIN_TELEGRAM_ID) {
        await sendOrders(env, message.chat.id);
      } else {
        await sendMessage(env, message.chat.id, "Команда доступна только администратору.");
      }
      return;
    }
    if (isCommand(text, "/partner")) {
      await sendPartnerDashboard(env, message.chat.id, message.from.id);
      return;
    }
    if (isCommand(text, "/promo")) {
      await setInputSession(env, message.from.id, "redeem_promo");
      await sendMessage(env, message.chat.id, "Отправьте промокод одним сообщением.");
      return;
    }
    if (isCommand(text, "/start")) {
      await sendMessage(env, message.chat.id, `Привет! \uD83D\uDC4B

Добро пожаловать в BananchikiVpn. Сервис помогает с доступом к интернету при белых списках и ограничениях сети.`);
      if (!await ensureMembership(env, message.chat.id, message.from.id))
        return;
      await sendPlans(env, message.chat.id, message.from.id);
      return;
    }
    if (isCommand(text, "/menu")) {
      if (!await ensureMembership(env, message.chat.id, message.from.id))
        return;
      await sendSubscriptionStatus(env, message.chat.id, message.from.id);
      return;
    }
    if (isCommand(text, "/sub")) {
      if (!await ensureMembership(env, message.chat.id, message.from.id))
        return;
      await sendMessage(env, message.chat.id, `Premium — выберите срок подписки.

Подписку можно подключить на 2 устройства:`, durationKeyboard("premium"));
      return;
    }
    if (isCommand(text, "/plans") || isCommand(text, "/buy")) {
      if (!await ensureMembership(env, message.chat.id, message.from.id))
        return;
      await sendPlans(env, message.chat.id, message.from.id);
      return;
    }
    if (isCommand(text, "/trial")) {
      if (!await ensureMembership(env, message.chat.id, message.from.id))
        return;
      await activateTrial(env, message.chat.id, message.from.id);
      return;
    }
    await sendMessage(env, message.chat.id, "Напишите /start — я проверю подписку на канал и помогу оформить Premium. Один раз можно начать с бесплатных трёх дней.");
  }
  function rubleKopeks(value) {
    if (!/^\d+(?:\.\d{1,2})?$/.test(value))
      return null;
    const [whole, fraction = ""] = value.split(".");
    const result = Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
    return Number.isSafeInteger(result) ? result : null;
  }
  function constantTimeEqual(left, right) {
    let difference = left.length ^ right.length;
    const max = Math.max(left.length, right.length);
    for (let index = 0;index < max; index += 1) {
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
    if (!buyer)
      throw new Error("order owner does not exist");
    const link = await deliverSubscription(env, buyer.telegram_id, order.plan, `YooMoney ${order.plan.toUpperCase()} ${order.duration_months}m`);
    return { buyer, link };
  }
  async function finalizePaidOrder(env, order, notification) {
    const { operationId, amount, currency, notificationType, paymentDatetime, sender, codepro, label, rawHash } = notification;
    const existingPayment = await env.DB.prepare("SELECT order_id, operation_id FROM payments WHERE operation_id = ?").bind(operationId).first();
    if (existingPayment && existingPayment.order_id !== order.id)
      throw new Error("operation already belongs to another order");
    if (order.status === "paid") {
      if (order.operation_id === operationId || existingPayment?.order_id === order.id) {
        await fulfilPaidOrder(env, order);
        return "OK";
      }
      throw new Error("order is already paid with another operation");
    }
    if (order.status !== "pending")
      throw new Error("order is not payable");
    const buyer = await getUser(env, order.user_id);
    if (!buyer)
      throw new Error("order owner does not exist");
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
    if (Number(results[1]?.meta?.changes ?? 0) === 0)
      return "OK";
    await recordPartnerReward(env, order.id);
    await fulfilPaidOrder(env, order);
    try {
      const period = order.duration_days ? `${order.duration_days} дней` : `${order.duration_months} мес.`;
      const status = renewal ? `Подписка продлена на ${period}.` : `Premium оформлен на ${period}.`;
      await sendSubscriptionChoice(env, order.user_id, `Оплата подтверждена — ${status}

Ваша ссылка на подписку:

Номер заказа: ${order.id}`);
    } catch (error) {
      console.error("Could not notify buyer after payment", error);
    }
    return "OK";
  }
  async function processYoomoneyNotification(env, body) {
    if (body.length > 64 * 1024)
      throw new Error("notification body is too large");
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
    if (!notificationType || !operationId || !amount || !currency || !paymentDatetime || !label || !receivedHash)
      throw new Error("missing YooMoney notification fields");
    const expectedHash = await sha1Hex(signedYoomoneyString(params, env.YOOMONEY_NOTIFICATION_SECRET));
    if (!constantTimeEqual(expectedHash, receivedHash.toLowerCase()))
      throw new Error("invalid YooMoney signature");
    if (codepro.toLowerCase() === "true")
      throw new Error("code-protected payment is not accepted");
    if (unaccepted.toLowerCase() === "true")
      throw new Error("unaccepted payment is not accepted");
    if (currency !== "643" && currency !== "RUB")
      throw new Error("unsupported payment currency");
    const order = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(label).first();
    if (!order)
      throw new Error("unknown order label");
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
    if (body.length > 64 * 1024)
      throw new Error("notification body is too large");
    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      throw new Error("invalid JSON notification");
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload))
      throw new Error("invalid notification object");
    const event = payload;
    if (event.event !== "payment.succeeded" || !event.object || typeof event.object !== "object" || Array.isArray(event.object))
      throw new Error("unsupported notification");
    const payment = event.object;
    if (payment.status !== "succeeded")
      throw new Error("payment is not succeeded");
    if (typeof payment.id !== "string" || !payment.id)
      throw new Error("missing payment id");
    if (!payment.metadata || typeof payment.metadata !== "object" || Array.isArray(payment.metadata))
      throw new Error("missing payment metadata");
    const orderId = payment.metadata.order_id;
    if (typeof orderId !== "string" || !orderId)
      throw new Error("missing order id");
    if (!payment.amount || typeof payment.amount !== "object" || Array.isArray(payment.amount))
      throw new Error("missing payment amount");
    const amount = payment.amount;
    if (amount.currency !== "RUB" || typeof amount.value !== "string")
      throw new Error("unsupported payment currency or amount");
    const order = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(orderId).first();
    if (!order)
      throw new Error("unknown order id");
    const amountKopeks = rubleKopeks(amount.value);
    if (amountKopeks === null || amountKopeks !== order.amount_rub * 100)
      throw new Error("payment amount does not match order");
    const paymentDatetime = typeof payment.created_at === "string" ? payment.created_at : new Date().toISOString();
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
      if (update.callback_query)
        await handleCallback(env, update.callback_query);
      else if (update.message)
        await handleMessage(env, update.message);
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
    const expired = await env.DB.prepare(`SELECT user_id, plan, happ_install_id FROM subscriptions
     WHERE happ_install_id IS NOT NULL AND happ_status = 'active'
       AND expiration_at IS NOT NULL AND expiration_at <= datetime('now') LIMIT 100`).all();
    for (const subscription of expired.results) {
      if (!subscription.happ_install_id)
        continue;
      try {
        await env.DB.prepare("UPDATE subscriptions SET happ_status = 'disabled', updated_at = datetime('now') WHERE user_id = ? AND plan = ? AND happ_install_id = ? AND happ_status = 'active'").bind(subscription.user_id, subscription.plan, subscription.happ_install_id).run();
      } catch (error) {
        console.error(`Could not mark expired ${subscription.plan} subscription for ${subscription.user_id}`, error);
      }
    }
  }
  var src_default = {
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

  // legacy-entry.ts
  var env = new Proxy({}, { get: (_, key) => globalThis[key] });
  addEventListener("fetch", (event) => event.respondWith(src_default.fetch(event.request, env, event)));
  addEventListener("scheduled", (event) => {
    if (src_default.scheduled)
      event.waitUntil(src_default.scheduled(event, env, event));
  });
})();
