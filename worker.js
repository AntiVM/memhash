// worker.js
(function () {
    'use strict';
  
    var ERROR = 'input is invalid type';
    var WINDOW = typeof window === 'object';
    var root = WINDOW ? window : {};
    if (root.JS_SHA256_NO_WINDOW) {
      WINDOW = false;
    }
    var WEB_WORKER = !WINDOW && typeof self === 'object';
    var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
    if (NODE_JS) {
      root = global;
    } else if (WEB_WORKER) {
      root = self;
    }
    var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === 'object' && module.exports;
    var AMD = typeof define === 'function' && define.amd;
    var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';
    var HEX_CHARS = '0123456789abcdef'.split('');
    var EXTRA = [-2147483648, 8388608, 32768, 128];
    var SHIFT = [24, 16, 8, 0];
    var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];
  
    var blocks = [];
  
    if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
      Array.isArray = function (obj) {
        return Object.prototype.toString.call(obj) === '[object Array]';
      };
    }
  
    if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
      ArrayBuffer.isView = function (obj) {
        return typeof obj === 'object' && obj.buffer && obj.buffer.constructor === ArrayBuffer;
      };
    }
  
    var createOutputMethod = function (outputType, is224) {
      return function (message) {
        return new Sha256(is224, true).update(message)[outputType]();
      };
    };
  
    var createMethod = function (is224) {
      var method = createOutputMethod('hex', is224);
      if (NODE_JS) {
        method = nodeWrap(method, is224);
      }
      method.create = function () {
        return new Sha256(is224);
      };
      method.update = function (message) {
        return method.create().update(message);
      };
      for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
        var type = OUTPUT_TYPES[i];
        method[type] = createOutputMethod(type, is224);
      }
      return method;
    };
  
    var nodeWrap = function (method, is224) {
      var crypto = eval("require('crypto')");
      var Buffer = eval("require('buffer').Buffer");
      var algorithm = is224 ? 'sha224' : 'sha256';
      var nodeMethod = function (message) {
        if (typeof message === 'string') {
          return crypto.createHash(algorithm).update(message, 'utf8').digest('hex');
        } else {
          if (message === null || message === undefined) {
            throw new Error(ERROR);
          } else if (message.constructor === ArrayBuffer) {
            message = new Uint8Array(message);
          }
        }
        if (Array.isArray(message) || ArrayBuffer.isView(message) ||
          message.constructor === Buffer) {
          return crypto.createHash(algorithm).update(new Buffer(message)).digest('hex');
        } else {
          return method(message);
        }
      };
      return nodeMethod;
    };
  
    var createHmacOutputMethod = function (outputType, is224) {
      return function (key, message) {
        return new HmacSha256(key, is224, true).update(message)[outputType]();
      };
    };
  
    var createHmacMethod = function (is224) {
      var method = createHmacOutputMethod('hex', is224);
      method.create = function (key) {
        return new HmacSha256(key, is224);
      };
      method.update = function (key, message) {
        return method.create(key).update(message);
      };
      for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
        var type = OUTPUT_TYPES[i];
        method[type] = createHmacOutputMethod(type, is224);
      }
      return method;
    };
  
    function Sha256(is224, sharedMemory) {
      if (sharedMemory) {
        blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
          blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
          blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
        this.blocks = blocks;
      } else {
        this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      }
  
      if (is224) {
        this.h0 = 0xc1059ed8;
        this.h1 = 0x367cd507;
        this.h2 = 0x3070dd17;
        this.h3 = 0xf70e5939;
        this.h4 = 0xffc00b31;
        this.h5 = 0x68581511;
        this.h6 = 0x64f98fa7;
        this.h7 = 0xbefa4fa4;
      } else { // 256
        this.h0 = 0x6a09e667;
        this.h1 = 0xbb67ae85;
        this.h2 = 0x3c6ef372;
        this.h3 = 0xa54ff53a;
        this.h4 = 0x510e527f;
        this.h5 = 0x9b05688c;
        this.h6 = 0x1f83d9ab;
        this.h7 = 0x5be0cd19;
      }
  
      this.block = this.start = this.bytes = this.hBytes = 0;
      this.finalized = this.hashed = false;
      this.first = true;
      this.is224 = is224;
    }
  
    Sha256.prototype.update = function (message) {
      if (this.finalized) {
        return;
      }
      var notString, type = typeof message;
      if (type !== 'string') {
        if (type === 'object') {
          if (message === null) {
            throw new Error(ERROR);
          } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
            message = new Uint8Array(message);
          } else if (!Array.isArray(message)) {
            if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
              throw new Error(ERROR);
            }
          }
        } else {
          throw new Error(ERROR);
        }
        notString = true;
      }
      var code, index = 0, i, length = message.length, blocks = this.blocks;
  
      while (index < length) {
        if (this.hashed) {
          this.hashed = false;
          blocks[0] = this.block;
          blocks[16] = blocks[1] = blocks[2] = blocks[3] =
            blocks[4] = blocks[5] = blocks[6] = blocks[7] =
            blocks[8] = blocks[9] = blocks[10] = blocks[11] =
            blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
        }
  
        if (notString) {
          for (i = this.start; index < length && i < 64; ++index) {
            blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
          }
        } else {
          for (i = this.start; index < length && i < 64; ++index) {
            code = message.charCodeAt(index);
            if (code < 0x80) {
              blocks[i >> 2] |= code << SHIFT[i++ & 3];
            } else if (code < 0x800) {
              blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
              blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
            } else if (code < 0xd800 || code >= 0xe000) {
              blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
              blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
              blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
            } else {
              code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
              blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
              blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
              blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
              blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
            }
          }
        }
  
        this.lastByteIndex = i;
        this.bytes += i - this.start;
        if (i >= 64) {
          this.block = blocks[16];
          this.start = i - 64;
          this.hash();
          this.hashed = true;
        } else {
          this.start = i;
        }
      }
      if (this.bytes > 4294967295) {
        this.hBytes += this.bytes / 4294967296 << 0;
        this.bytes = this.bytes % 4294967296;
      }
      return this;
    };
  
    Sha256.prototype.finalize = function () {
      if (this.finalized) {
        return;
      }
      this.finalized = true;
      var blocks = this.blocks, i = this.lastByteIndex;
      blocks[16] = this.block;
      blocks[i >> 2] |= EXTRA[i & 3];
      this.block = blocks[16];
      if (i >= 56) {
        if (!this.hashed) {
          this.hash();
        }
        blocks[0] = this.block;
        blocks[16] = blocks[1] = blocks[2] = blocks[3] =
          blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
          blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      }
      blocks[14] = this.hBytes << 3 | this.bytes >>> 29;
      blocks[15] = this.bytes << 3;
      this.hash();
    };
  
    Sha256.prototype.hash = function () {
      var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6,
        h = this.h7, blocks = this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;
  
      for (j = 16; j < 64; ++j) {
        // rightrotate
        t1 = blocks[j - 15];
        s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
        t1 = blocks[j - 2];
        s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
        blocks[j] = blocks[j - 16] + s0 + blocks[j - 7] + s1 << 0;
      }
  
      bc = b & c;
      for (j = 0; j < 64; j += 4) {
        if (this.first) {
          if (this.is224) {
            ab = 300032;
            t1 = blocks[0] - 1413257819;
            h = t1 - 150054599 << 0;
            d = t1 + 24177077 << 0;
          } else {
            ab = 704751109;
            t1 = blocks[0] - 210244248;
            h = t1 - 1521486534 << 0;
            d = t1 + 143694565 << 0;
          }
          this.first = false;
        } else {
          s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
          s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
          ab = a & b;
          maj = ab ^ (a & c) ^ bc;
          ch = (e & f) ^ (~e & g);
          t1 = h + s1 + ch + K[j] + blocks[j];
          t2 = s0 + maj;
          h = d + t1 << 0;
          d = t1 + t2 << 0;
        }
        s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
        s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
        da = d & a;
        maj = da ^ (d & b) ^ ab;
        ch = (h & e) ^ (~h & f);
        t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
        t2 = s0 + maj;
        g = c + t1 << 0;
        c = t1 + t2 << 0;
        s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
        s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
        cd = c & d;
        maj = cd ^ (c & a) ^ da;
        ch = (g & h) ^ (~g & e);
        t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
        t2 = s0 + maj;
        f = b + t1 << 0;
        b = t1 + t2 << 0;
        s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
        s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
        bc = b & c;
        maj = bc ^ (b & d) ^ cd;
        ch = (f & g) ^ (~f & h);
        t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
        t2 = s0 + maj;
        e = a + t1 << 0;
        a = t1 + t2 << 0;
      }
  
      this.h0 = this.h0 + a << 0;
      this.h1 = this.h1 + b << 0;
      this.h2 = this.h2 + c << 0;
      this.h3 = this.h3 + d << 0;
      this.h4 = this.h4 + e << 0;
      this.h5 = this.h5 + f << 0;
      this.h6 = this.h6 + g << 0;
      this.h7 = this.h7 + h << 0;
    };
  
    Sha256.prototype.hex = function () {
      this.finalize();
  
      var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
        h6 = this.h6, h7 = this.h7;
  
      var hex = HEX_CHARS[(h0 >> 28) & 0x0F] + HEX_CHARS[(h0 >> 24) & 0x0F] +
        HEX_CHARS[(h0 >> 20) & 0x0F] + HEX_CHARS[(h0 >> 16) & 0x0F] +
        HEX_CHARS[(h0 >> 12) & 0x0F] + HEX_CHARS[(h0 >> 8) & 0x0F] +
        HEX_CHARS[(h0 >> 4) & 0x0F] + HEX_CHARS[h0 & 0x0F] +
        HEX_CHARS[(h1 >> 28) & 0x0F] + HEX_CHARS[(h1 >> 24) & 0x0F] +
        HEX_CHARS[(h1 >> 20) & 0x0F] + HEX_CHARS[(h1 >> 16) & 0x0F] +
        HEX_CHARS[(h1 >> 12) & 0x0F] + HEX_CHARS[(h1 >> 8) & 0x0F] +
        HEX_CHARS[(h1 >> 4) & 0x0F] + HEX_CHARS[h1 & 0x0F] +
        HEX_CHARS[(h2 >> 28) & 0x0F] + HEX_CHARS[(h2 >> 24) & 0x0F] +
        HEX_CHARS[(h2 >> 20) & 0x0F] + HEX_CHARS[(h2 >> 16) & 0x0F] +
        HEX_CHARS[(h2 >> 12) & 0x0F] + HEX_CHARS[(h2 >> 8) & 0x0F] +
        HEX_CHARS[(h2 >> 4) & 0x0F] + HEX_CHARS[h2 & 0x0F] +
        HEX_CHARS[(h3 >> 28) & 0x0F] + HEX_CHARS[(h3 >> 24) & 0x0F] +
        HEX_CHARS[(h3 >> 20) & 0x0F] + HEX_CHARS[(h3 >> 16) & 0x0F] +
        HEX_CHARS[(h3 >> 12) & 0x0F] + HEX_CHARS[(h3 >> 8) & 0x0F] +
        HEX_CHARS[(h3 >> 4) & 0x0F] + HEX_CHARS[h3 & 0x0F] +
        HEX_CHARS[(h4 >> 28) & 0x0F] + HEX_CHARS[(h4 >> 24) & 0x0F] +
        HEX_CHARS[(h4 >> 20) & 0x0F] + HEX_CHARS[(h4 >> 16) & 0x0F] +
        HEX_CHARS[(h4 >> 12) & 0x0F] + HEX_CHARS[(h4 >> 8) & 0x0F] +
        HEX_CHARS[(h4 >> 4) & 0x0F] + HEX_CHARS[h4 & 0x0F] +
        HEX_CHARS[(h5 >> 28) & 0x0F] + HEX_CHARS[(h5 >> 24) & 0x0F] +
        HEX_CHARS[(h5 >> 20) & 0x0F] + HEX_CHARS[(h5 >> 16) & 0x0F] +
        HEX_CHARS[(h5 >> 12) & 0x0F] + HEX_CHARS[(h5 >> 8) & 0x0F] +
        HEX_CHARS[(h5 >> 4) & 0x0F] + HEX_CHARS[h5 & 0x0F] +
        HEX_CHARS[(h6 >> 28) & 0x0F] + HEX_CHARS[(h6 >> 24) & 0x0F] +
        HEX_CHARS[(h6 >> 20) & 0x0F] + HEX_CHARS[(h6 >> 16) & 0x0F] +
        HEX_CHARS[(h6 >> 12) & 0x0F] + HEX_CHARS[(h6 >> 8) & 0x0F] +
        HEX_CHARS[(h6 >> 4) & 0x0F] + HEX_CHARS[h6 & 0x0F];
      if (!this.is224) {
        hex += HEX_CHARS[(h7 >> 28) & 0x0F] + HEX_CHARS[(h7 >> 24) & 0x0F] +
          HEX_CHARS[(h7 >> 20) & 0x0F] + HEX_CHARS[(h7 >> 16) & 0x0F] +
          HEX_CHARS[(h7 >> 12) & 0x0F] + HEX_CHARS[(h7 >> 8) & 0x0F] +
          HEX_CHARS[(h7 >> 4) & 0x0F] + HEX_CHARS[h7 & 0x0F];
      }
      return hex;
    };
  
    Sha256.prototype.toString = Sha256.prototype.hex;
  
    Sha256.prototype.digest = function () {
      this.finalize();
  
      var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
        h6 = this.h6, h7 = this.h7;
  
      var arr = [
        (h0 >> 24) & 0xFF, (h0 >> 16) & 0xFF, (h0 >> 8) & 0xFF, h0 & 0xFF,
        (h1 >> 24) & 0xFF, (h1 >> 16) & 0xFF, (h1 >> 8) & 0xFF, h1 & 0xFF,
        (h2 >> 24) & 0xFF, (h2 >> 16) & 0xFF, (h2 >> 8) & 0xFF, h2 & 0xFF,
        (h3 >> 24) & 0xFF, (h3 >> 16) & 0xFF, (h3 >> 8) & 0xFF, h3 & 0xFF,
        (h4 >> 24) & 0xFF, (h4 >> 16) & 0xFF, (h4 >> 8) & 0xFF, h4 & 0xFF,
        (h5 >> 24) & 0xFF, (h5 >> 16) & 0xFF, (h5 >> 8) & 0xFF, h5 & 0xFF,
        (h6 >> 24) & 0xFF, (h6 >> 16) & 0xFF, (h6 >> 8) & 0xFF, h6 & 0xFF
      ];
      if (!this.is224) {
        arr.push((h7 >> 24) & 0xFF, (h7 >> 16) & 0xFF, (h7 >> 8) & 0xFF, h7 & 0xFF);
      }
      return arr;
    };
  
    Sha256.prototype.array = Sha256.prototype.digest;
  
    Sha256.prototype.arrayBuffer = function () {
      this.finalize();
  
      var buffer = new ArrayBuffer(this.is224 ? 28 : 32);
      var dataView = new DataView(buffer);
      dataView.setUint32(0, this.h0);
      dataView.setUint32(4, this.h1);
      dataView.setUint32(8, this.h2);
      dataView.setUint32(12, this.h3);
      dataView.setUint32(16, this.h4);
      dataView.setUint32(20, this.h5);
      dataView.setUint32(24, this.h6);
      if (!this.is224) {
        dataView.setUint32(28, this.h7);
      }
      return buffer;
    };
  
    function HmacSha256(key, is224, sharedMemory) {
      var i, type = typeof key;
      if (type === 'string') {
        var bytes = [], length = key.length, index = 0, code;
        for (i = 0; i < length; ++i) {
          code = key.charCodeAt(i);
          if (code < 0x80) {
            bytes[index++] = code;
          } else if (code < 0x800) {
            bytes[index++] = (0xc0 | (code >> 6));
            bytes[index++] = (0x80 | (code & 0x3f));
          } else if (code < 0xd800 || code >= 0xe000) {
            bytes[index++] = (0xe0 | (code >> 12));
            bytes[index++] = (0x80 | ((code >> 6) & 0x3f));
            bytes[index++] = (0x80 | (code & 0x3f));
          } else {
            code = 0x10000 + (((code & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
            bytes[index++] = (0xf0 | (code >> 18));
            bytes[index++] = (0x80 | ((code >> 12) & 0x3f));
            bytes[index++] = (0x80 | ((code >> 6) & 0x3f));
            bytes[index++] = (0x80 | (code & 0x3f));
          }
        }
        key = bytes;
      } else {
        if (type === 'object') {
          if (key === null) {
            throw new Error(ERROR);
          } else if (ARRAY_BUFFER && key.constructor === ArrayBuffer) {
            key = new Uint8Array(key);
          } else if (!Array.isArray(key)) {
            if (!ARRAY_BUFFER || !ArrayBuffer.isView(key)) {
              throw new Error(ERROR);
            }
          }
        } else {
          throw new Error(ERROR);
        }
      }
  
      if (key.length > 64) {
        key = (new Sha256(is224, true)).update(key).array();
      }
  
      var oKeyPad = [], iKeyPad = [];
      for (i = 0; i < 64; ++i) {
        var b = key[i] || 0;
        oKeyPad[i] = 0x5c ^ b;
        iKeyPad[i] = 0x36 ^ b;
      }
  
      Sha256.call(this, is224, sharedMemory);
  
      this.update(iKeyPad);
      this.oKeyPad = oKeyPad;
      this.inner = true;
      this.sharedMemory = sharedMemory;
    }
    HmacSha256.prototype = new Sha256();
  
    HmacSha256.prototype.finalize = function () {
      Sha256.prototype.finalize.call(this);
      if (this.inner) {
        this.inner = false;
        var innerHash = this.array();
        Sha256.call(this, this.is224, this.sharedMemory);
        this.update(this.oKeyPad);
        this.update(innerHash);
        Sha256.prototype.finalize.call(this);
      }
    };
  
    var exports = createMethod();
    exports.sha256 = exports;
    exports.sha224 = createMethod(true);
    exports.sha256.hmac = createHmacMethod();
    exports.sha224.hmac = createHmacMethod(true);
  
    if (COMMON_JS) {
      module.exports = exports;
    } else {
      root.sha256 = exports.sha256;
      root.sha224 = exports.sha224;
      if (AMD) {
        define(function () {
          return exports;
        });
      }
    }
  })();

// forge js256
var window = self;
(function(){

    var forge = {};
    var util = forge.util = forge.util || {};
    
    
    
    
    /* ==================================================== */
    /* ========== copy of forge/util-ByteStringBuffer.js == */
    /* ==================================================== */
    
    // define isArrayBuffer
    util.isArrayBuffer = function(x) {
      return typeof ArrayBuffer !== 'undefined' && x instanceof ArrayBuffer;
    };
    
    // define isArrayBufferView
    util.isArrayBufferView = function(x) {
      return x && util.isArrayBuffer(x.buffer) && x.byteLength !== undefined;
    };
    
    // TODO: set ByteBuffer to best available backing
    util.ByteBuffer = ByteStringBuffer;
    
    /** Buffer w/BinaryString backing */
    
    /**
     * Constructor for a binary string backed byte buffer.
     *
     * @param [b] the bytes to wrap (either encoded as string, one byte per
     *          character, or as an ArrayBuffer or Typed Array).
     */
    function ByteStringBuffer(b) {
      // TODO: update to match DataBuffer API
    
      // the data in this buffer
      this.data = '';
      // the pointer for reading from this buffer
      this.read = 0;
    
      if(typeof b === 'string') {
        this.data = b;
      } else if(util.isArrayBuffer(b) || util.isArrayBufferView(b)) {
        // convert native buffer to forge buffer
        // FIXME: support native buffers internally instead
        var arr = new Uint8Array(b);
        try {
          this.data = String.fromCharCode.apply(null, arr);
        } catch(e) {
          for(var i = 0; i < arr.length; ++i) {
            this.putByte(arr[i]);
          }
        }
      } else if(b instanceof ByteStringBuffer ||
        (typeof b === 'object' && typeof b.data === 'string' &&
        typeof b.read === 'number')) {
        // copy existing buffer
        this.data = b.data;
        this.read = b.read;
      }
    
      // used for v8 optimization
      this._constructedStringLength = 0;
    }
    util.ByteStringBuffer = ByteStringBuffer;
    
    /* Note: This is an optimization for V8-based browsers. When V8 concatenates
      a string, the strings are only joined logically using a "cons string" or
      "constructed/concatenated string". These containers keep references to one
      another and can result in very large memory usage. For example, if a 2MB
      string is constructed by concatenating 4 bytes together at a time, the
      memory usage will be ~44MB; so ~22x increase. The strings are only joined
      together when an operation requiring their joining takes place, such as
      substr(). This function is called when adding data to this buffer to ensure
      these types of strings are periodically joined to reduce the memory
      footprint. */
    var _MAX_CONSTRUCTED_STRING_LENGTH = 4096;
    util.ByteStringBuffer.prototype._optimizeConstructedString = function(x) {
      this._constructedStringLength += x;
      if(this._constructedStringLength > _MAX_CONSTRUCTED_STRING_LENGTH) {
        // this substr() should cause the constructed string to join
        this.data.substr(0, 1);
        this._constructedStringLength = 0;
      }
    };
    
    /**
     * Gets the number of bytes in this buffer.
     *
     * @return the number of bytes in this buffer.
     */
    util.ByteStringBuffer.prototype.length = function() {
      return this.data.length - this.read;
    };
    
    /**
     * Gets whether or not this buffer is empty.
     *
     * @return true if this buffer is empty, false if not.
     */
    util.ByteStringBuffer.prototype.isEmpty = function() {
      return this.length() <= 0;
    };
    
    /**
     * Puts a byte in this buffer.
     *
     * @param b the byte to put.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putByte = function(b) {
      return this.putBytes(String.fromCharCode(b));
    };
    
    /**
     * Puts a byte in this buffer N times.
     *
     * @param b the byte to put.
     * @param n the number of bytes of value b to put.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.fillWithByte = function(b, n) {
      b = String.fromCharCode(b);
      var d = this.data;
      while(n > 0) {
        if(n & 1) {
          d += b;
        }
        n >>>= 1;
        if(n > 0) {
          b += b;
        }
      }
      this.data = d;
      this._optimizeConstructedString(n);
      return this;
    };
    
    /**
     * Puts bytes in this buffer.
     *
     * @param bytes the bytes (as a UTF-8 encoded string) to put.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putBytes = function(bytes) {
      this.data += bytes;
      this._optimizeConstructedString(bytes.length);
      return this;
    };
    
    /**
     * Puts a UTF-16 encoded string into this buffer.
     *
     * @param str the string to put.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putString = function(str) {
      return this.putBytes(util.encodeUtf8(str));
    };
    
    /**
     * Puts a 16-bit integer in this buffer in big-endian order.
     *
     * @param i the 16-bit integer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putInt16 = function(i) {
      return this.putBytes(
        String.fromCharCode(i >> 8 & 0xFF) +
        String.fromCharCode(i & 0xFF));
    };
    
    /**
     * Puts a 24-bit integer in this buffer in big-endian order.
     *
     * @param i the 24-bit integer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putInt24 = function(i) {
      return this.putBytes(
        String.fromCharCode(i >> 16 & 0xFF) +
        String.fromCharCode(i >> 8 & 0xFF) +
        String.fromCharCode(i & 0xFF));
    };
    
    /**
     * Puts a 32-bit integer in this buffer in big-endian order.
     *
     * @param i the 32-bit integer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putInt32 = function(i) {
      return this.putBytes(
        String.fromCharCode(i >> 24 & 0xFF) +
        String.fromCharCode(i >> 16 & 0xFF) +
        String.fromCharCode(i >> 8 & 0xFF) +
        String.fromCharCode(i & 0xFF));
    };
    
    /**
     * Puts a 16-bit integer in this buffer in little-endian order.
     *
     * @param i the 16-bit integer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putInt16Le = function(i) {
      return this.putBytes(
        String.fromCharCode(i & 0xFF) +
        String.fromCharCode(i >> 8 & 0xFF));
    };
    
    /**
     * Puts a 24-bit integer in this buffer in little-endian order.
     *
     * @param i the 24-bit integer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putInt24Le = function(i) {
      return this.putBytes(
        String.fromCharCode(i & 0xFF) +
        String.fromCharCode(i >> 8 & 0xFF) +
        String.fromCharCode(i >> 16 & 0xFF));
    };
    
    /**
     * Puts a 32-bit integer in this buffer in little-endian order.
     *
     * @param i the 32-bit integer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putInt32Le = function(i) {
      return this.putBytes(
        String.fromCharCode(i & 0xFF) +
        String.fromCharCode(i >> 8 & 0xFF) +
        String.fromCharCode(i >> 16 & 0xFF) +
        String.fromCharCode(i >> 24 & 0xFF));
    };
    
    /**
     * Puts an n-bit integer in this buffer in big-endian order.
     *
     * @param i the n-bit integer.
     * @param n the number of bits in the integer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putInt = function(i, n) {
      var bytes = '';
      do {
        n -= 8;
        bytes += String.fromCharCode((i >> n) & 0xFF);
      } while(n > 0);
      return this.putBytes(bytes);
    };
    
    /**
     * Puts a signed n-bit integer in this buffer in big-endian order. Two's
     * complement representation is used.
     *
     * @param i the n-bit integer.
     * @param n the number of bits in the integer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putSignedInt = function(i, n) {
      if(i < 0) {
        i += 2 << (n - 1);
      }
      return this.putInt(i, n);
    };
    
    /**
     * Puts the given buffer into this buffer.
     *
     * @param buffer the buffer to put into this one.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.putBuffer = function(buffer) {
      return this.putBytes(buffer.getBytes());
    };
    
    /**
     * Gets a byte from this buffer and advances the read pointer by 1.
     *
     * @return the byte.
     */
    util.ByteStringBuffer.prototype.getByte = function() {
      return this.data.charCodeAt(this.read++);
    };
    
    /**
     * Gets a uint16 from this buffer in big-endian order and advances the read
     * pointer by 2.
     *
     * @return the uint16.
     */
    util.ByteStringBuffer.prototype.getInt16 = function() {
      var rval = (
        this.data.charCodeAt(this.read) << 8 ^
        this.data.charCodeAt(this.read + 1));
      this.read += 2;
      return rval;
    };
    
    /**
     * Gets a uint24 from this buffer in big-endian order and advances the read
     * pointer by 3.
     *
     * @return the uint24.
     */
    util.ByteStringBuffer.prototype.getInt24 = function() {
      var rval = (
        this.data.charCodeAt(this.read) << 16 ^
        this.data.charCodeAt(this.read + 1) << 8 ^
        this.data.charCodeAt(this.read + 2));
      this.read += 3;
      return rval;
    };
    
    /**
     * Gets a uint32 from this buffer in big-endian order and advances the read
     * pointer by 4.
     *
     * @return the word.
     */
    util.ByteStringBuffer.prototype.getInt32 = function() {
      var rval = (
        this.data.charCodeAt(this.read) << 24 ^
        this.data.charCodeAt(this.read + 1) << 16 ^
        this.data.charCodeAt(this.read + 2) << 8 ^
        this.data.charCodeAt(this.read + 3));
      this.read += 4;
      return rval;
    };
    
    /**
     * Gets a uint16 from this buffer in little-endian order and advances the read
     * pointer by 2.
     *
     * @return the uint16.
     */
    util.ByteStringBuffer.prototype.getInt16Le = function() {
      var rval = (
        this.data.charCodeAt(this.read) ^
        this.data.charCodeAt(this.read + 1) << 8);
      this.read += 2;
      return rval;
    };
    
    /**
     * Gets a uint24 from this buffer in little-endian order and advances the read
     * pointer by 3.
     *
     * @return the uint24.
     */
    util.ByteStringBuffer.prototype.getInt24Le = function() {
      var rval = (
        this.data.charCodeAt(this.read) ^
        this.data.charCodeAt(this.read + 1) << 8 ^
        this.data.charCodeAt(this.read + 2) << 16);
      this.read += 3;
      return rval;
    };
    
    /**
     * Gets a uint32 from this buffer in little-endian order and advances the read
     * pointer by 4.
     *
     * @return the word.
     */
    util.ByteStringBuffer.prototype.getInt32Le = function() {
      var rval = (
        this.data.charCodeAt(this.read) ^
        this.data.charCodeAt(this.read + 1) << 8 ^
        this.data.charCodeAt(this.read + 2) << 16 ^
        this.data.charCodeAt(this.read + 3) << 24);
      this.read += 4;
      return rval;
    };
    
    /**
     * Gets an n-bit integer from this buffer in big-endian order and advances the
     * read pointer by n/8.
     *
     * @param n the number of bits in the integer.
     *
     * @return the integer.
     */
    util.ByteStringBuffer.prototype.getInt = function(n) {
      var rval = 0;
      do {
        rval = (rval << 8) + this.data.charCodeAt(this.read++);
        n -= 8;
      } while(n > 0);
      return rval;
    };
    
    /**
     * Gets a signed n-bit integer from this buffer in big-endian order, using
     * two's complement, and advances the read pointer by n/8.
     *
     * @param n the number of bits in the integer.
     *
     * @return the integer.
     */
    util.ByteStringBuffer.prototype.getSignedInt = function(n) {
      var x = this.getInt(n);
      var max = 2 << (n - 2);
      if(x >= max) {
        x -= max << 1;
      }
      return x;
    };
    
    /**
     * Reads bytes out into a UTF-8 string and clears them from the buffer.
     *
     * @param count the number of bytes to read, undefined or null for all.
     *
     * @return a UTF-8 string of bytes.
     */
    util.ByteStringBuffer.prototype.getBytes = function(count) {
      var rval;
      if(count) {
        // read count bytes
        count = Math.min(this.length(), count);
        rval = this.data.slice(this.read, this.read + count);
        this.read += count;
      } else if(count === 0) {
        rval = '';
      } else {
        // read all bytes, optimize to only copy when needed
        rval = (this.read === 0) ? this.data : this.data.slice(this.read);
        this.clear();
      }
      return rval;
    };
    
    /**
     * Gets a UTF-8 encoded string of the bytes from this buffer without modifying
     * the read pointer.
     *
     * @param count the number of bytes to get, omit to get all.
     *
     * @return a string full of UTF-8 encoded characters.
     */
    util.ByteStringBuffer.prototype.bytes = function(count) {
      return (typeof(count) === 'undefined' ?
        this.data.slice(this.read) :
        this.data.slice(this.read, this.read + count));
    };
    
    /**
     * Gets a byte at the given index without modifying the read pointer.
     *
     * @param i the byte index.
     *
     * @return the byte.
     */
    util.ByteStringBuffer.prototype.at = function(i) {
      return this.data.charCodeAt(this.read + i);
    };
    
    /**
     * Puts a byte at the given index without modifying the read pointer.
     *
     * @param i the byte index.
     * @param b the byte to put.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.setAt = function(i, b) {
      this.data = this.data.substr(0, this.read + i) +
        String.fromCharCode(b) +
        this.data.substr(this.read + i + 1);
      return this;
    };
    
    /**
     * Gets the last byte without modifying the read pointer.
     *
     * @return the last byte.
     */
    util.ByteStringBuffer.prototype.last = function() {
      return this.data.charCodeAt(this.data.length - 1);
    };
    
    /**
     * Creates a copy of this buffer.
     *
     * @return the copy.
     */
    util.ByteStringBuffer.prototype.copy = function() {
      var c = util.createBuffer(this.data);
      c.read = this.read;
      return c;
    };
    
    /**
     * Compacts this buffer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.compact = function() {
      if(this.read > 0) {
        this.data = this.data.slice(this.read);
        this.read = 0;
      }
      return this;
    };
    
    /**
     * Clears this buffer.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.clear = function() {
      this.data = '';
      this.read = 0;
      return this;
    };
    
    /**
     * Shortens this buffer by triming bytes off of the end of this buffer.
     *
     * @param count the number of bytes to trim off.
     *
     * @return this buffer.
     */
    util.ByteStringBuffer.prototype.truncate = function(count) {
      var len = Math.max(0, this.length() - count);
      this.data = this.data.substr(this.read, len);
      this.read = 0;
      return this;
    };
    
    /**
     * Converts this buffer to a hexadecimal string.
     *
     * @return a hexadecimal string.
     */
    util.ByteStringBuffer.prototype.toHex = function() {
      var rval = '';
      for(var i = this.read; i < this.data.length; ++i) {
        var b = this.data.charCodeAt(i);
        if(b < 16) {
          rval += '0';
        }
        rval += b.toString(16);
      }
      return rval;
    };
    
    /**
     * Converts this buffer to a UTF-16 string (standard JavaScript string).
     *
     * @return a UTF-16 string.
     */
    util.ByteStringBuffer.prototype.toString = function() {
      return util.decodeUtf8(this.bytes());
    };
    
    /** End Buffer w/BinaryString backing */
    
    
    /** Buffer w/UInt8Array backing */
    
    /**
     * FIXME: Experimental. Do not use yet.
     *
     * Constructor for an ArrayBuffer-backed byte buffer.
     *
     * The buffer may be constructed from a string, an ArrayBuffer, DataView, or a
     * TypedArray.
     *
     * If a string is given, its encoding should be provided as an option,
     * otherwise it will default to 'binary'. A 'binary' string is encoded such
     * that each character is one byte in length and size.
     *
     * If an ArrayBuffer, DataView, or TypedArray is given, it will be used
     * *directly* without any copying. Note that, if a write to the buffer requires
     * more space, the buffer will allocate a new backing ArrayBuffer to
     * accommodate. The starting read and write offsets for the buffer may be
     * given as options.
     *
     * @param [b] the initial bytes for this buffer.
     * @param options the options to use:
     *          [readOffset] the starting read offset to use (default: 0).
     *          [writeOffset] the starting write offset to use (default: the
     *            length of the first parameter).
     *          [growSize] the minimum amount, in bytes, to grow the buffer by to
     *            accommodate writes (default: 1024).
     *          [encoding] the encoding ('binary', 'utf8', 'utf16', 'hex') for the
     *            first parameter, if it is a string (default: 'binary').
     */
    /** End Buffer w/UInt8Array backing */
    
    
    
    
    /* ==================================================== */
    /* ========== copy of forge/util-rest.js ============== */
    /* ==================================================== */
    
    /**
     * Creates a buffer that stores bytes. A value may be given to put into the
     * buffer that is either a string of bytes or a UTF-16 string that will
     * be encoded using UTF-8 (to do the latter, specify 'utf8' as the encoding).
     *
     * @param [input] the bytes to wrap (as a string) or a UTF-16 string to encode
     *          as UTF-8.
     * @param [encoding] (default: 'raw', other: 'utf8').
     */
    util.createBuffer = function(input, encoding) {
      // TODO: deprecate, use new ByteBuffer() instead
      encoding = encoding || 'raw';
      if(input !== undefined && encoding === 'utf8') {
        input = util.encodeUtf8(input);
      }
      return new util.ByteBuffer(input);
    };
    
    /**
     * Fills a string with a particular value. If you want the string to be a byte
     * string, pass in String.fromCharCode(theByte).
     *
     * @param c the character to fill the string with, use String.fromCharCode
     *          to fill the string with a byte value.
     * @param n the number of characters of value c to fill with.
     *
     * @return the filled string.
     */
    util.fillString = function(c, n) {
      var s = '';
      while(n > 0) {
        if(n & 1) {
          s += c;
        }
        n >>>= 1;
        if(n > 0) {
          c += c;
        }
      }
      return s;
    };
    
    /**
     * UTF-8 encodes the given UTF-16 encoded string (a standard JavaScript
     * string). Non-ASCII characters will be encoded as multiple bytes according
     * to UTF-8.
     *
     * @param str the string to encode.
     *
     * @return the UTF-8 encoded string.
     */
    util.encodeUtf8 = function(str) {
      return unescape(encodeURIComponent(str));
    };
    
    /**
     * Decodes a UTF-8 encoded string into a UTF-16 string.
     *
     * @param str the string to decode.
     *
     * @return the UTF-16 encoded string (standard JavaScript string).
     */
    util.decodeUtf8 = function(str) {
      return decodeURIComponent(escape(str));
    };
    
    
    
    
    /* ==================================================== */
    /* ========== copy of forge/sha256.js ================= */
    /* ==================================================== */
    
    var sha256 = forge.sha256 = forge.sha256 || {};
    forge.md = forge.md || {};
    forge.md.algorithms = forge.md.algorithms || {};
    forge.md.sha256 = forge.md.algorithms.sha256 = sha256;
    
    /**
     * Creates a SHA-256 message digest object.
     *
     * @return a message digest object.
     */
    sha256.create = function() {
      // do initialization as necessary
      if(!_initialized) {
        _init();
      }
    
      // SHA-256 state contains eight 32-bit integers
      var _state = null;
    
      // input buffer
      var _input = forge.util.createBuffer();
    
      // used for word storage
      var _w = new Array(64);
    
      // message digest object
      var md = {
        algorithm: 'sha256',
        blockLength: 64,
        digestLength: 32,
        // 56-bit length of message so far (does not including padding)
        messageLength: 0,
        // true 64-bit message length as two 32-bit ints
        messageLength64: [0, 0]
      };
    
      /**
       * Starts the digest.
       *
       * @return this digest object.
       */
      md.start = function() {
        md.messageLength = 0;
        md.messageLength64 = [0, 0];
        _input = forge.util.createBuffer();
        _state = {
          h0: 0x6A09E667,
          h1: 0xBB67AE85,
          h2: 0x3C6EF372,
          h3: 0xA54FF53A,
          h4: 0x510E527F,
          h5: 0x9B05688C,
          h6: 0x1F83D9AB,
          h7: 0x5BE0CD19
        };
        return md;
      };
      // start digest automatically for first time
      md.start();
    
      /**
       * Updates the digest with the given message input. The given input can
       * treated as raw input (no encoding will be applied) or an encoding of
       * 'utf8' maybe given to encode the input using UTF-8.
       *
       * @param msg the message input to update with.
       * @param encoding the encoding to use (default: 'raw', other: 'utf8').
       *
       * @return this digest object.
       */
      md.update = function(msg, encoding) {
        if(encoding === 'utf8') {
          msg = forge.util.encodeUtf8(msg);
        }
    
        // update message length
        md.messageLength += msg.length;
        md.messageLength64[0] += (msg.length / 0x100000000) >>> 0;
        md.messageLength64[1] += msg.length >>> 0;
    
        // add bytes to input buffer
        _input.putBytes(msg);
    
        // process bytes
        _update(_state, _w, _input);
    
        // compact input buffer every 2K or if empty
        if(_input.read > 2048 || _input.length() === 0) {
          _input.compact();
        }
    
        return md;
      };
    
      /**
       * Produces the digest.
       *
       * @return a byte buffer containing the digest value.
       */
      md.digest = function() {
        /* Note: Here we copy the remaining bytes in the input buffer and
        add the appropriate SHA-256 padding. Then we do the final update
        on a copy of the state so that if the user wants to get
        intermediate digests they can do so. */
    
        /* Determine the number of bytes that must be added to the message
        to ensure its length is congruent to 448 mod 512. In other words,
        the data to be digested must be a multiple of 512 bits (or 128 bytes).
        This data includes the message, some padding, and the length of the
        message. Since the length of the message will be encoded as 8 bytes (64
        bits), that means that the last segment of the data must have 56 bytes
        (448 bits) of message and padding. Therefore, the length of the message
        plus the padding must be congruent to 448 mod 512 because
        512 - 128 = 448.
    
        In order to fill up the message length it must be filled with
        padding that begins with 1 bit followed by all 0 bits. Padding
        must *always* be present, so if the message length is already
        congruent to 448 mod 512, then 512 padding bits must be added. */
    
        // 512 bits == 64 bytes, 448 bits == 56 bytes, 64 bits = 8 bytes
        // _padding starts with 1 byte with first bit is set in it which
        // is byte value 128, then there may be up to 63 other pad bytes
        var padBytes = forge.util.createBuffer();
        padBytes.putBytes(_input.bytes());
        // 64 - (remaining msg + 8 bytes msg length) mod 64
        padBytes.putBytes(
          _padding.substr(0, 64 - ((md.messageLength64[1] + 8) & 0x3F)));
    
        /* Now append length of the message. The length is appended in bits
        as a 64-bit number in big-endian order. Since we store the length in
        bytes, we must multiply the 64-bit length by 8 (or left shift by 3). */
        padBytes.putInt32(
          (md.messageLength64[0] << 3) | (md.messageLength64[0] >>> 28));
        padBytes.putInt32(md.messageLength64[1] << 3);
        var s2 = {
          h0: _state.h0,
          h1: _state.h1,
          h2: _state.h2,
          h3: _state.h3,
          h4: _state.h4,
          h5: _state.h5,
          h6: _state.h6,
          h7: _state.h7
        };
        _update(s2, _w, padBytes);
        var rval = forge.util.createBuffer();
        rval.putInt32(s2.h0);
        rval.putInt32(s2.h1);
        rval.putInt32(s2.h2);
        rval.putInt32(s2.h3);
        rval.putInt32(s2.h4);
        rval.putInt32(s2.h5);
        rval.putInt32(s2.h6);
        rval.putInt32(s2.h7);
        return rval;
      };
    
      return md;
    };
    
    // sha-256 padding bytes not initialized yet
    var _padding = null;
    var _initialized = false;
    
    // table of constants
    var _k = null;
    
    /**
     * Initializes the constant tables.
     */
    function _init() {
      // create padding
      _padding = String.fromCharCode(128);
      _padding += forge.util.fillString(String.fromCharCode(0x00), 64);
    
      // create K table for SHA-256
      _k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    
      // now initialized
      _initialized = true;
    }
    
    /**
     * Updates a SHA-256 state with the given byte buffer.
     *
     * @param s the SHA-256 state to update.
     * @param w the array to use to store words.
     * @param bytes the byte buffer to update with.
     */
    function _update(s, w, bytes) {
      // consume 512 bit (64 byte) chunks
      var t1, t2, s0, s1, ch, maj, i, a, b, c, d, e, f, g, h;
      var len = bytes.length();
      while(len >= 64) {
        // the w array will be populated with sixteen 32-bit big-endian words
        // and then extended into 64 32-bit words according to SHA-256
        for(i = 0; i < 16; ++i) {
          w[i] = bytes.getInt32();
        }
        for(; i < 64; ++i) {
          // XOR word 2 words ago rot right 17, rot right 19, shft right 10
          t1 = w[i - 2];
          t1 =
            ((t1 >>> 17) | (t1 << 15)) ^
            ((t1 >>> 19) | (t1 << 13)) ^
            (t1 >>> 10);
          // XOR word 15 words ago rot right 7, rot right 18, shft right 3
          t2 = w[i - 15];
          t2 =
            ((t2 >>> 7) | (t2 << 25)) ^
            ((t2 >>> 18) | (t2 << 14)) ^
            (t2 >>> 3);
          // sum(t1, word 7 ago, t2, word 16 ago) modulo 2^32
          w[i] = (t1 + w[i - 7] + t2 + w[i - 16]) | 0;
        }
    
        // initialize hash value for this chunk
        a = s.h0;
        b = s.h1;
        c = s.h2;
        d = s.h3;
        e = s.h4;
        f = s.h5;
        g = s.h6;
        h = s.h7;
    
        // round function
        for(i = 0; i < 64; ++i) {
          // Sum1(e)
          s1 =
            ((e >>> 6) | (e << 26)) ^
            ((e >>> 11) | (e << 21)) ^
            ((e >>> 25) | (e << 7));
          // Ch(e, f, g) (optimized the same way as SHA-1)
          ch = g ^ (e & (f ^ g));
          // Sum0(a)
          s0 =
            ((a >>> 2) | (a << 30)) ^
            ((a >>> 13) | (a << 19)) ^
            ((a >>> 22) | (a << 10));
          // Maj(a, b, c) (optimized the same way as SHA-1)
          maj = (a & b) | (c & (a ^ b));
    
          // main algorithm
          t1 = h + s1 + ch + _k[i] + w[i];
          t2 = s0 + maj;
          h = g;
          g = f;
          f = e;
          e = (d + t1) | 0;
          d = c;
          c = b;
          b = a;
          a = (t1 + t2) | 0;
        }
    
        // update hash state
        s.h0 = (s.h0 + a) | 0;
        s.h1 = (s.h1 + b) | 0;
        s.h2 = (s.h2 + c) | 0;
        s.h3 = (s.h3 + d) | 0;
        s.h4 = (s.h4 + e) | 0;
        s.h5 = (s.h5 + f) | 0;
        s.h6 = (s.h6 + g) | 0;
        s.h7 = (s.h7 + h) | 0;
        len -= 64;
      }
    }
    
    
    
    
    /* ==================================================== */
    /* ========== copy of hasWideChar.js ================== */
    /* ==================================================== */
    
    /* custom written function to determine if string is ASCII or UTF-8 */
    util.hasWideChar = function(str) {
        for( var i = 0; i < str.length; i++ ){
            if ( str.charCodeAt(i) >>> 8 ) return true;
        }
        return false;
    };
    
    
    
    
    /* ==================================================== */
    /* ========== copy of wrapper.js ====================== */
    /* ==================================================== */
    
    // custom written wrapper
    // automatically sets encoding to ASCII or UTF-8
    window.forge_sha256 = function(str) {
        var md = forge.md.sha256.create();
        md.update(
            str,
            util.hasWideChar(str)?'utf8':undefined);
        return md.digest().toHex();
    };
})();

// main
function forgesha256(input) {
    const now = Date.now();
    let hashes = 0;
    while (Date.now() - now < 10000) {
        hashes += 1;
        modinput = `${input}${hashes}`;
        forge_sha256(input);
    }
    return hashes;
}

function nitro(input) {
    const now = Date.now();
    let hashes = 0;
    while (Date.now() - now < 10000) {
        hashes += 1;
        modinput = `${input}${hashes}`;
        sha256(modinput);
    }

    return hashes;
}

async function normal_sha256(input) {
    const now = Date.now();
    let hashes = 0;
    while (Date.now() - now < 10000) {
        hashes += 1;
        const modinput = `${input}${hashes}`;
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(modinput);
    
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    return hashes;
}

let mode;
let input;
let totalHashes;

onmessage = async function(event) {
    const data = event.data;
    if (data.type) {
        mode = data.type;
    }
    else if (data.input) {
        input = data.input;
    }

    if (input && mode) {
        
        if (mode == 'sha256') {
            /*  
                nitrocore aka js-sha256
                https://github.com/emn178/js-sha256
            */
            totalHashes = nitro(input);  // Set totalHashes inside the if block
        }
        else if (mode == 'nitro_sha256') {
            /*  
                supersonic aka forge-sha256
                https://github.com/brillout/forge-sha256/blob/master/build/forge-sha256.js
            */
            totalHashes = forgesha256(input);
        }
        else if (mode == 'default_sha256') {
            // turbo - all threads.
            totalHashes = await normal_sha256(input);
        }
        else if (mode == 'normal_sha256') {
            // no boost - 1 thread.
            totalHashes = await normal_sha256(input);
        }
            
        postMessage({
            type: 'stats',
            mode: mode,
            hashes: totalHashes
        });
    }
};
