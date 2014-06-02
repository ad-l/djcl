/**
 * AES encryption and associated modes. Supports 128, 192 and 256 bit keys.
 * @author Antoine Delignat-Lavaud
 * @description
 * <p>Implementation of AES on 256 bit keys.</p>
 * @requires encoding
 * @namespace
 */
 var aes =
 {
  Stables: (function()
  {
   var a256 = function()
   {
    return [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
   },

   t5 = function(){return [a256(), a256(), a256(), a256(), a256()]},
   encTable = t5(), decTable = t5(),
   sbox = encTable[4], sboxInv = decTable[4],
   i = 0, x = 0, xInv = 0, x2 = 0, x4 = 0, x8 = 0,
   tEnc = 0, tDec = 0, s = 0, d = a256(), th = a256();

   for(i=0; i < 256; i++)
    th[((d[i & 255] = i<<1 ^ (i>>7)*283)^i) & 255] = i;

   for(x=xInv=0; !sbox[x&255]; x^=(!x2?1:x2), xInv=th[xInv&255], xInv=(!xInv?1:xInv))
   {
    s = xInv ^ xInv<<1 ^ xInv<<2 ^ xInv<<3 ^ xInv<<4;
    s = s>>8 ^ s&255 ^ 99;
    sbox[x&255] = s; sboxInv[s&255] = x;

    x8 = d[(x4 = d[(x2 = d[x&255])&255])&255];
    tDec = x8*0x1010101 ^ x4*0x10001 ^ x2*0x101 ^ x*0x1010100;
    tEnc = d[s&255]*0x101 ^ s*0x1010100;

    for (i=0; i<4; i++)
    {
     encTable[i&3][x&255] = tEnc = tEnc<<24 ^ tEnc>>>8;
     decTable[i&3][s&255] = tDec = tDec<<24 ^ tDec>>>8;
    }
   }

   return [encTable, decTable];
  })(),

  key: (function()
  {
   var a = function(){ return [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
   ]};
   return [a(),a()];
  })(),

/** The AES key size, either 4, 6 or 8 bytes.
  * This field is automatically set by the setKey method
  * based on the length of the given key.
  */
  keySize: 8,

/** Set the key to use for encryption and decryption.
  * Accepts 128, 192 and 256 bit keys.
  * @param {string} key ASCII key (16, 24 or 32 bytes long)
  */
  setKey: function(key)
  {
   var key = key + "", k = [0,0,0,0,0,0,0,0],
       kl = key.length > 24 ? 8 : (key.length > 16 ? 6 : 4),
       pad = function(s){var s = s+''; while(s.length < 4*kl) s = "\x00"+s; return s},
       key = pad(key), i = 0, s = 0;

   this.keySize = kl;
   for(i=0; i<key.length; i++)
   {
    s = (s<<8) + encoding.a2b(key[i]);
    if((i%4)==3) k[(i/4)&7] = s;
   }
   this._setKey(k);
  },

  _setKey: function(key)
  {
   var i = 0, j = 0, rcon = 1, tmp = 0,
     keySize = this.keySize,
      encKey = this.key[0],
      decKey = this.key[1],
    decTable = this.Stables[1],
        sbox = this.Stables[0][4];

   for(i = 0; i < 4*keySize+28; i++)
   {
    if(i < keySize)
    {
     encKey[i & 63] = key[i & 7];
     continue;
    }

    tmp = encKey[(i-1) & 63];
    if(!(i%keySize) || (keySize==8 && !(i%4)))
    {
     tmp = sbox[tmp>>>24 & 255]<<24
         ^ sbox[tmp>>16  & 255]<<16
         ^ sbox[tmp>>8   & 255]<<8
         ^ sbox[tmp & 255];

     if(!(i%keySize))
     {
      tmp = tmp<<8 ^ tmp>>>24 ^ rcon<<24;
      rcon = rcon<<1 ^ (rcon>>7)*283;
     }
    }

    encKey[i & 63] = encKey[(i-keySize) & 63] ^ tmp;
   }
  
   for(j = 0; i>0; j++, i--)
   {
    tmp = encKey[(!(j&3) ? i-4 : i)&63];

    decKey[j & 63] =
     (i<=4 || j<4) ? tmp :
     decTable[0][sbox[tmp>>>24 & 255] & 255] ^
     decTable[1][sbox[tmp>>16  & 255] & 255] ^
     decTable[2][sbox[tmp>>8   & 255] & 255] ^
     decTable[3][sbox[tmp      & 255] & 255];
   }
  },

/** Constant time string equality - this is to prevent timing attacks
  * This function is very slow and should only be used for sensitive comparisons
  * @param {string} first string
  * @param {string} second string
  * @returns {boolean} true iff strings are equal
  */
  ctEq: function(a, b)
  {
    var res = true, i = 0,
        a = a+'', b=b+'',
        n = a.length < b.length ? b.length : a.length;

    for(i = 0; i < n; i++)
     if(((i>>>=0)<a.length?a[i]:'') != ((i>>>=0)<b.length?b[i]:''))
      res = false;

    return res;
  },

/** Internal AES block function.
  * @param {number[]} input array of four 32-bit words to process
  * @param {boolean} dir false for encryption, true for decryption
  * @returns {number[]} result of the encryption, an array of 8 32-bit words
  */
  _aes: function(input, dir)
  {
   var key = this.key[(!dir ? 0 : 1) & 1],
         a = input[0] ^ key[0],
         b = input[(!dir ? 1 : 3) & 3] ^ key[1],
         c = input[2] ^ key[2],
         d = input[(!dir ? 3 : 1) & 3] ^ key[3],
        a2 = 0, b2 = 0, c2 = 0, i = 0, kIndex = 4,
       out = [0, 0, 0, 0],
    rounds = 5+this.keySize,
     table = this.Stables[(!dir ? 0 : 1 ) & 1],
        t0 = table[0], t1 = table[1], t2 = table[2],
        t3 = table[3], sbox = table[4];

   for(i = 0; i < rounds; i++)
   {
    a2 = t0[a>>>24 & 255] ^ t1[b>>16 & 255] ^ t2[c>>8 & 255] ^ t3[d & 255] ^ key[kIndex & 63];
    b2 = t0[b>>>24 & 255] ^ t1[c>>16 & 255] ^ t2[d>>8 & 255] ^ t3[a & 255] ^ key[(kIndex + 1) & 63];
    c2 = t0[c>>>24 & 255] ^ t1[d>>16 & 255] ^ t2[a>>8 & 255] ^ t3[b & 255] ^ key[(kIndex + 2) & 63];
    d  = t0[d>>>24 & 255] ^ t1[a>>16 & 255] ^ t2[b>>8 & 255] ^ t3[c & 255] ^ key[(kIndex + 3) & 63];
    kIndex += 4; a = a2; b = b2; c = c2;
   }
        
   for(i = 0; i < 4; i++)
   {
    out[(!dir ? i : (3&-i)) & 3] =
    sbox[a>>>24 & 255]<<24 ^ 
    sbox[b>>16  & 255]<<16 ^
    sbox[c>>8   & 255]<<8  ^
    sbox[d      & 255]     ^
    key[kIndex++ & 63];
    a2=a; a=b; b=c; c=d; d=a2;
   }

   return out;
  },

/** Block generator function, with PKCS#5 support for padding.
  * @private
  * @param {string} s input string to process in blocks
  * @param {boolean} dir false for encryption, true for decryption (no padding)
  * @returns {{blocks:number, gen:blockgen}} A record containing the number of blocks and the block generating function
  */
  _blockGen: function(s, dir)
  {
   var s = s+'', len = s.length, block = 0, i = 0, e = len&15,
       blocks = (!dir&&!e?1:0)+(!e?0:1)+(len>>4), pad = (blocks<<4)-len,

   gen = function()
   {
    var res = [0,0,0,0], i = 0, j = 0,
        m = 0, base = block++ << 4, tmp = 0;

    for(i = 0; i < 4; i++)
    {
     for(tmp = 0, j = base+4*i, m = j+4; j < m; j++)
      tmp = (tmp<<8)+encoding.a2b((j>>>=0)<s.length ? s[j] : "\x00");
     res[i&3] = tmp;
    }
    return res;
   };

   if(!dir) for(i=0; i<pad; i++) s += encoding.b2a(pad);
   else while(!!(e++%16)) s += "\x00";

   return {blocks: blocks, gen: gen};
  },

/** Output processing. By default, returns an ASCII string.
  * @private
  * @param {number[]} block internal block (four 32-bit words) to output
  * @param {boolean} last true if this is the last block, false otherwise
  * @returns {string} ASCII string representing the input block. Will unpad if this is the last block.
  */
  _output: function(block, last)
  {
   var res = "", i = 0, j = 0, c = 0, pad = 16; 

   if(last) pad -= 1+block[3]&255;

   for(i=0; i < 4; i++)
    for(c = block[i&3], j=0; j<4 && res.length <= pad; j++)
     res += encoding.b2a(c >> (24-8*j) &255);

   return res;
  },

  _xor4: function(x,y)
  {
   return [x[0]^y[0], x[1]^y[1], x[2]^y[2], x[3]^y[3]];
  },

/** CBC mode encryption and decryption using AES.
  * @param {string} s input plaintext or ciphertext (ASCII string)
  * @param {string} iv initial vector of the encryption, a 16 bytes ASCII string
  * @param {boolean} dir false for encryption, true for encryption
  * @returns {string} result as an ASCII string
  */
  CBC: function(s, iv, dir)
  {
   var  i = 0, res = "", last = false,
    input = this._blockGen(s, dir),
       iv = this._blockGen(iv, true).gen(),
    block = [0,0,0,0],
      xor = this._xor4;

   for(i=0; i<input.blocks; i++)
   {
    block = input.gen();

    if(!dir)
    {
     iv = this._aes(xor(iv,block), false);
     res += this._output(iv, false);
    }
    else
    {
     res += this._output(xor(iv, this._aes(block,true)), i+1 == input.blocks);
     iv = block;
    }
   }

   return res;
  },

  /** Authenticated encryption in CCM mode (provides ciphertext integrity).
   * @param {string} s input plaintext (ASCII string)
   * @param {string} iv Random initialization vector, 16 byte ASCII string
   * @param {string} adata Optional authentication data (not secret but integrity protected)
   * @param {number} tlen tag length in bytes (2 to 16) - high values make it harder to tamper with the ciphertext
   * @return {string} the encrypted data, an ASCII string
   */
  CCM_encrypt: function(s, iv2, adata, tlen)
  {
   var tlen = (tlen<4 || tlen>16 || !!(tlen&1)) ? 8 : tlen,
       s=s+'', sl=s.length, ol=sl>>3, L=0, i=0, iv = '',
       tag = '', res = {data:'', tag:''};

   for(L=2; L<4 && !!(ol>>>8*L); L++);
   for(iv2+='';iv2.length < 16; iv2+="\x00");
   for(i=0; i<iv2.length; i++){ iv += iv2[i]; if(i>13-L) break }
 
   tag = this._ccmTag(s, iv, adata, tlen, L);
   res = this._ctrMode(s, iv, tag, tlen, L);

   return res.data + res.tag;
  },
  
  /** Decryption in CCM mode.
   * @param {string} s input ciphertext
   * @param {string} iv random initialization vector (ASCII string)
   * @param {string} adata Optional authenticated data (ASCII)
   * @param {number} tlen tag length in bytes
   * @return {{valid:bolean,data:string}} Object containing the decrypted data and authentication status
   */
  CCM_decrypt: function(s, iv2, adata, tlen)
  {
   var tlen = (tlen<4 || tlen>16 || !!(tlen&1)) ? 8 : tlen,
       s=s+'', sl=s.length, c = '', ol=(sl-tlen)>>3, L=0,
       i=0, res = {data:'',tag:''}, tag = '', iv = '';

   for(i=0; i<s.length; i++)
   {
    if(i < sl-tlen) c += s[i];
    else tag += s[i];
   }

   for(L=2; L<4 && !!(ol>>>8*L); L++);
   for(iv2+='';iv2.length < 16; iv2+="\x00");
   for(i=0; i<iv2.length; i++){ iv += iv2[i]; if(i>13-L) break }

   res = this._ctrMode(c, iv, tag, tlen, L);
   s = this._ccmTag(res.data, iv, adata, tlen, L);

   return {valid: this.ctEq(s,res.tag), data: res.data};
  },

  _ccmTag: function(s, iv, adata, tlen, L)
  {
   var i=0, s=s+'', sl=s.length, xor = this._xor4, c = [0,0,0,0],
       ad = (function(x){var x=x+'', n=x.length, c=function(n){
       return encoding.b2a(n)}; if(!n) return x; if(n<=0xFEFF)
       return c(n>>16)+c(n&255)+x; return "\xff\xfe"+c(n>>>24)+
       c(n>>16&255)+c(n>>8&255)+c(n&255)+x})(adata), res = '', T = '',
       p = this._blockGen(s, true), q = this._blockGen(ad, true);

   T = encoding.b2a(((adata==''?0:1)<<6) | (((tlen-2)>>1)<<3) | (L-1))+iv;
   for(i=15-T.length; i>=0; i--) T += encoding.b2a(i>3?0:sl>>>8*i);
   c = this._aes(this._blockGen(T,true).gen(), false);

   if(!!ad) // Additional data
    for(i=0; i<q.blocks; i++) c = this._aes(xor(c, q.gen()), false);
   for(i=0; i<p.blocks; i++) c = this._aes(xor(c, p.gen()), false);

   T = this._output(c, false);
   for(i=0; i<T.length; i++)
   {
    res += T[i];
    if(i+1 == tlen) break;
   }

   return res;
  },

  _ctrMode: function(s, iv, tag, tlen, L)
  {
   var ctr = this._blockGen(encoding.b2a(L-1)+iv, true).gen(), tag0=tag,
       xor = this._xor4, res = "", D = this._blockGen(s, true), sl=s.length,
       tag = xor(this._blockGen(tag, true).gen(), this._aes(ctr, false)),
       ts = '', i = 0, c = "", j = 0;

   c = this._output(tag, false);
   for(i=0; i<c.length; i++){ ts+=c[i]; if(i+1==tlen) break; }

   for (i=0; i<D.blocks; i++)
   {
    ctr[3]++;
    c = this._output(xor(D.gen(), this._aes(ctr, false)), false);
    for(j=0; j<c.length; j++)
    {
     res += c[j];
     if(res.length == sl) break;
    }
   }

   return {tag:ts, data:res};
  }
 };

