/**
 * RSA Public Key cryptography
 * @author Antoine Delignat-Lavaud
 * @description
 * <p>An implementation of PKCS#1 v2.1.</p>
 * <p>The main difference with other PKCS#1 implementations
 * is the format of the keys. Instead of using ASN.1 for
 * encoding, the keys are stored in an equivalent JSON object.
 * For a public key, the fields are 'n' for the modulus and
 * 'e' for the public exponent. In addition, a private key must
 * contain the CRT values 'dmp1', 'dmq1', 'p', 'q' and 'iqmp'
 * (the private exponent 'd' is not required because it is not
 * used for decryption; using BigInteger it is easy to compute
 * 'dmp1', 'dmq1' and 'iqmp' from 'd', 'p' and 'q').</p>
 * <p>Use the following PHP script (requires the openssl extension)
 * to convert a PKCS#1 key to JSON:</p>
 * <pre>#!/usr/bin/env php
 * &lt;?
 * if(count($argv)&lt;2) die("Usage: {$argv[0]} file.pem\n");
 * $f = "file://{$argv[1]}";
 * if(!($k = openssl_pkey_get_private($f)))
 *  dir("Failed to import private key {$argv[1]}.\n");
 * $d = openssl_pkey_get_details($k);
 * $pk = $d['rsa'];
 * foreach($pk as $p=&gt;$v) $pk[$p] = bin2hex($v);
 * echo json_encode($pk)."\n";</pre>
 * @requires BigInteger
 * @requires encoding
 * @requires hashing
 * @namespace
 */
 var rsa =
 {
/** Label of OAEP encryption, an ASCII string empty by default.
  * Can be of any length since it will be hash using rsa.encryption_hash
  */
  label: '',

/** Salt of PSS signature, an ASCII string empty by default.
  * The max length is n-h-2 where n is the modulus size in bytes and h the
  * size in bytes of the output of the hash function.
  */
  salt: '',

/** Hash function to use for OAEP label (hashing.sha256 by default) */
  encryption_hash: hashing.sha256,

/** Hash function to use for MGF function (hashing.sha256 by default) */
  mgf_hash: hashing.sha256,

/** Hash function to use for PSS signature (hashing.sha256 by default) */
  signature_hash: hashing.sha256,

/** If something fails, this code provides information about the error.
  * <table width="100%"><tr><th>Code</th><th>Description</th></tr>
  * <tr><th>0</td><td>No error.</td></tr>
  * <tr><th>1</td><td>Message is too long for the modulus.</td></tr>
  * <tr><th>2</td><td>Invalid length of the input to decrypt or verify.</td></tr>
  * <tr><th>3</td><td>Top byte/bit is not zero after decryption/verification.</td></tr>
  * <tr><th>4</td><td>Incorrect padding of encrypted/signature data.</td></tr>
  * <tr><th>5</td><td>Bad label of OAEP encryption.</td></tr>
  * <tr><th>6</td><td>PSS salt is too long for modulus.</td></tr>
  * <tr><th>7</td><td>Invalid PSS padding byte in PSS signature.</td></tr>
  * </table> */
  error_code: 0,

/** RSAES-OAEP-ENCRYPT encryption.
  * @param {string} m Message to encode, an ASCII string
  * @param {publicKey} pub Public key
  * @returns {string} Hex string representing the encrypted message
  */
  encrypt: function(message, pub)
  {
   var m = encoding.astr2hstr(message)+'', l = m.length>>1,
       N = BigInteger.create(pub.n+''), E = BigInteger.create(pub.e+''),
       h = this.encryption_hash, n = BigInteger.bitLength(N)>>3,
       i = 0, DB = '', pad = '', sm = '', hs = h.size, w = this.label+'',
       seed = encoding.astr2hstr(h.hash(message+w));// Should be random

   if(n-2*hs-2 < l){this.error_code = 1; return '' }
   for(i=0; i < n-2*hs-2-l; i++) pad += '00';
   DB = encoding.astr2hstr(h.hash(w)) + pad + '01' + m;

   // Mask
   pad = this.MGF(seed, n-hs-1);
   DB = BigInteger.toString(BigInteger.xor(BigInteger.create(DB),BigInteger.create(pad)));
   if(!!(DB.length&1)) DB = '0'+DB;

   // Final message
   sm = BigInteger.toString(BigInteger.xor(BigInteger.create(seed), BigInteger.create(this.MGF(DB, hs))));
   DB = BigInteger.toString(BigInteger.expMod(BigInteger.create(sm+DB), E, N));
   if(!!(DB.length&1)) DB = '0'+DB;

   this.error_code = 0;
   return DB;
  },

/** RSADP/RSASP1 - Computes m^d mod n using CRT coefficients.
  * @private
  * @param {string} message Hex-encoded message
  * @param {privateKey} priv Private key object
  * @returns {string} Hex string representing m^d mod n
  */
  _private: function(message, priv)
  {
   var C = BigInteger.create(message), dP = BigInteger.create(priv.dmp1),
       dQ = BigInteger.create(priv.dmq1), P = BigInteger.create(priv.p),
       Q = BigInteger.create(priv.q), qInv = BigInteger.create(priv.iqmp),
       M = BigInteger.create("0");

   // CRT decryption
   dP = BigInteger.expMod(C,dP,P); // m1 = c ^ dP mod p
   dQ = BigInteger.expMod(C,dQ,Q);// m2 = c ^ dQ mod q
   BigInteger.subTo(dP, dQ, M);
   BigInteger.multiplyTo(M, qInv, C);
   BigInteger.multiplyTo(Q, BigInteger.mod(C,P), M); // h = qInv * (m1 - m2) mod p
   BigInteger.subTo(dQ, BigInteger.negate(M), C); // m = m2 + h * q
   return BigInteger.toString(C);
  },

/** RSAES-OAEP-DECRYPT decryption.
  * @param {string} message Hex string containing the encrypted data
  * @param {privateKey} priv Private Key
  * @returns {string} ASCII string representing the original message, or an empty string if decryption failed.
  */
  decrypt: function(message, priv)
  {
   var m = message+'', l = m.length>>1,
       n = BigInteger.bitLength(BigInteger.create(priv.n+''))>>3,
       f = false, DB = '', sm = '', pad = '', i = 0,
       h = this.encryption_hash, hs = h.size;

   if(n != l){ this.error_code = 2; return "" }
   DB = this._private(m,priv);
   for(i = (n<<1)-DB.length; i>0; i--) DB = '0'+DB;

   // Parsing and unmasking
   for(i=0; i < DB.length; i++)
   {
    if(i<2){ if(DB[i] != '0'){ this.error_code = 3; return ''}}
    else if(i < 2*(hs+1)) sm += DB[i];
    else pad += DB[i];
   }

   DB = this.MGF(pad, hs);
   sm = BigInteger.toString(BigInteger.xor(BigInteger.create(sm), BigInteger.create(DB)));
   DB = this.MGF(sm, n-hs-1);
   DB = BigInteger.toString(BigInteger.xor(BigInteger.create(pad),BigInteger.create(DB)));
   if(!!(DB.length&1)) DB='0'+DB;

   // Unpadding
   m = ''; f = false; sm = '';
   for(i=0; i < DB.length; i++)
   {
    if(i < 2*hs){sm += DB[i]; continue;}
    pad = DB[i];
    if(f) m += pad;
    else
    {
     if(pad == "1"){ if(!(i&1)) break; else f = true; }
     else if(pad != "0") break;
    }
   }
   if(!sm){this.error_code = 4; return "" }
   if(sm != encoding.astr2hstr(h.hash(this.label))){ this.error_code = 5; return "" }

   this.error_code = 0;
   return encoding.hstr2astr(m);
  },

/** RSASSA-PSS-SIGN signature using rsa.signature_hash.
  * @param {string} message ASCII string containing the data to sign
  * @param {privateKey} priv Private Key
  * @returns {string} Hex string representing a PSS signature for the data
  */
  sign: function(message, priv)
  {
   var h = this.signature_hash, m = h.hash(message+''),
       DB = '', sm = '', pad = '', salt = this.salt+'',
       sl = salt.length, i = 0, hs = h.size,
       n = BigInteger.bitLength(BigInteger.create(priv.n+''))>>3;

   if(n-hs-2 < sl){this.error_code = 6; return ""}
   m = encoding.astr2hstr(h.hash("\x00\x00\x00\x00\x00\x00\x00\x00"+m+salt));
   sm = "01"+encoding.astr2hstr(salt);
   for(i = sm.length>>1; i < n-sl-hs-2; i++) pad+="00";
   DB = this.MGF(m, n-hs-1);

   // Most significant bit - PSS could be using a byte like OAEP...
   sm = (+('0x'+(0<DB.length?DB[0]:"0"))>>3==0?"00":"80") + pad + sm;
   DB = BigInteger.toString(BigInteger.xor(BigInteger.create(DB), BigInteger.create(sm)));
   DB += m+'bc';

   DB = this._private(DB, priv);
   if(!!(DB.length&1)) DB='0'+DB;
   this.error_code = 0;
   return DB;
  },

/** EMSA-PKCS1-v1_5-ENCODE
  * @private
  */
  _pkcs1_sig_pad: function(m, n)
  {
   var h = this.signature_hash, m = h.hash(m+''),
       res = '', pad = '', i = 0;

   // DER octet string of hash
   m = "04"+encoding.b2h(h.size)+encoding.astr2hstr(m);
   res = h.identifier + '';
   res = '06'+encoding.b2h(res.length>>1)+res+'0500';
   res = '30'+encoding.b2h(res.length>>1)+res+m;
   res = '0030'+encoding.b2h(res.length>>1)+res;
   for(i=res.length>>1; i < n-2; i++) pad += "ff";
   return '0001'+pad+res;
  },

/** RSASSA-PKCS1-V1_5-SIGN signature using rsa.signature_hash.
  * @param {string} message ASCII string containing the data to sign
  * @param {privateKey} priv Private Key
  * @returns {string} Hex string representing a PKCS1v1.5 signature for the data
  */
  sign_pkcs1_v1_5: function(message, priv)
  {
   var res = '',
       n = BigInteger.bitLength(BigInteger.create(priv.n+''))>>3;

   res = this._private(this._pkcs1_sig_pad(message, n), priv);
   if(!!(res.length&1)) res = '0'+res;

   this.error_code = 0;
   return res;
  },

/** RSASSA-PSS-VERIFY signature verification using rsa.signature_hash.
  * @param {string} data ASCII string containing the signed data
  * @param {string} signature Hex string containing the signature of the data
  * @param {publicKey} pub Public key of the expected sender
  * @returns {boolean} whether s is a valid signature for m from pub
  */
  verify: function(data, signature, pub)
  {
   var h = this.signature_hash, hs = h.size,
       m = h.hash(data+''), s = signature+'',
       N = BigInteger.create(pub.n+''), k = s.length>>1,
       E = BigInteger.create(pub.e+''), n = BigInteger.bitLength(N)>>3,
       i = 0, DB = '', sm = '', pad = '', f = false;

   if(k != n){this.error_code = 2; return false }
   s = BigInteger.toString(BigInteger.expMod(BigInteger.create(s), E, N));

   while(s.length != 2*n) s='0'+s;
   if(+(0<s.length?s[0]:'0')>>3 != 0){this.error_code = 3; return false }

   for(i=0; i<s.length; i++)
   {
    if(i < 2*(n-hs-1)) DB += s[i];
    else if(i < 2*(n-1)) sm += s[i];
    else pad += s[i];
   }

   if(pad != "bc"){ this.error_code = 7; return false }
   s = sm; sm = this.MGF(sm, n-hs-1);

   DB = BigInteger.toString(BigInteger.xor(BigInteger.create(DB), BigInteger.create(sm)));
   if(!!(DB.length&1)) DB='0'+DB;

   sm = "";
   for(i=0; i < DB.length; i++)
   {
    pad = DB[i];
    if(!i){ if(pad != "0" && pad != "8") return false; }
    else if(f) sm += pad;
    else
    {
     if(pad == "1" && !!(i&1)){f = true; continue;}
     if(pad != "0"){ this.error_code = 4; return false }
    }
   }

   sm = encoding.hstr2astr(sm);
   this.error_code = 0;
   return encoding.astr2hstr(h.hash("\x00\x00\x00\x00\x00\x00\x00\x00"+m+sm)) == s;
  },

/** RSASSA-PKCS1-V1_5-VERIFY signature verification using rsa.signature_hash.
  * @param {string} data ASCII string containing the signed data
  * @param {string} signature Hex string containing the signature of the data
  * @param {publicKey} pub Public key of the expected sender
  * @returns {boolean} whether s is a valid signature for m from pub
  */
  verify_pkcs1_v1_5: function(data, signature, pub)
  {
   var N = BigInteger.create(pub.n+''), E = BigInteger.create(pub.e+''),
       s = signature+'', k = s.length >> 1, n = BigInteger.bitLength(N)>>3,
       res = this._pkcs1_sig_pad(data, n);

   if(k != n){this.error_code = 2; return false }
   s = BigInteger.toString(BigInteger.expMod(BigInteger.create(s), E, N));
   while(s.length != 2*n) s='0'+s;
   return s == res;
  },

/** MGF1 message generating function. Underlying hash function is rsa.mgf_hash
  * @param {string} seed Hex string containing the seed for message generation
  * @param {number} length Length n of the requested message in bytes
  * @returns {string} Hex string of the desired length
  */
  MGF: function(seed, length)
  {
   var res = '', c = '', i = 0, j = 0, h = this.mgf_hash,
       len = length<<1, hs = h.size,
       n = (length/hs |0) + (!(length%hs) ? 0 :1);

   for(i=0; i<n; i++)
   {
    for(c = '', j = 0; j < 4; j++)
     c += encoding.b2h((i>>(24-8*j))&255);

    c = encoding.astr2hstr(h.hash(encoding.hstr2astr(seed+c)));
    for(j=0; j < c.length; j++)
    {
     res += c[j];
     if(res.length == len) return res;
    }
   }
   return res;
  }
 };

