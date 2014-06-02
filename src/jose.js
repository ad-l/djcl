var JWT =
{
 algorithm: "HS256",
 algos: ["HS256","RS256"],

 algfun: [
  {
   sign: function(si,k)
   {
    hashing.hmac_hash = hashing.sha256;
    return encoding.base64_urlencode(
     encoding.hstr2astr(hashing.HMAC(k, si))
    );
   },
   verify: function(si,k,h)
   {
    return this.sign(si,k)==h;
   }
  }, {
   sign: function(s,k)
   {
    rsa.signature_hash = hashing.sha256;
    return encoding.base64_urlencode(
     encoding.hstr2astr(rsa.sign_pkcs1_v1_5(s,k))
    );
   },
   verify: function(si,k,h)
   {
    this.sign;
    return rsa.verify_pkcs1_v1_5(si,
     encoding.astr2hstr(encoding.base64_decode(h)), k);
   }
  }
 ],

 create: function(pt, key)
 {
  var algs =  this.algos, af= this.algfun, ai = 0,
      hdr = "", res = "", alg = "";

  for(ai=0; ai < algs.length; ai++)
   if(algs[ai] == this.algorithm) break;

  alg = algs[(ai>>>0)%algs.length];
  res = encoding.base64_urlencode('{"typ":"JWT","alg":"'+alg+'"}');

  res += '.'+encoding.base64_urlencode(encoding.utf8_decode(pt));
  res += '.'+af[(ai>>>0)%af.length].sign(res, key);
  return res;
 },

 parse: function(s, key)
 {
  var s=s+"", off = 0, c = "", hd = "", cs = "", sig = "",
      header = {typ:"", alg:""}, ai = 0, algs = this.algos,
      af = this.algfun, r = {valid:false, header:"", claims:""};

  for(off=0; off < s.length; off++)
  {
   if((c = s[off])==".") ai++;
   else if(!ai) hd += c;
   else if(ai==1) cs += c;
   else sig += c;
  }

  r.header = encoding.utf8_encode(encoding.base64_decode(hd));
  r.claims = encoding.utf8_encode(encoding.base64_decode(cs));

  if(!DJSON.parse(r.header, header, {type: "object", props:[
   {name: "typ", value: {type: "string", props:[]}},
   {name: "alg", value: {type: "string", props:[]}}
  ]})) return r;

  if(header.typ != "JWT") return r;

  for(ai=0; ai < algs.length; ai++)
   if(algs[ai] == header.alg) break;

  if(ai >= this.algos.length) return r;
  r.valid = af[(ai>>>0)%af.length].verify(hd+"."+cs, key, sig);
  return r;
 }
};

var JWE = 
{
 error_code: 0,
 supportedAlgorithm: {"alg":"A256CBC", "enc":"A256CBC+HS256"},

 encryptData: function(data, key, IV)
 {
  aes.setKey(encoding.utf8_decode(key));
  return aes.CBC(encoding.utf8_decode(data), encoding.utf8_decode(IV), 0);
 },

 decryptData: function(cipher, key, IV)
 {
  aes.setKey(encoding.utf8_decode(key));
  return encoding.utf8_encode(aes.CBC(cipher, encoding.utf8_decode(IV), 1));
 },

 validateHeader: function(header)
 {
  return (header.alg == this.supportedAlgorithm.alg && header.enc == this.supportedAlgorithm.enc)
 },

 concatKeyDerivation: function(CMK, header)
 {
  var round = "\x00\x00\x00\x01";
  var cekLabel = "Encryption";
  var cekOutputSize = "\x00\x00\x01\x00";
  var cek = hashing.SHA256(encoding.astr2hstr(round+CMK+cekOutputSize+header.enc+cekLabel));
  var cikLabel = "Integrity";
  var cikOutputSize = "\x00\x00\x01\x00";
  var cik = hashing.SHA256(encoding.astr2hstr(round+CMK+cikOutputSize+header.enc+cikLabel));
  return {'CEK':cek, 'CIK':cik};
 },

 sign: function(input, CIK)
 {
  var m = hashing.HMAC(encoding.utf8_decode(CIK), encoding.utf8_decode(input));
  return m;
 },

 create: function(header, data, IV, CMK, secret)
 {
  var encodedHeader = encoding.base64_urlencode(encoding.astr2hstr(JSON.stringify(header)));
  var encodedIV = encoding.base64_urlencode(encoding.astr2hstr(IV));
  var encryptedCMK = encoding.base64_urlencode(this.encryptData(CMK, secret, IV));
  var derivedKeys = this.concatKeyDerivation(CMK, header);
  var cipherText = encoding.base64_urlencode(this.encryptData(data, derivedKeys.CEK, IV));
  var secureInput = encodedHeader + "." + encryptedCMK + "." + encodedIV + "." + cipherText;
  var integrity = encoding.base64_urlencode(this.sign(secureInput, derivedKeys.CIK));

  if(!this.validateHeader(header)) { this.error_code = 1; return ""; }
  return secureInput + "." + integrity;
 },

 parse: function(input, secret)
 {
  var parts = function(s)
  {
   var res = ["","","","","","","",""], i = 0, j = 0, c="";
   for(i=0; i<s.length; i++)
   {
    c = s[i];
    if(c == "."){ j++; continue; }
    res[j&7] += c;
   }
   res[5] = ""+j;
   return res;
  }(input);

  var header = JSON.parse(encoding.hstr2astr(encoding.base64_decode(parts[0])));
  var encCMK = encoding.base64_decode(parts[1]);
  var IV = encoding.hstr2astr(encoding.base64_decode(parts[2]));

  var cipher = encoding.base64_decode(parts[3]);
  var sign = parts[4];

  var CMK = this.decryptData(encCMK, secret, IV);
  var derivedKeys = this.concatKeyDerivation(CMK, header);

  var secureInput = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3];
  var integrity = encoding.base64_urlencode(this.sign(secureInput, derivedKeys.CIK));

  if(!this.validateHeader(header)){ this.error_code = 1; return ""; }
  if(integrity != sign){ this.error_code = 2; return ""; }
  return this.decryptData(cipher, derivedKeys.CEK, IV);
 }
}

