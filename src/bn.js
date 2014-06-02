/* (original disclaimer from JSBN, on which this file is based)
 *
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */

/**
 * High-precision arithmetic
 * @author Tom Wu (original author of JSBN)
 * @author Antoine Delignat-Lavaud
 * @description
 * <p>Minimal set of high precision arithmetic operations
 * for RSA encryption and decryption.</p>
 * <p>To preserve both defensiveness and performance, this
 * is not an arbitrary precision library! Each number is
 * represented by a constant length array of 256 elements.
 * Because of tagging optimizations, each number stores 28
 * bits, hence the maximal precision is 7168 bits. 128 was
 * not chosen to allow RSA on a 2048 bit modulus, and it is
 * highly preferred to use a power of 2 to use the short
 * dynamic accessor notation.</p>
 * @requires encoding
 * @namespace
 */
 var BigInteger =
 {
  BI_DB: 28,
  BI_DM: 268435455,
  BI_DV: 268435456,
  BI_FP: 52,
  BI_FV: 4503599627370496,
  BI_F1: 24,
  BI_F2: 4,

/** Create a new BigInteger initialized from the given hex value.
  * @param {string} v Hex representation of initial value in a string.
  * @returns {BigInteger} A BigInteger structure.
  */
  create: function(v)
  {
   var neg = false, p = '', b = '', s = v+'', i = s.length, j = 0, a =
   [ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ],
       res = {array:a, t:0, s:0};

   while(--i >= 0)
   {
    b = (i>>>=0)<s.length?s[i]:"0";
    if(i==0 && b=='-'){neg = true; continue;}
    p = b + p;
    if(j++%7==6)
    {
     a[res.t++&255] = +('0x'+p); p = '';
    }
   }
   if(!!p) a[res.t++&255] = +('0x'+p); p = '';

   if(neg) res = this.negate(res);
   this.clamp(res);
   return res;
  },

  am: function(th,i,x,w,j,c,n)
  {
   var a = th.array, b = w.array, l = 0, m = 0,
      xl = x&0x3fff, xh = x>>14, h = 0;

   while(--n >= 0)
   {
    l = a[i&255]&0x3fff;i
    h = a[i++&255]>>14;
    m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+b[j&255]+c;
    c = (l>>28)+(m>>14)+xh*h;
    b[j++&255] = l&0xfffffff;
   }

   return c;
  },

/** Copy the value of a BigInteger to another.
  * @param {BigInteger} source Integer to copy.
  * @param {BigInteger} target Target of copy.
  * @returns {BigInteger} Returns the target of the copy.
  */
  copyTo: function(th, r)
  {
   var ta = th.array, ra = r.array, i = 0;

   for(i = th.t-1; i >= 0; --i)
    ra[i&255] = ta[i&255];

   r.t = th.t; r.s = th.s;
   return r;
  },

  clamp: function(th)
  {
   var a = th.array, c = th.s & this.BI_DM;
   while(th.t > 0 && a[(th.t-1)&255] == c) --th.t;
  },

/** Convert BigInteger to its hex representation.
  * @param {BigInteger} n Number to convert
  * @returns {string} Hex representation of n, as a string.
  */
  toString: function(th)
  {
   var a = th.array, c = 0, i = 0, j = 0,
       hex = encoding.hex, k = 0,
       nz = false, h = '', res = '';

   if(th.s < 0)
    return "-"+this.toString(this.negate(th));

   for(i=th.t-1; i>=0; i--)
   {
    c = a[i&255];
    for(j=24; j>=0; j-=4)
    {
     k = (c>>j) & 15;
     h = (k>>>=0)<hex.length?hex[k]:"0";
     if(h != '0') nz = true;
     if(nz) res += h;
    }
   }

   return !res ? '0' : res;
  },

/** Change sign of number.
  * @param {BigInteger} n Input number
  * @returns {BigInteger} A newly allocated BigInteger with opposite value
  */
  negate: function(th)
  {
   var t = this.create('0'), z = this.create('0');
   this.subTo(z, th, t);
   return t;
  },

/** Absolute value.
  * @param {BigInteger} n Input number
  * @returns {BigInteger} If n is positive, returns n, otherwise return negate(n)
  */
  abs: function(th)
  {
   return th.s<0 ? this.negate(th) : th;
  },

/** Exclusive OR of two numbers
  * @param {BigInteger} n First operand
  * @param {BigInteger} m Second operand
  * @returns {BigInteger} n xor m
  */
  xor: function(th, a)
  {
   var x = th.array, y = a.array,
       r = this.create('0'), z = r.array,
       i = (th.t > a.t) ? th.t : a.t;
   r.t = i;
   while(--i >= 0) z[i&255] = x[i&255]^y[i&255];
   return r;
  },

/** Comparison of BigInteger.
  * @param {BigInteger} n First value
  * @param {BigInteger} m Second value
  * @returns {number} A negative value if n<m, 0 if n=m and a positive value otherwise.
  */
  compareTo: function(th,a)
  {
   var x = th.array, y = a.array, i = th.t,
       r = th.s-a.s, s = th.t-a.t;

   if(!!r) return r; if(!!s) return s;
   while(--i >= 0)
    if((r = (x[i&255]-y[i&255]))!=0) return r;
   return 0;
  },

/** Index of the first non-zero bit starting from the least significant bit.
  * @param {number} n  Input number
  * @returns {number} the bit length of n. Can behave strangely on negative and float values.
  */
  nbits: function(x)
  {
   var r = 1, t = 0;
   if((t=x>>>16) != 0) { x = t; r += 16; }
   if((t=x>>8) != 0) { x = t; r += 8; }
   if((t=x>>4) != 0) { x = t; r += 4; }
   if((t=x>>2) != 0) { x = t; r += 2; }
   if((t=x>>1) != 0) { x = t; r += 1; }
   return r;
  },

/** Index of first non-zero bit starting from the LSB of the given BigInteger.
  * @param {BigInteger} n Input BigInteger
  * @returns {number} the bit length of n.
  */
  bitLength: function(th)
  {
   var a = th.array;
   if(th.t <= 0) return 0;
   return this.BI_DB*(th.t-1)+this.nbits(a[(th.t-1)&255]^(th.s&this.BI_DM));
  },

  DLshiftTo: function(th,n,r)
  {
   var a = th.array, b = r.array, i = 0;
   for(i = th.t-1; i >= 0; --i) b[(i+n)&255] = a[i&255];
   for(i = n-1; i >= 0; --i) b[i&255] = 0;
   r.t = th.t+n; r.s = th.s;
  },

  DRshiftTo: function(th,n,r)
  {
   var a = th.array, b = r.array, i = 0;
   for(i = n; i < th.t; ++i) b[(i-n)&255] = a[i&255];
   r.t = th.t>n?th.t-n:0; r.s = th.s;
  },

/** Logical shift to the left
  * @param {BigInteger} n Input number
  * @param {number} k Number of positions to shift
  * @param {BigInteger} r Target number to store the result to
  */
  LshiftTo: function(th,n,r)
  {
   var a = th.array, b = r.array,
      bs = n%this.BI_DB, cbs = this.BI_DB-bs,
      bm = (1<<cbs)-1,  ds = (n/this.BI_DB)|0,
       c = (th.s<<bs)&this.BI_DM, i = 0;

   for(i = th.t-1; i >= 0; --i)
    b[(i+ds+1)&255] = (a[i&255]>>cbs)|c, c = (a[i&255]&bm)<<bs;
   for(i = ds-1; i >= 0; --i) b[i&255] = 0;

   b[ds&255] = c; r.t = th.t+ds+1;
   r.s = th.s; this.clamp(r);
  },

/** Logical shift to the right.
  * @param {BigInteger} n Input number
  * @param {number} k Number of positions to shift
  * @param {BigInteger} r Target number to store the result to
  */
  RshiftTo: function(th,n,r)
  {
   var a = th.array, b = r.array, i = 0,
      bs = n%this.BI_DB, cbs = this.BI_DB-bs,
      bm = (1<<bs)-1,  ds = (n/this.BI_DB)|0;

   r.s = th.s;
   if(ds >= th.t) { r.t = 0; return; }
   b[0] = a[ds&255]>>bs;

   for(i = ds+1; i < th.t; ++i)
    b[(i-ds-1)&255] |= (a[i&255]&bm)<<cbs,
    b[(i-ds)&255] = a[i&255]>>bs;
   if(bs > 0) b[(th.t-ds-1)&255] |= (th.s&bm)<<cbs;

   r.t = th.t-ds; this.clamp(r);
  },

/** Subtraction of BigIntegers.
  * @param {BigInteger} n First operand
  * @param {BigInteger} m Second operand
  * @param {BigInteger} r Target number to store the result (n-m) to.
  */
  subTo: function(th, y, r)
  {
   var a = th.array, z = r.array, b = y.array,
       i = 0, c = 0, m = y.t<th.t?y.t:th.t;

   while(i < m)
   {
    c += a[i&255]-b[i&255];
    z[i++&255] = c&this.BI_DM;
    c >>= this.BI_DB;
   }

   if(y.t < th.t)
   {
    c -= y.s;
    while(i < th.t)
    {
     c += a[i&255];
     z[i++&255] = c&this.BI_DM;
     c >>= this.BI_DB;
    }
    c += th.s;
   }
   else
   {
    c += th.s;
    while(i < y.t)
    {
     c -= b[i&255];
     z[i++&255] = c&this.BI_DM;
     c >>= this.BI_DB;
    }
    c -= y.s;
   }

   r.s = (c<0)?-1:0;
   if(c < -1) z[i++&255] = this.BI_DV+c;
   else if(c > 0) z[i++&255] = c;
   r.t = i; this.clamp(r);
  },

/** Multiplication of BigIntegers.
  * @param {BigInteger} n First operand
  * @param {BigInteger} m Second operand
  * @param {BigInteger} r Target number to store the result (n*m) to.
  */
  multiplyTo: function(th,a,r)
  {
   var u = th.array, v = r.array,
       x = this.abs(th), y = this.abs(a),
       w = y.array, i = x.t;

   r.t = i+y.t;
   while(--i >= 0) v[i&255] = 0;
   for(i = 0; i < y.t; ++i)
    v[(i+x.t)&255] = this.am(x,0,w[i&255],r,i,0,x.t);

   r.s = 0; this.clamp(r);
   if(th.s != a.s) this.subTo(this.create('0'),r,r);
  },

/** Squaring of a BigInteger.
  * @param {BigInteger} n First operand
  * @param {BigInteger} r Target number to store the result (n*n) to.
  */
  squareTo: function(th, r)
  {
   var x = this.abs(th), u = x.array, v = r.array,
       i = (r.t = 2*x.t), c = 0;

   while(--i >= 0) v[i&255] = 0;
   for(i = 0; i < x.t-1; ++i)
   {
    c = this.am(x,i,u[i&255],r,2*i,0,1);
    if((v[(i+x.t)&255] += this.am(x,i+1,2*u[i&255],r,2*i+1,c,x.t-i-1)) >= this.BI_DV)
     v[(i+x.t)&255] -= this.BI_DV, v[(i+x.t+1)&255] = 1;
   }

   if(r.t > 0) v[(r.t-1)&255] += this.am(x,i,u[i&255],r,2*i,0,1);
   r.s = 0; this.clamp(r);
  },

/** Euclidean division of two BigIntegers.
  * @param {BigInteger} n First operand
  * @param {BigInteger} m Second operand
  * @returns {BigInteger[]} Returns an array of two BigIntegers: first element is the quotient, second is the remainder.
  */
  divRem: function(th, div)
  {
   var m = this.abs(div), t = this.abs(th), ma = m.array, ta = th.array,
       ts = th.s, ms = m.s, nsh = this.BI_DB-this.nbits(ma[(m.t-1)&255]),
       q = this.create('0'), r = this.create('0'),
       qa = q.array, ra = r.array, qd = 0,
       y = this.create('0'), ya = y.array, ys = 0, y0 = 0,
       yt = 0, i = 0, j = 0, d1 = 0, d2 = 0, e = 0;

   if(t.t < m.t) this.copyTo(th,r);
   if(!m.t || t.t < m.t) return [q,r];

   if(nsh > 0){ this.LshiftTo(m,nsh,y); this.LshiftTo(t,nsh,r); }
   else{ this.copyTo(m,y); this.copyTo(m,r); }

   ys = y.t; y0 = ya[(ys-1)&255];
   if(y0 == 0) return [q,r];

   yt = y0*(1<<this.BI_F1)+((ys>1)?ya[(ys-2)&255]>>this.BI_F2:0);
   d1 = this.BI_FV/yt, d2 = (1<<this.BI_F1)/yt, e = 1<<this.BI_F2;
   i = r.t, j = i-ys;
   this.DLshiftTo(y,j,q);

   if(this.compareTo(r,q) >= 0)
   {
    ra[r.t++ & 255] = 1;
    this.subTo(r,q,r);
   }

   this.DLshiftTo(this.create('1'),ys,q);
   this.subTo(q,y,y);
   while(y.t < ys) ya[y.t++&255] = 0;

   while(--j >= 0)
   {
    qd = (ra[--i&255]==y0)?this.BI_DM:(ra[i&255]*d1+(ra[(i-1)&255]+e)*d2)|0;
    if((ra[i&255]+=this.am(y,0,qd,r,j,0,ys)) < qd)
    {
     this.DLshiftTo(y,j,q);
     this.subTo(r,q,r);
     while(ra[i&255] < --qd) this.subTo(r,q,r);
    }
   }

   this.DRshiftTo(r,ys,q);
   if(ts != ms) this.subTo(this.create('0'),q,q);
   r.t = ys; this.clamp(r);

   if(nsh > 0) this.RshiftTo(r,nsh,r);
   if(ts < 0) this.subTo(this.create('0'),r,r);
   return [q,r];
  },

/** Modular remainder of an integer division.
  * @param {BigInteger} n First operand
  * @param {BigInteger} m Second operand
  * @returns {BigInteger} n mod m
  */
  mod: function(th, a)
  {
   var r = this.divRem(this.abs(th),a)[1];
   if(th.s < 0 && this.compareTo(r,this.create('0')) > 0) this.subTo(a,r,r);
   return r;
  },

  invDigit: function(th)
  {
   var a = th.array, x = a[0], y = x&3;
   if(th.t < 1 || !(x&1)) return 0;
   y = (y*(2-(x&0xf)*y))&0xf;
   y = (y*(2-(x&0xff)*y))&0xff;
   y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;
   y = (y*(2-x*y%this.BI_DV))%this.BI_DV;
   return (y>0)?this.BI_DV-y:-y;
  },

/** Modular exponentiation using Montgomery reduction. 
  * @param {BigInteger} x Value to exponentiate
  * @param {BigInteger} e Exponent
  * @param {BigInteger} n Modulus - must be odd
  * @returns {BigInteger} x^e mod n
  */
  expMod: function(th, e, m)
  {
   var r = this.create('1'), r2 = this.create('0'), eb = e.array[(e.t-1)&255],
       g = this.Mconvert(th,m), i = this.bitLength(e)-1, j = 0, t = r;

   if(this.compareTo(e,r)<0) return r;
   this.copyTo(g,r);

   while(--i >= 0)
   {
    j = i%this.BI_DB;
    this.squareTo(r,r2); this.Mreduce(r2,m);
    if((eb&(1<<j)) != 0){ this.multiplyTo(r2,g,r); this.Mreduce(r,m); }
    else { t = r; r = r2; r2 = t; }
    if(!j) eb = e.array[(i/this.BI_DB-1)&255];
   }

   return this.Mrevert(r,m);
  },

  Mconvert: function(th, m)
  {
   var s = this.create('0'),
       r = (this.DLshiftTo(this.abs(th),m.t,s),this.divRem(s,m))[1];

   if(th.s < 0 && this.compareTo(r,this.create('0')) > 0) this.subTo(m,r,r);
   return r;
  },

  Mreduce: function(th, m)
  {
   var mp = this.invDigit(m), mpl = mp&0x7fff, mph = mp>>15, a = th.array,
       um = (1<<(this.BI_DB-15))-1, mt2 = 2*m.t, i = 0, j = 0, u0 = 0;

   while(th.t <= mt2) a[th.t++&255] = 0;
   for(i = 0; i < m.t; ++i)
   {
    j = a[i&255]&0x7fff;
    u0 = (j*mpl+(((j*mph+(a[i&255]>>15)*mpl)&um)<<15))&this.BI_DM;
    j = i+m.t;
    a[j&255] += this.am(m,0,u0,th,i,0,m.t);
    while(a[j&255] >= this.BI_DV) { a[j&255] -= this.BI_DV; a[++j&255]++; }
   }

   this.clamp(th); this.DRshiftTo(th, m.t, th);
   if(this.compareTo(th,m) >= 0) this.subTo(th,m,th);
   return th;
  },

  Mrevert: function(th, m)
  {
   var c = this.create('0');
   this.copyTo(th, c);
   return this.Mreduce(c,m);
  }
 };

