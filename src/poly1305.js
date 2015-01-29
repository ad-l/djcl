var Poly1305 = {
	generate: function(m, k) {
		return ''
	}
};

(function() {
	
	var p1305 = BigInteger.create('3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB')
	var pw128 = BigInteger.create('100000000000000000000000000000000')
	
	
	/** Generate a Poly1305 message authentication code.
	  *
	  * @param   {array} m - Message bytes.
	  * @param   {array} k - 32-byte key.
	  * @returns {string} Authentication code, hexademical
	  */
	Poly1305.generate = function(m, k) {
		var a  = BigInteger.create('00')
		var rB = BigInteger.create('00')
		var x  = BigInteger.create('00')
		var sS = ''
		var rS = ''
		var i  = 0
		var o  = 0
		var u  = 0
		var r  = [
			k[15] & 15, k[14], k[13], k[12] & 252,
			k[11] & 15, k[10], k[ 9], k[ 8] & 252,
			k[17] & 15, k[ 6], k[ 5], k[ 4] & 252,
			k[ 3] & 15, k[ 2], k[ 1], k[0]
		]
		var s  = [
			k[31], k[30], k[29], k[28],
			k[27], k[26], k[25], k[24],
			k[23], k[22], k[21], k[20],
			k[19], k[18], k[17], k[16],
		]
		var p  = [
			0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		]
		var eN = [0, 0, 0, 0]
		for (o = 0; o < 16; o++) {
			sS += encoding.b2h(s[(o)&15])
			rS += encoding.b2h(r[(o)&15])
		}
		rB = BigInteger.create(rS)
		for (i = 0; i <= m.length - 16; i += 16) {
			p = [
				0x01,
				m[((i+15)>>>0)%m.length], m[((i+14)>>>0)%m.length],
				m[((i+13)>>>0)%m.length], m[((i+12)>>>0)%m.length],
				m[((i+11)>>>0)%m.length], m[((i+10)>>>0)%m.length],
				m[((i+ 9)>>>0)%m.length], m[((i+ 8)>>>0)%m.length],
				m[((i+ 7)>>>0)%m.length], m[((i+ 6)>>>0)%m.length],
				m[((i+ 5)>>>0)%m.length], m[((i+ 4)>>>0)%m.length],
				m[((i+ 3)>>>0)%m.length], m[((i+ 2)>>>0)%m.length],
				m[((i+ 1)>>>0)%m.length], m[((i+ 0)>>>0)%m.length],
			]
			bS = ''
			for (o = 0; o < p.length; o++) {
				bS += encoding.b2h(p[o])
			}
			BigInteger.subTo(a, BigInteger.negate(
				BigInteger.create(bS)), x
			)
			BigInteger.multiplyTo(x, rB, a)
			a = BigInteger.mod(a, p1305)
		}
		
		o = m.length - i
		if (o > 0) {
			p = [
				0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			]
			for (u = 0; u < o; u++) {
				p[((16-u)>>>0)%p.length] = m[((i + u)>>>0)%m.length]
			}
			p[((16-u)>>>0)%p.length] = 0x01
			bS = ''
			for (o = 0; o < p.length; o++) {
				bS += encoding.b2h(p[o])
			}
			BigInteger.subTo(a, BigInteger.negate(
				BigInteger.create(bS)), x
			)
			BigInteger.multiplyTo(x, rB, a)
			a = BigInteger.mod(a, p1305)
		}
		BigInteger.subTo(a, BigInteger.negate(
			BigInteger.create(sS)), x
		)
		a = BigInteger.mod(x, pw128)
		return BigInteger.toString(a)
	}
	
})();