var Curve25519 = {
	scalarMult: function(scalar, base) {
		return {
			array: [
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
			],
			s: 0,
			t: 0
		}
	}
};

(function() {

	var p25519 = BigInteger.create(
		'7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed'
	)
	var p25519Minus2 = BigInteger.create(
		'7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb'
	)
	var a = BigInteger.create('076d06')
	var two = BigInteger.create('02')
	var four = BigInteger.create('04')

	// groupAdd adds two elements of the elliptic curve group in Montgomery form.
	var groupAdd = function(x1, xn, zn, xm, zm) {
		var xx   = BigInteger.create('0')
		var zz   = BigInteger.create('0')
		var d    = BigInteger.create('0')
		var sq   = BigInteger.create('0')
		var outx = BigInteger.create('0')
		var xz   = BigInteger.create('0')
		var zx   = BigInteger.create('0')
		var sq2  = BigInteger.create('0')
		var outz = BigInteger.create('0')
		// x₃ = 4(x·x′ - z·z′)² · z1
		BigInteger.multiplyTo(xn, xm, xx)
		xx = BigInteger.mod(xx, p25519)
		BigInteger.multiplyTo(zn, zm, zz)
		zz = BigInteger.mod(zz, p25519)
		if (BigInteger.compareTo(xx, zz) > 0) {
			BigInteger.subTo(xx, zz, d)
		}
		else {
			BigInteger.subTo(zz, xx, d)
		}
		sq = BigInteger.expMod(d, two, p25519)
		BigInteger.multiplyTo(sq, four, outx)
		outx = BigInteger.mod(outx, p25519)
		// z₃ = 4(x·z′ - z·x′)² · x1
		BigInteger.multiplyTo(xm, zn, xz)
		xz = BigInteger.mod(xz, p25519)
		BigInteger.multiplyTo(zm, xn, zx)
		zx = BigInteger.mod(zx, p25519)
		if (BigInteger.compareTo(xz, zx) > 0) {
			BigInteger.subTo(xz, zx, d)
		}
		else {
			BigInteger.subTo(zx, xz, d)
		}
		sq = BigInteger.expMod(d, two, p25519)
		BigInteger.multiplyTo(sq, x1, sq2)
		sq2 = BigInteger.mod(sq2, p25519)
		BigInteger.multiplyTo(sq2, four, outz)
		outz = BigInteger.mod(outz, p25519)
		return [outx, outz]
	}

	// groupDouble doubles a point in the elliptic curve group.
	var groupDouble = function(x, z) {
		var xx     = BigInteger.create('0')
		var zz     = BigInteger.create('0')
		var d      = BigInteger.create('0')
		var outx   = BigInteger.create('0')
		var s      = BigInteger.create('0')
		var xz     = BigInteger.create('0')
		var axz    = BigInteger.create('0')
		var fourxz = BigInteger.create('0')
		var outz   = BigInteger.create('0')
		// x₂ = (x² - z²)²
		xx = BigInteger.expMod(x, two, p25519)
		zz = BigInteger.expMod(z, two, p25519)
		if (BigInteger.compareTo(xx, zz) > 0) {
			BigInteger.subTo(xx, zz, d)
		}
		else {
			BigInteger.subTo(zz, xx, d)
		}
		outx = BigInteger.expMod(d, two, p25519)
		// z₂ = 4xz·(x² + Axz + z²)
		BigInteger.subTo(xx, BigInteger.negate(zz), s)
		BigInteger.multiplyTo(x, z, xz)
		xz = BigInteger.mod(xz, p25519)
		BigInteger.multiplyTo(xz, a, axz)
		BigInteger.subTo(s, BigInteger.negate(axz), s)
		BigInteger.multiplyTo(xz, four, fourxz)
		BigInteger.multiplyTo(fourxz, s, outz)
		outz = BigInteger.mod(outz, p25519)
		return [outx, outz]
	}

	/** scalarMult calculates i*base in the elliptic curve.
	  * We can use it in order to generate a public key value,
	  * or to perform key agreement.
	  *
	  * In order to generate a public key:
	  * priv = 256-bit random hexadecimal string
	  * base = '09'
	  * pub  = Curve25519.scalarMult(priv, base)
	  * 
	  * In order to perform key agreement:
	  * shared = scalarMult(myPriv, theirPub)
	  *
	  * @param   {string} scalar - Private key, hexadecimal string
	  * @param   {string} base - Base point (or public key), hexadecimal string
	  * @returns {string} Public key or shared secret, hexadecimal string
	  */
	Curve25519.scalarMult = function(scalar, base) {
		var x1    = BigInteger.create('0')
		var z1    = BigInteger.create('0')
		var x2    = BigInteger.create('0')
		var z2    = BigInteger.create('0')
		var point = [BigInteger.create('0'), BigInteger.create('0')]
		var i     = 253
		var zlinv = BigInteger.create('0')
		var x     = BigInteger.create('0')
		scalar    = BigInteger.create(scalar)
		base      = BigInteger.create(base)
		x1 = BigInteger.create('01')
		z1 = BigInteger.create('00')
		x2 = base
		z2 = BigInteger.create('01')
		// Highest bit is one
		point = groupAdd(base, x1, z1, x2, z2)
		x1 = point[0]
		z1 = point[1]
		point = groupDouble(x2, z2)
		x2 = point[0]
		z2 = point[1]
		for (i = 253; i >= 3; i--) {
			if (BigInteger.getBit(scalar, i) === 1) {
				point = groupAdd(base, x1, z1, x2, z2)
				x1 = point[0]
				z1 = point[1]
				point = groupDouble(x2, z2)
				x2 = point[0]
				z2 = point[1]
			}
			else {
				point = groupAdd(base, x1, z1, x2, z2)
				x2 = point[0]
				z2 = point[1]
				point = groupDouble(x1, z1)
				x1 = point[0]
				z1 = point[1]
			}
		}
		// Lowest 3 bits are zero
		for (i = 2; i >= 0; i--) {
			point = groupDouble(x1, z1)
			x1 = point[0]
			z1 = point[1]
		}
		zlinv = BigInteger.expMod(z1, p25519Minus2, p25519)
		BigInteger.multiplyTo(zlinv, x1, x)
		x = BigInteger.mod(x, p25519)
		return BigInteger.toString(x)
	}

})();