var Salsa20 = {
	getBlock: function(key, nonce, blockNumber) {
		return [
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0
		]
	}
}

var HSalsa20 = {
	getBlock: function(key, nonce) {
		return [
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0
		]
	}
}

var XSalsa20 = {
	getBlock: function(key, nonce, blockNumber) {
		return [
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0
		]
	}
};

(function() {
	var rounds = 20
	var sigmaWords = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
	
	var generateSalsa20Block = function(keyWords, nonceWords, counterWords) {
		var block = [
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0
		]
		var z0  = sigmaWords[0]
		var z1  = keyWords[0]
		var z2  = keyWords[1]
		var z3  = keyWords[2]
		var z4  = keyWords[3]
		var z5  = sigmaWords[1]
		var z6  = nonceWords[0]
		var z7  = nonceWords[1]
		var z8  = counterWords[0]
		var z9  = counterWords[1]
		var z10 = sigmaWords[2]
		var z11 = keyWords[4]
		var z12 = keyWords[5]
		var z13 = keyWords[6]
		var z14 = keyWords[7]
		var z15 = sigmaWords[3]
		var x0  = z0
		var x1  = z1
		var x2  = z2
		var x3  = z3
		var x4  = z4
		var x5  = z5
		var x6  = z6
		var x7  = z7
		var x8  = z8
		var x9  = z9
		var x10 = z10
		var x11 = z11
		var x12 = z12
		var x13 = z13
		var x14 = z14
		var x15 = z15
		var i   = 0
		var u   = 0
		for (i = 0; i < rounds; i += 2) {
			u = x0 + x12
			x4 ^= (u<<7)   | (u>>>(32-7))
			u = x4 + x0
			x8 ^= (u<<9)   | (u>>>(32-9))
			u = x8 + x4
			x12 ^= (u<<13) | (u>>>(32-13))
			u = x12 + x8
			x0 ^= (u<<18)  | (u>>>(32-18))
			u = x5 + x1
			x9 ^= (u<<7)   | (u>>>(32-7))
			u = x9 + x5
			x13 ^= (u<<9)  | (u>>>(32-9))
			u = x13 + x9
			x1 ^= (u<<13)  | (u>>>(32-13))
			u = x1 + x13
			x5 ^= (u<<18)  | (u>>>(32-18))
			u = x10 + x6
			x14 ^= (u<<7)  | (u>>>(32-7))
			u = x14 + x10
			x2 ^= (u<<9)   | (u>>>(32-9))
			u = x2 + x14
			x6 ^= (u<<13)  | (u>>>(32-13))
			u = x6 + x2
			x10 ^= (u<<18) | (u>>>(32-18))
			u = x15 + x11
			x3 ^= (u<<7)   | (u>>>(32-7))
			u = x3 + x15
			x7 ^= (u<<9)   | (u>>>(32-9))
			u = x7 + x3
			x11 ^= (u<<13) | (u>>>(32-13))
			u = x11 + x7
			x15 ^= (u<<18) | (u>>>(32-18))
			u = x0 + x3
			x1 ^= (u<<7)   | (u>>>(32-7))
			u = x1 + x0
			x2 ^= (u<<9)   | (u>>>(32-9))
			u = x2 + x1
			x3 ^= (u<<13)  | (u>>>(32-13))
			u = x3 + x2
			x0 ^= (u<<18)  | (u>>>(32-18))
			u = x5 + x4
			x6 ^= (u<<7)   | (u>>>(32-7))
			u = x6 + x5
			x7 ^= (u<<9)   | (u>>>(32-9))
			u = x7 + x6
			x4 ^= (u<<13)  | (u>>>(32-13))
			u = x4 + x7
			x5 ^= (u<<18)  | (u>>>(32-18))
			u = x10 + x9
			x11 ^= (u<<7)  | (u>>>(32-7))
			u = x11 + x10
			x8 ^= (u<<9)   | (u>>>(32-9))
			u = x8 + x11
			x9 ^= (u<<13)  | (u>>>(32-13))
			u = x9 + x8
			x10 ^= (u<<18) | (u>>>(32-18))
			u = x15 + x14
			x12 ^= (u<<7)  | (u>>>(32-7))
			u = x12 + x15
			x13 ^= (u<<9)  | (u>>>(32-9))
			u = x13 + x12
			x14 ^= (u<<13) | (u>>>(32-13))
			u = x14 + x13
			x15 ^= (u<<18) | (u>>>(32-18))
		}
		x0  += z0
		x1  += z1
		x2  += z2
		x3  += z3
		x4  += z4
		x5  += z5
		x6  += z6
		x7  += z7
		x8  += z8
		x9  += z9
		x10 += z10
		x11 += z11
		x12 += z12
		x13 += z13
		x14 += z14
		x15 += z15
		block[ 0] = ( x0 >>>  0) & 0xff
		block[ 1] = ( x0 >>>  8) & 0xff
		block[ 2] = ( x0 >>> 16) & 0xff
		block[ 3] = ( x0 >>> 24) & 0xff
		block[ 4] = ( x1 >>>  0) & 0xff
		block[ 5] = ( x1 >>>  8) & 0xff
		block[ 6] = ( x1 >>> 16) & 0xff
		block[ 7] = ( x1 >>> 24) & 0xff
		block[ 8] = ( x2 >>>  0) & 0xff
		block[ 9] = ( x2 >>>  8) & 0xff
		block[10] = ( x2 >>> 16) & 0xff
		block[11] = ( x2 >>> 24) & 0xff
		block[12] = ( x3 >>>  0) & 0xff
		block[13] = ( x3 >>>  8) & 0xff
		block[14] = ( x3 >>> 16) & 0xff
		block[15] = ( x3 >>> 24) & 0xff
		block[16] = ( x4 >>>  0) & 0xff
		block[17] = ( x4 >>>  8) & 0xff
		block[18] = ( x4 >>> 16) & 0xff
		block[19] = ( x4 >>> 24) & 0xff
		block[20] = ( x5 >>>  0) & 0xff
		block[21] = ( x5 >>>  8) & 0xff
		block[22] = ( x5 >>> 16) & 0xff
		block[23] = ( x5 >>> 24) & 0xff
		block[24] = ( x6 >>>  0) & 0xff
		block[25] = ( x6 >>>  8) & 0xff
		block[26] = ( x6 >>> 16) & 0xff
		block[27] = ( x6 >>> 24) & 0xff
		block[28] = ( x7 >>>  0) & 0xff
		block[29] = ( x7 >>>  8) & 0xff
		block[30] = ( x7 >>> 16) & 0xff
		block[31] = ( x7 >>> 24) & 0xff
		block[32] = ( x8 >>>  0) & 0xff
		block[33] = ( x8 >>>  8) & 0xff
		block[34] = ( x8 >>> 16) & 0xff
		block[35] = ( x8 >>> 24) & 0xff
		block[36] = ( x9 >>>  0) & 0xff
		block[37] = ( x9 >>>  8) & 0xff
		block[38] = ( x9 >>> 16) & 0xff
		block[39] = ( x9 >>> 24) & 0xff
		block[40] = (x10 >>>  0) & 0xff
		block[41] = (x10 >>>  8) & 0xff
		block[42] = (x10 >>> 16) & 0xff
		block[43] = (x10 >>> 24) & 0xff
		block[44] = (x11 >>>  0) & 0xff
		block[45] = (x11 >>>  8) & 0xff
		block[46] = (x11 >>> 16) & 0xff
		block[47] = (x11 >>> 24) & 0xff
		block[48] = (x12 >>>  0) & 0xff
		block[49] = (x12 >>>  8) & 0xff
		block[50] = (x12 >>> 16) & 0xff
		block[51] = (x12 >>> 24) & 0xff
		block[52] = (x13 >>>  0) & 0xff
		block[53] = (x13 >>>  8) & 0xff
		block[54] = (x13 >>> 16) & 0xff
		block[55] = (x13 >>> 24) & 0xff
		block[56] = (x14 >>>  0) & 0xff
		block[57] = (x14 >>>  8) & 0xff
		block[58] = (x14 >>> 16) & 0xff
		block[59] = (x14 >>> 24) & 0xff
		block[60] = (x15 >>>  0) & 0xff
		block[61] = (x15 >>>  8) & 0xff
		block[62] = (x15 >>> 16) & 0xff
		block[63] = (x15 >>> 24) & 0xff
		return block
	}
	
	var generateHSalsa20Block = function(keyWords, nonceWords) {
		var block = [
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0
		]
		var z0  = sigmaWords[0]
		var z1  = keyWords[0]
		var z2  = keyWords[1]
		var z3  = keyWords[2]
		var z4  = keyWords[3]
		var z5  = sigmaWords[1]
		var z6  = nonceWords[0]
		var z7  = nonceWords[1]
		var z8  = nonceWords[2]
		var z9  = nonceWords[3]
		var z10 = sigmaWords[2]
		var z11 = keyWords[4]
		var z12 = keyWords[5]
		var z13 = keyWords[6]
		var z14 = keyWords[7]
		var z15 = sigmaWords[3]
		var x0  = z0
		var x1  = z1
		var x2  = z2
		var x3  = z3
		var x4  = z4
		var x5  = z5
		var x6  = z6
		var x7  = z7
		var x8  = z8
		var x9  = z9
		var x10 = z10
		var x11 = z11
		var x12 = z12
		var x13 = z13
		var x14 = z14
		var x15 = z15
		var i   = 0
		var u   = 0
		for (i = 0; i < rounds; i += 2) {
			u = x0 + x12
			x4 ^= (u<<7)   | (u>>>(32-7))
			u = x4 + x0
			x8 ^= (u<<9)   | (u>>>(32-9))
			u = x8 + x4
			x12 ^= (u<<13) | (u>>>(32-13))
			u = x12 + x8
			x0 ^= (u<<18)  | (u>>>(32-18))
			u = x5 + x1
			x9 ^= (u<<7)   | (u>>>(32-7))
			u = x9 + x5
			x13 ^= (u<<9)  | (u>>>(32-9))
			u = x13 + x9
			x1 ^= (u<<13)  | (u>>>(32-13))
			u = x1 + x13
			x5 ^= (u<<18)  | (u>>>(32-18))
			u = x10 + x6
			x14 ^= (u<<7)  | (u>>>(32-7))
			u = x14 + x10
			x2 ^= (u<<9)   | (u>>>(32-9))
			u = x2 + x14
			x6 ^= (u<<13)  | (u>>>(32-13))
			u = x6 + x2
			x10 ^= (u<<18) | (u>>>(32-18))
			u = x15 + x11
			x3 ^= (u<<7)   | (u>>>(32-7))
			u = x3 + x15
			x7 ^= (u<<9)   | (u>>>(32-9))
			u = x7 + x3
			x11 ^= (u<<13) | (u>>>(32-13))
			u = x11 + x7
			x15 ^= (u<<18) | (u>>>(32-18))
			u = x0 + x3
			x1 ^= (u<<7)   | (u>>>(32-7))
			u = x1 + x0
			x2 ^= (u<<9)   | (u>>>(32-9))
			u = x2 + x1
			x3 ^= (u<<13)  | (u>>>(32-13))
			u = x3 + x2
			x0 ^= (u<<18)  | (u>>>(32-18))
			u = x5 + x4
			x6 ^= (u<<7)   | (u>>>(32-7))
			u = x6 + x5
			x7 ^= (u<<9)   | (u>>>(32-9))
			u = x7 + x6
			x4 ^= (u<<13)  | (u>>>(32-13))
			u = x4 + x7
			x5 ^= (u<<18)  | (u>>>(32-18))
			u = x10 + x9
			x11 ^= (u<<7)  | (u>>>(32-7))
			u = x11 + x10
			x8 ^= (u<<9)   | (u>>>(32-9))
			u = x8 + x11
			x9 ^= (u<<13)  | (u>>>(32-13))
			u = x9 + x8
			x10 ^= (u<<18) | (u>>>(32-18))
			u = x15 + x14
			x12 ^= (u<<7)  | (u>>>(32-7))
			u = x12 + x15
			x13 ^= (u<<9)  | (u>>>(32-9))
			u = x13 + x12
			x14 ^= (u<<13) | (u>>>(32-13))
			u = x14 + x13
			x15 ^= (u<<18) | (u>>>(32-18))
		}
		block[ 0] = ( x0 >>>  0) & 0xff
		block[ 1] = ( x0 >>>  8) & 0xff
		block[ 2] = ( x0 >>> 16) & 0xff
		block[ 3] = ( x0 >>> 24) & 0xff
		block[ 4] = ( x5 >>>  0) & 0xff
		block[ 5] = ( x5 >>>  8) & 0xff
		block[ 6] = ( x5 >>> 16) & 0xff
		block[ 7] = ( x5 >>> 24) & 0xff
		block[ 8] = (x10 >>>  0) & 0xff
		block[ 9] = (x10 >>>  8) & 0xff
		block[10] = (x10 >>> 16) & 0xff
		block[11] = (x10 >>> 24) & 0xff
		block[12] = (x15 >>>  0) & 0xff
		block[13] = (x15 >>>  8) & 0xff
		block[14] = (x15 >>> 16) & 0xff
		block[15] = (x15 >>> 24) & 0xff
		block[16] = ( x6 >>>  0) & 0xff
		block[17] = ( x6 >>>  8) & 0xff
		block[18] = ( x6 >>> 16) & 0xff
		block[19] = ( x6 >>> 24) & 0xff
		block[20] = ( x7 >>>  0) & 0xff
		block[21] = ( x7 >>>  8) & 0xff
		block[22] = ( x7 >>> 16) & 0xff
		block[23] = ( x7 >>> 24) & 0xff
		block[24] = ( x8 >>>  0) & 0xff
		block[25] = ( x8 >>>  8) & 0xff
		block[26] = ( x8 >>> 16) & 0xff
		block[27] = ( x8 >>> 24) & 0xff
		block[28] = ( x9 >>>  0) & 0xff
		block[29] = ( x9 >>>  8) & 0xff
		block[30] = ( x9 >>> 16) & 0xff
		block[31] = ( x9 >>> 24) & 0xff
		return block
	}
	
	/** Get a Salsa20 block.
	  *
	  * @param   {array} key - 32-byte key.
	  * @param   {array} nonce - 8-byte nonce.
	  * @returns {number} blockNumber - which block in the sequence to output.
	  */
	Salsa20.getBlock = function(key, nonce, blockNumber) {
		// Initialize state
		var keyWords     = [0, 0, 0, 0, 0, 0, 0, 0]
		var nonceWords   = [0, 0]
		var counterWords = [0, 0]
		var i            = 0
		var j            = 0
		// Set key
		for (i = 0, j = 0; i < 8; i++, j += 4) {
			keyWords[i&7] = (key[j&31    ] & 0xff)        |
				           ((key[(j+1)&31] & 0xff) << 8)  |
				           ((key[(j+2)&31] & 0xff) << 16) |
				           ((key[(j+3)&31] & 0xff) << 24)
		}
		// Set nonce
		nonceWords = [
			 (nonce[0] & 0xff)        |
			((nonce[1] & 0xff) << 8)  |
			((nonce[2] & 0xff) << 16) |
			((nonce[3] & 0xff) << 24) ,
			 (nonce[4] & 0xff)        |
			((nonce[5] & 0xff) << 8)  |
			((nonce[6] & 0xff) << 16) |
			((nonce[7] & 0xff) << 24)
		]
		// Increment counter
		i = 0
		for (i = 0; i < blockNumber; i++) {
			counterWords[0]     = (counterWords[0] + 1) & 0xffffffff
			if (counterWords[0] === 0) {
				counterWords[1] = (counterWords[1] + 1) & 0xffffffff
			}
		}
		return generateSalsa20Block(keyWords, nonceWords, counterWords)
	}
	
	/** Get a HSalsa20 block.
	  *
	  * @param   {array} key - 32-byte key.
	  * @param   {array} nonce - 16-byte nonce.
	  */
	HSalsa20.getBlock = function(key, nonce) {
		// Initialize state
		var keyWords     = [0, 0, 0, 0, 0, 0, 0, 0]
		var nonceWords   = [0, 0, 0, 0]
		var i            = 0
		var j            = 0
		// Set key
		for (i = 0, j = 0; i < 8; i++, j += 4) {
			keyWords[i&7] = (key[j&31    ] & 0xff)        |
				           ((key[(j+1)&31] & 0xff) << 8)  |
				           ((key[(j+2)&31] & 0xff) << 16) |
				           ((key[(j+3)&31] & 0xff) << 24)
		}
		// Set nonce
		nonceWords = [
			 (nonce[ 0] & 0xff)        |
			((nonce[ 1] & 0xff) << 8)  |
			((nonce[ 2] & 0xff) << 16) |
			((nonce[ 3] & 0xff) << 24) ,
			 (nonce[ 4] & 0xff)        |
			((nonce[ 5] & 0xff) << 8)  |
			((nonce[ 6] & 0xff) << 16) |
			((nonce[ 7] & 0xff) << 24) ,
			 (nonce[ 8] & 0xff)        |
			((nonce[ 9] & 0xff) << 8)  |
			((nonce[10] & 0xff) << 16) |
			((nonce[11] & 0xff) << 24) ,
			 (nonce[12] & 0xff)        |
			((nonce[13] & 0xff) << 8)  |
			((nonce[14] & 0xff) << 16) |
			((nonce[15] & 0xff) << 24)
		]
		return generateHSalsa20Block(keyWords, nonceWords)
	}
	
	/** Get a XSalsa20 block.
	  *
	  * @param   {array} key - 32-byte key.
	  * @param   {array} nonce - 24-byte nonce.
	  * @returns {number} blockNumber - which block in the sequence to output.
	  */
	XSalsa20.getBlock = function(key, nonce, blockNumber) {
		// Initialize state
		var keyWords     = [0, 0, 0, 0, 0, 0, 0, 0]
		var HNonceWords  = [0, 0, 0, 0]
		var SNonceWords2 = [0, 0]
		var i            = 0
		var j            = 0
		// Set key
		for (i = 0, j = 0; i < 8; i++, j += 4) {
			keyWords[i&7] = (key[j&31    ] & 0xff)        |
				           ((key[(j+1)&31] & 0xff) << 8)  |
				           ((key[(j+2)&31] & 0xff) << 16) |
				           ((key[(j+3)&31] & 0xff) << 24)
		}
		// Set nonce
		HNonceWords = [
			 (nonce[ 0] & 0xff)        |
			((nonce[ 1] & 0xff) << 8)  |
			((nonce[ 2] & 0xff) << 16) |
			((nonce[ 3] & 0xff) << 24) ,
			 (nonce[ 4] & 0xff)        |
			((nonce[ 5] & 0xff) << 8)  |
			((nonce[ 6] & 0xff) << 16) |
			((nonce[ 7] & 0xff) << 24) ,
			 (nonce[ 8] & 0xff)        |
			((nonce[ 9] & 0xff) << 8)  |
			((nonce[10] & 0xff) << 16) |
			((nonce[11] & 0xff) << 24) ,
			 (nonce[12] & 0xff)        |
			((nonce[13] & 0xff) << 8)  |
			((nonce[14] & 0xff) << 16) |
			((nonce[15] & 0xff) << 24) 
		]
		SNonceWords = [
			nonce[16], nonce[17], nonce[18], nonce[19],
			nonce[20], nonce[21], nonce[22], nonce[23]
		]
		return Salsa20.getBlock(
			generateHSalsa20Block(
				keyWords, HNonceWords
			),
			SNonceWords,
			blockNumber
		)
	}

})();