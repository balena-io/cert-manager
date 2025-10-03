const crypto = require('crypto');
const fs = require('fs');

// Read in required cert files
const base = process.argv[2];
const pem = fs.readFileSync(`${base}.pem`, 'utf8');
const key = fs.readFileSync(`${base}.key`, 'utf8');
const kid = fs.readFileSync(`${base}.kid`, 'utf8').trim();

// Generate jwk from pem
const privateKey = crypto.createPrivateKey(key);
const jwk = privateKey.export({ format: 'jwk' });

// Generate x5t thumbprint from pem
const x509 = new crypto.X509Certificate(pem);
const sha1hash = crypto.createHash('sha1').update(x509.raw).digest();
const x5t = sha1hash.toString('base64url');

// Remove unnecessary private 'd' property
if (jwk.d) {
	delete jwk.d;
}

// Output result
process.stdout.write(JSON.stringify({
	keys: [{
		...jwk,
		use: 'sig',
		alg: 'ES256',
		kid,
		x5t,
	}],
}, null, 2));
