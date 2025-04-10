const https = require('https');
const { readFile } = require('fs/promises');

function createStandardAgent(caCert, serverName) {
	return new https.Agent({
		ca: caCert,
		servername: serverName,
		rejectUnauthorized: true,
	});
}

function httpsGet(url, agent) {
	return new Promise((resolve, reject) => {
		const req = https.get(url, { agent }, (res) => {
			let data = '';
			res.on('data', chunk => data += chunk);
			res.on('end', () => {
				resolve({ statusCode: res.statusCode, body: data });
			});
		});
		req.on('error', reject);
	});
}

async function testRequest(conf, agent) {
	const url = `https://localhost:${conf.addr}`;
	try {
		const res = await httpsGet(url, agent);
		if (conf.expectedOK) {
			console.log(`  \x1b[32m✔\x1b[0m Request to :${conf.addr} (as ${conf.serverName}) succeeded`);
			console.log(`    - Response: ${res.body}`);
		} else {
			console.log(`  \x1b[31m✘\x1b[0m Request to :${conf.addr} (as ${conf.serverName}) succeeded but was not expected to`);
		}
	} catch (err) {
		if (conf.expectedOK) {
			console.log(`  \x1b[31m✘\x1b[0m Request to :${conf.addr} (as ${conf.serverName}) failed: ${err.message}`);
		} else {
			console.log(`  \x1b[32m✔\x1b[0m Request to :${conf.addr} (as ${conf.serverName}) failed as expected: ${err.message}`);
		}
	}
}

async function main() {
	const caPath = 'ca/root/root.cert.pem';
	const caCert = await readFile(caPath);

	const configs = [
		{ name: "domain_correct_ou_correct", addr: 8443, serverName: "only-this-domain-is-allowed.com", expectedOK: true },
		{ name: "domain_incorrect_ou_correct", addr: 8444, serverName: "only-this-domain-is-allowed.com", expectedOK: false },
		{ name: "domain_correct_ou_incorrect", addr: 8445, serverName: "this-domain-is-not-allowed.com", expectedOK: false },
		{ name: "domain_incorrect_ou_incorrect", addr: 8446, serverName: "this-domain-is-not-allowed.com", expectedOK: false },
	];

	console.log("\nTesting using the standard TLS client");
	console.log("=====================================\n");

	for (const conf of configs) {
		console.log(`Testing ${conf.name}`);
		const agent = createStandardAgent(caCert, conf.serverName);
		await testRequest(conf, agent);
		console.log();
	}
}

main();
