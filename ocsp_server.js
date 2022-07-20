var spawn = require('child_process').spawn;
var exec = require('child_process').exec;
var yaml = require('js-yaml');
var fs = require('fs-extra');
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));
var ocsp = null;
const password = "ocsppass";
var kill = require('tree-kill');

var startServer = function() {
    return new Promise(function(resolve, reject) {
        console.log("Starting OCSP server...")

        // spawn
        ocsp = spawn('openssl', [
            'ocsp',
            '-port', global.config.ca.ocsp.port,
            '-text',
            '-index', 'intermediate/index.txt',
            '-CA', 'intermediate/certs/ca-chain.cert.pem',
            '-rkey', 'ocsp/private/ocsp.key.pem',
            '-rsigner', 'ocsp/certs/ocsp.cert.pem',
            '-nmin', '1'
         ], {
            cwd: __dirname + '/pki/',
            detached: false,
            shell: true,
            // stdio: "inherit"
        });

        // // exec
        // ocsp = exec('openssl', [
        //     'ocsp',
        //     '-port', global.config.ca.ocsp.port,
        //     '-text',
        //     '-index', 'C:/Users/Lahiru/Desktop/gitdesk/OCSP/pki/intermediate/index.txt',
        //     '-CA', 'C:/Users/Lahiru/Desktop/gitdesk/OCSP/pki/intermediate/certs/ca-chain.cert.pem',
        //     '-rkey', 'C:/Users/Lahiru/Desktop/gitdesk/OCSP/pki/ocsp/private/ocsp.key.pem',
        //     '-rsigner', 'C:/Users/Lahiru/Desktop/gitdesk/OCSP/pki/ocsp/certs/ocsp.cert.pem',
        //     // '-passin', 'pass:'+global.config.ca.ocsp.passphrase
        //     // '-passin', `pass:${password}`
        //  ]);

        // // Enter ocsp private key password
        // ocsp.stdin.setEncoding('utf-8');
        // ocsp.stdin.write(global.config.ca.ocsp.passphrase + '\n');
        // ocsp.stdin.end();

        console.log(">>>>>> OCSP server is listening on " + global.config.ca.ocsp.ip + ':' + global.config.ca.ocsp.port + " <<<<<<");

        ocsp.on('error', function(error) {
            console.log("OCSP server startup error: " + error);
            reject(error);
        });

        // ocsp.on('close', function(code){
        //     if(code === null) {
        //         console.log("OCSP server exited successfully.");
        //     } else {
        //         console.log("OCSP exited with code " + code);
        //         ocsp;
        //     }
        // });

        resolve(ocsp);
    });
};

module.exports = {
    startServer: startServer
}

// client: openssl ocsp -CAfile intermediate/certs/ca-chain.cert.pem -url http://127.0.0.1:2560 -resp_text -issuer intermediate/certs/intermediate.cert.pem -cert client/certs/client.cert.pem
// server: openssl ocsp -port 2560 -text -index intermediate/index.txt -CA intermediate/certs/ca-chain.cert.pem -rkey ocsp/private/ocsp.key.pem -rsigner ocsp/certs/ocsp.cert.pem
// revoke: openssl ca -config intermediate/openssl.cnf -revoke client/certs/client.cert.pem