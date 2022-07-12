var spawn = require('child_process').spawn;
var exec = require('child_process').exec;
var yaml = require('js-yaml');
var fs = require('fs-extra');
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));
var ocsp = null;
const password = "ocsppass";

var startServer = function() {
    return new Promise(function(resolve, reject) {
        console.log("Starting OCSP server...")

        // spawn
        ocsp = spawn('openssl', [
            'ocsp',
            '-port', global.config.ca.intermediate.ocsp.port,
            '-text',
            '-index', 'intermediate/index.txt',
            '-CA', 'intermediate/certs/ca-chain.cert.pem',
            '-rkey', 'ocsp/private/ocsp.key.pem',
            '-rsigner', 'ocsp/certs/ocsp.cert.pem'
         ], {
            cwd: __dirname + '/pki/',
            detached: true,
            shell: true,
            // stdio: "inherit"
        });

        // // exec
        // ocsp = exec('openssl', [
        //     'ocsp',
        //     '-port', global.config.ca.intermediate.ocsp.port,
        //     '-text',
        //     '-index', 'C:/Users/Lahiru/Desktop/gitdesk/OCSP/pki/intermediate/index.txt',
        //     '-CA', 'C:/Users/Lahiru/Desktop/gitdesk/OCSP/pki/intermediate/certs/ca-chain.cert.pem',
        //     '-rkey', 'C:/Users/Lahiru/Desktop/gitdesk/OCSP/pki/ocsp/private/ocsp.key.pem',
        //     '-rsigner', 'C:/Users/Lahiru/Desktop/gitdesk/OCSP/pki/ocsp/certs/ocsp.cert.pem',
        //     // '-passin', 'pass:'+global.config.ca.intermediate.ocsp.passphrase
        //     // '-passin', `pass:${password}`
        //  ]);

        // // Enter ocsp private key password
        // ocsp.stdin.setEncoding('utf-8');
        // ocsp.stdin.write(global.config.ca.intermediate.ocsp.passphrase + '\n');
        // ocsp.stdin.end();

        console.log(">>>>>> OCSP server is listening on " + global.config.ca.intermediate.ocsp.ip + ':' + global.config.ca.intermediate.ocsp.port + " <<<<<<");

        resolve();

        ocsp.on('error', function(error) {
            console.log("OCSP server startup error: " + error);
            reject(error);
        });

        ocsp.on('close', function(code){
            if(code === null) {
                console.log("OCSP server exited successfully.");
                reject();
            } else {
                console.log("OCSP already exist");
                // reject();
                process.stdin.resume();
                resolve();
            }
        });
    });
};

var stopServer = function() {
    ocsp.kill('SIGHUP');
    console.log("OCSP server stopped.");
};

// var checkStatus = function() {
//     return new Promise(function(resolve, reject) {
//         ocsp.stdout.on('data', function(data) {
//             resolve(data);
//         });
//     });
// }

module.exports = {
    startServer: startServer,
    stopServer: stopServer
    // checkStatus: checkStatus
}


// client: openssl ocsp -CAfile intermediate/certs/ca-chain.cert.pem -url http://127.0.0.1:2560 -resp_text -issuer intermediate/certs/intermediate.cert.pem -cert client/certs/client.cert.pem
// server: openssl ocsp -port 2560 -text -index intermediate/index.txt -CA intermediate/certs/ca-chain.cert.pem -rkey ocsp/private/ocsp.key.pem -rsigner ocsp/certs/ocsp.cert.pem
// revoke: openssl ca -config intermediate/openssl.cnf -revoke client/certs/client.cert.pem