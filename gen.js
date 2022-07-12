// Script generates OpenSSL PKI based on the configuration in config.yml

var fs = require('fs-extra');
var yaml = require('js-yaml');
var exec = require('child_process').exec;
var path = require('path');

const pkidir = __dirname + '/pki/';
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));

var createFileStructure = function() {
    console.log(">>> Creating CA file structure")

    return new Promise(function(resolve, reject) {
        fs.ensureDirSync(pkidir);

        // Prepare root dir
        fs.ensureDirSync(pkidir + 'root');
        fs.ensureDirSync(pkidir + 'root/certs');
        fs.ensureDirSync(pkidir + 'root/private');
        fs.ensureDirSync(pkidir + 'root/newcerts');
        fs.ensureDirSync(pkidir + 'root/crl');
        fs.writeFileSync(pkidir + 'root/index.txt', '', 'utf8');
        fs.writeFileSync(pkidir + 'root/serial', '1000', 'utf8');
        openssl_root_cnf = fs.readFileSync(__dirname + '/cnf/rootCA.cnf', 'utf8');
        fs.writeFileSync(pkidir + 'root/openssl.cnf', openssl_root_cnf);

        // Prepare intermediate dir
        fs.ensureDirSync(pkidir + 'intermediate');
        fs.ensureDirSync(pkidir + 'intermediate/certs');
        fs.ensureDirSync(pkidir + 'intermediate/private');
        fs.ensureDirSync(pkidir + 'intermediate/newcerts');
        fs.ensureDirSync(pkidir + 'intermediate/crl');
        fs.writeFileSync(pkidir + 'intermediate/index.txt', '', 'utf8');
        fs.writeFileSync(pkidir + 'intermediate/serial', '1000', 'utf8');
        openssl_intermediate_cnf = fs.readFileSync(__dirname + '/cnf/intermediateCA.cnf', 'utf8');
        fs.writeFileSync(pkidir + 'intermediate/openssl.cnf', openssl_intermediate_cnf);

        // Prepare ocsp dir
        fs.ensureDirSync(pkidir + 'ocsp');
        fs.ensureDirSync(pkidir + 'ocsp/certs');
        fs.ensureDirSync(pkidir + 'ocsp/private');
        fs.ensureDirSync(pkidir + 'ocsp/csr');
        openssl_ocsp_cnf = fs.readFileSync(__dirname + '/cnf/ocsp.cnf', 'utf8');
        fs.writeFileSync(pkidir + 'ocsp/openssl.cnf', openssl_ocsp_cnf);

        // Prepare server dir
        fs.ensureDirSync(pkidir + 'server');
        fs.ensureDirSync(pkidir + 'server/certs');
        fs.ensureDirSync(pkidir + 'server/private');
        fs.ensureDirSync(pkidir + 'server/csr');
        openssl_server_cnf = fs.readFileSync(__dirname + '/cnf/server.cnf', 'utf8');
        fs.writeFileSync(pkidir + 'server/openssl.cnf', openssl_server_cnf);

        // Prepare client dir
        fs.ensureDirSync(pkidir + 'client');
        fs.ensureDirSync(pkidir + 'client/certs');
        fs.ensureDirSync(pkidir + 'client/private');
        fs.ensureDirSync(pkidir + 'client/csr');
        openssl_client_cnf = fs.readFileSync(__dirname + '/cnf/client.cnf', 'utf8');
        fs.writeFileSync(pkidir + 'client/openssl.cnf', openssl_client_cnf);

        resolve();
    });
};
 
var createRootCA = function() {
    console.log(">>> Creating Root CA");

    return new Promise(function(resolve, reject) {
        // Create root key
        exec('openssl genrsa -aes256 -out private/root.key.pem -passout pass:' + global.config.ca.root.passphrase + ' 4096', {
            cwd: pkidir + 'root'
        }, function() {
            // Create Root certificate
            exec('openssl req -config openssl.cnf -key private/root.key.pem -new -x509 -days ' + global.config.ca.root.days + ' -sha256 -extensions v3_ca -out certs/root.cert.pem -passin pass:' + global.config.ca.root.passphrase, {
                cwd: pkidir + 'root'
            }, function() {
                resolve();
            });
        });
    });
};

var createIntermediateCA = function() {
    console.log(">>> Creating Intermediate CA");

    return new Promise(function(resolve, reject) {
        // Create intermediate key
        exec('openssl genrsa -aes256 -out private/intermediate.key.pem -passout pass:' + global.config.ca.intermediate.passphrase + ' 4096', {
            cwd: pkidir + 'intermediate'
        }, function() {
            // Create intermediate certificate request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/intermediate.key.pem -out intermediate.csr.pem -passin pass:' + global.config.ca.intermediate.passphrase, {
                cwd: pkidir + 'intermediate'
            }, function() {
                // Create intermediate certificate
                exec('openssl ca -config ../root/openssl.cnf -extensions v3_intermediate_ca -days ' + global.config.ca.intermediate.days + ' -notext -md sha256 -in intermediate.csr.pem -out certs/intermediate.cert.pem -passin pass:' + global.config.ca.root.passphrase + ' -batch', {
                    cwd: pkidir + 'intermediate'
                }, function(error, stdout, stderr) {
                    console.log(error);
                    // Remove intermediate.csr.pem file
                    fs.removeSync(pkidir + 'intermediate/intermediate.csr.pem');

                    // Create CA chain file
                    // Read intermediate
                    intermediate = fs.readFileSync(pkidir + 'intermediate/certs/intermediate.cert.pem', 'utf8');
                    // Read root cert
                    root = fs.readFileSync(pkidir + 'root/certs/root.cert.pem', 'utf8');
                    cachain = intermediate + '\n\n' + root;
                    fs.writeFileSync(pkidir + 'intermediate/certs/ca-chain.cert.pem', cachain);
                    resolve();
                });
            });
        });
    });
};

var createOCSPKeys = function() {
    console.log(">>> Creating OCSP Keys")

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl genrsa -aes256 -out private/ocsp.key.pem -passout pass:' + global.config.ca.intermediate.ocsp.passphrase + ' 4096', {
            cwd: pkidir + 'ocsp'
        }, function() {
            // Create request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/ocsp.key.pem -passin pass:' + global.config.ca.intermediate.ocsp.passphrase + ' -out csr/ocsp.csr.pem', {
                cwd: pkidir + 'ocsp'
            }, function() {
                // Create certificate
                exec('openssl ca -config openssl.cnf -extensions ocsp -days 3650 -notext -md sha256 -in csr/ocsp.csr.pem -out certs/ocsp.cert.pem -passin pass:' + global.config.ca.intermediate.passphrase + ' -batch', {
                    cwd: pkidir + 'ocsp'
                }, function() {
                    fs.removeSync(pkidir + 'ocsp/csr/ocsp.csr.pem');
                    resolve();
                });
            });
        });
    });
};
 
var createServer = function() {
    console.log(">>> Creating Server certificates");

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl genrsa -out private/server.key.pem 4096', {
            cwd: pkidir + 'server'
        }, function() {
            // Create request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/server.key.pem -out csr/server.csr.pem', {
                cwd: pkidir + 'server'
            }, function() {
                // Create certificate
                exec('openssl ca -config openssl.cnf -extensions server_cert -days 365 -notext -md sha256 -in csr/server.csr.pem -out certs/server.cert.pem -passin pass:' + global.config.ca.intermediate.passphrase + ' -batch', {
                    cwd: pkidir + 'server'
                }, function() {
                    fs.removeSync(pkidir + 'server/csr/server.csr.pem');
                    resolve();
                });
            });
        });
    });
};

var createClient = function() {
    console.log(">>> Creating Client certificates");

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl genrsa -out private/client.key.pem 4096', {
            cwd: pkidir + 'client'
        }, function() {
            // Create request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/client.key.pem -out csr/client.csr.pem', {
                cwd: pkidir + 'client'
            }, function() {
                // Create certificate
                exec('openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in csr/client.csr.pem -out certs/client.cert.pem -passin pass:' + global.config.ca.intermediate.passphrase + ' -batch', {
                    cwd: pkidir + 'client'
                }, function(err) {
                    console.log(err);
                    fs.removeSync(pkidir + 'client/csr/client.csr.pem');
                    resolve();
                });
            });
        });
    });
};

// var setFilePerms = function() {
//     log(">>> Setting file permissions")

//     return new Promise(function(resolve, reject) {
//         // Root CA
//         fs.chmodSync(pkidir + 'root/root.key.pem', 0400);
//         fs.chmodSync(pkidir + 'root/root.cert.pem', 0444);
//         fs.chmodSync(pkidir + 'root/openssl.cnf', 0400);

//         // Intermediate CA
//         fs.chmodSync(pkidir + 'intermediate/intermediate.key.pem', 0400);
//         fs.chmodSync(pkidir + 'intermediate/intermediate.cert.pem', 0444);
//         fs.chmodSync(pkidir + 'intermediate/openssl.cnf', 0400);

//         resolve();
//     });
// };

function create() {
    return new Promise(function(resolve, reject) {
        createFileStructure().then(function() {
            createRootCA().then(function() {
                createIntermediateCA().then(function() {
                    createServer().then(function() {
                        createClient().then(function() {
                            createOCSPKeys().then(function() {
                                console.log("### Finished!");
                                resolve()
                            })
                            .catch(function(err) {
                                reject("Error: " + err)
                            });
                        })
                        .catch(function(err) {
                            reject("Error: " + err)
                        });
                    })
                    .catch(function(err) {
                        reject("Error: " + err)
                    });
                })
                .catch(function(err) {
                    reject("Error: " + err)
                });
            })
            .catch(function(err) {
                reject("Error: " + err)
            })
        })
        .catch(function(err) {
            reject("Error: " + err)
        });
    })
}
 
create();