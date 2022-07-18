const apipath = '/ocsp';
const pkidir = __dirname + '/pki/';
const fs = require('fs-extra');
const exec = require('child_process').exec;

var createUserKey = function(username, passWord) {
    console.log(">>> Creating a User");
    fs.ensureDirSync(pkidir + username);
    fs.ensureDirSync(pkidir + username +'/certs');
    fs.ensureDirSync(pkidir + username +'/private');
    fs.ensureDirSync(pkidir + username +'/csr');
    openssl_client_cnf = fs.readFileSync(__dirname + '/cnf/client.cnf', 'utf8');
    fs.writeFileSync(pkidir + username +'/openssl.cnf', openssl_client_cnf);

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl genrsa -out private/client.key.pem 4096', {
            cwd: pkidir + username
        }, function() {
            // Create request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/client.key.pem -out csr/client.csr.pem', {
                cwd: pkidir + username
            }, function() {
                // Create certificate
                exec('openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in csr/client.csr.pem -out certs/client.cert.pem -passin pass:' + global.config.ca.intermediate.passphrase + ' -batch', {
                    cwd: pkidir + username
                }, function(err) {
                    // console.log(err.message);
                    if(err){
                        resolve([err.message, false]);
                    }
                    // fs.removeSync(pkidir + 'client/csr/client.csr.pem');
                    resolve([username + " Created", true]);
                });
            });
        });
    });
};

const initAPI = function(app) {
    app.post(apipath + '/user/', function(req, res) {
        console.log("Admin is requesting to create a new user:", req.body.name);
        createUserKey(req.body.name, req.body.passwd).then((msg) =>{
            // console.log(msg);
            result = msg[0]
            res.json({
                success: msg[1],
                result
            });
        });
    });
}

module.exports = {
    initAPI
};