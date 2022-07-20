const apipath = '/ocsp';
var path = require('path');
const pkidir = path.resolve(__dirname + '/pki/').split(path.sep).join("/")+"/";
const fs = require('fs-extra');
const exec = require('child_process').exec;
const suspend = require('suspend');
var yaml = require('js-yaml');
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));

var createUserKey = function(username, passWord) {
    console.log(">>> Creating a User");
    fs.ensureDirSync(pkidir + username);
    fs.ensureDirSync(pkidir + username +'/certs');
    fs.ensureDirSync(pkidir + username +'/private');
    fs.ensureDirSync(pkidir + username +'/csr');
    // openssl_client_cnf = fs.readFileSync(__dirname + '/cnf/client.cnf', 'utf8');
    // fs.writeFileSync(pkidir + username +'/openssl.cnf', openssl_client_cnf);

    openssl_client = fs.readFileSync(__dirname + '/template/openssl_client.cnf.tpl', 'utf8');
    openssl_client = openssl_client.replace(/{basedir}/g, pkidir + 'intermediate');
    openssl_client = openssl_client.replace(/{rootname}/g, global.config.ca.admin.rootname);
    openssl_client = openssl_client.replace(/{chainname}/g, global.config.ca.admin.chainname);
    openssl_client = openssl_client.replace(/{name}/g, username);
    openssl_client = openssl_client.replace(/{days}/g, global.config.ca.admin.days);
    openssl_client = openssl_client.replace(/{country}/g, global.config.ca.admin.country);
    openssl_client = openssl_client.replace(/{state}/g, global.config.ca.admin.state);
    openssl_client = openssl_client.replace(/{locality}/g, global.config.ca.admin.locality);
    openssl_client = openssl_client.replace(/{organization}/g, global.config.ca.admin.organization);
    openssl_client = openssl_client.replace(/{unit}/g, global.config.ca.admin.unit);
    openssl_client = openssl_client.replace(/{commonname}/g, username);
    fs.writeFileSync(pkidir + username+ '/openssl.cnf', openssl_client);

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

function* serialRevoke(serial, passphrase, username) {
    console.log('>>>>>>>>>> Revoke serial ', serial);
    const revokation = yield revokeCertificate(serial, passphrase, username);
    return revokation;
}


function revokeCertificate(serialNumber, passphrase, username) {
    exec('openssl ca -config openssl.cnf -revoke ./newcerts/' + serialNumber.toString() + '.pem -passin pass:' + passphrase, {
        cwd: pkidir + "intermediate"
    }, function(err, stdout, stderr) {
        console.log(err);
    });
}

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

    app.post(apipath + '/revoke/', function(req, res) {
        console.log("Admin is requesting revokation of serial " + req.body.serial);

        suspend.run(function*() {
            return yield* serialRevoke(req.body.serial, req.body.passphrase, req.body.username);
    
        }, function(err, result) {
            if (err) {
                console.log('err', err);
            }
        });
    });

    
}

module.exports = {
    initAPI
};