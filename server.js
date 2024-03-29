var fs = require('fs');
var WebSocket = require('ws');
var https = require('https');
var ocsp = require('ocsp');
var ocsp_server = require('./ocsp_server.js');
var PORT = 8080;

var bodyparser = require('body-parser');
var express = require('express');
var app = express();
var api = require('./api.js');
var spawn = require('child_process').spawn;
var yaml = require('js-yaml');
var kill = require('tree-kill');

global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));
var reocsp = null;
var ocspCache = new ocsp.Cache();

app.use(bodyparser.json());

var server = new https.createServer({
    cert: fs.readFileSync(`${__dirname}/pki/server/certs/server.cert.pem`),
    key: fs.readFileSync(`${__dirname}/pki/server/private/server.key.pem`),
    ca: [
        fs.readFileSync(`${__dirname}/pki/intermediate/certs/ca-chain.cert.pem`)
    ],
    requestCert: true,
    rejectUnauthorized: true,
    secureProtocol: 'TLS_method',
    ciphers: 'AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384',
    ecdhCurve: 'secp521r1:secp384r1',
    honorCipherOrder: true,
    // requestOCSP: true
}, app);

var wss = new WebSocket.Server({
    server,
    verifyClient: (info) => {
        // console.log(info.req.client);
        var success = !!info.req.client.authorized;
        console.log(success);
        return success;
    }
});

wss.on('connection', function connection(ws, req) {
    // console.log(req.connection.remoteAddress);
    // console.log(req.socket.getPeerCertificate().subject.CN);
    // console.log(req.method);
    // console.log(req.url);

    var cert = req.socket.getPeerCertificate(true);
    var rawCert = cert.raw;
    var rawIssuer = cert.issuerCertificate.raw;

    ocsp.getOCSPURI(rawCert, function(err, uri) {
        if (err) console.log(err);
        var req = ocsp.request.generate(rawCert, rawIssuer);
        var options = {
            url: uri,
            ocsp: req.data
        };
        ocspCache.request(req.id, options, null);
    });

    ws.on('message', function incoming(message) {
        console.log(ocspCache.cache);
        ocsp.check({cert: rawCert, issuer: rawIssuer}, function(err, res) {
            if(err) {
                console.log(err.message);
                ws.send('Failed to obtain OCSP response!');
            } else {
                console.log(res.type);
                var status = res.type;
                if(status == 'good'){
                    console.log('Received: %s', message);
                    ws.send('Hello from server!');
                }else{
                    ws.send('Certificate is revoked!');
                }
            }                              
        });
    });
});

server.listen(PORT, ()=>{
    api.initAPI(app);
    ocsp_server.startServer().then(function (cbocsp) {
        var ocsprenewint = 1000 * 60; // 1min
        reocsp = cbocsp;

        setInterval(() => {
            kill(cbocsp.pid, 'SIGKILL', function(err) {
                if(err){
                    console.log(err.message);
                    process.exit();
                }
                else{
                    console.log("Restart the ocsp server..");
                    cbocsp = spawn('openssl', [
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
                        detached: true,
                        shell: true
                    });
        
                    cbocsp.on('error', function(error) {
                        console.log("OCSP server startup error: " + error);
                        reject(error);
                    });

                    reocsp = cbocsp;
                }
            });

        }, ocsprenewint);

    })
    .catch(function(error){
        console.log("Could not start OCSP server: " + error);
    });

    console.log( (new Date()) + " Server is listening on port " + PORT);
});

// Server stop routine and events
var stopServer = function() {
    console.log("Received termination signal.");
    console.log("Stopping OCSP server...");
    kill(reocsp.pid, 'SIGKILL', function(err) {
        if(err){
            console.log(err.message);
        }
        else{
            console.log("Server stoped!");
        }
        process.exit();
    });
};

process.on('SIGINT', stopServer);
process.on('SIGHUP', stopServer);
process.on('SIGQUIT', stopServer);