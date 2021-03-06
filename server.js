const fs = require('fs');
const WebSocket = require('ws');
const https = require('https');
const ocsp = require('ocsp');
const ocsp_server = require('./ocsp_server.js');
const PORT = 8080;

const bodyparser = require('body-parser');
const express = require('express');
const app = express();
const api = require('./api.js');
const { json } = require('body-parser');
const CronJob = require('cron').CronJob;
var spawn = require('child_process').spawn;
var yaml = require('js-yaml');
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));

var ocspCache = new ocsp.Cache();

app.use(bodyparser.json());

const server = new https.createServer({
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
    honorCipherOrder: true
    // nextUpdate: 1e3, //24 * 3600 * 1e3
}, app);

const wss = new WebSocket.Server({
    server,
    verifyClient: (info) => {
        // console.log(info.req.client);
        var success = !!info.req.client.authorized;
        console.log(success);
        return success;
    }
});

wss.on('connection', function connection(ws, req, cb) {

    // console.log(req.connection.remoteAddress);
    // console.log(req.socket.getPeerCertificate().subject.CN);
    // console.log(req.method);
    // console.log(req.url);
    // console.log(ocspCache);
    
    const cert = req.socket.getPeerCertificate(true);
    const rawCert = cert.raw;
    const rawIssuer = cert.issuerCertificate.raw;

    ocsp.getOCSPURI(rawCert, function(err, uri) {
        if (err) return cb(error);
        var req = ocsp.request.generate(rawCert, rawIssuer);
        var options = {
            url: uri,
            ocsp: req.data
        };
        // console.log(options);
        ocspCache.request(req.id, options, cb);
    });

    ws.on('message', function incoming(message) {
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

// const job = new CronJob('1 * * * * *', function() {
// 	console.log('Restart the ocsp');
//     ocsp_server.startServer();
// });

// omit
var sslSessionCache = {};
server.on('newSession', function(sessionId, sessionData, callback) {
    // console.log('newSession: ', sessionId);
    sslSessionCache[sessionId] = sessionData;
    callback();
});

server.on('resumeSession', function (sessionId, callback) {
    // console.log('resumeSession: ', sessionId);
    callback(null, sslSessionCache[sessionId]);
});

var kill = require('tree-kill');
var yyy = null;

server.listen(PORT, ()=>{
    api.initAPI(app);
    ocsp_server.startServer().then(function (xxx) {
        // var ocsprenewint = 1000 * 60 * 60 * 24; // 24h
        var ocsprenewint = 1000 * 10; // 1min

        setInterval(() => {
            yyy = xxx;
            kill(xxx.pid, 'SIGKILL', function(err) {
                if(err){
                    console.log(err.message);
                    process.exit();
                }
                else{
                    console.log("Restart the ocsp server..");
                    xxx = spawn('openssl', [
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
        
                    xxx.on('error', function(error) {
                        console.log("OCSP server startup error: " + error);
                        reject(error);
                    });

                    // xxx.on('close', function(code){
                    //     if(code === null) {
                    //         console.log("OCSP server exited successfully.");
                    //     } else {
                    //         console.log("OCSP exited with code " + code);
                    //     }
                    // });
        
                }
            });

        }, 3000);

    })
    .catch(function(error){
        console.log("Could not start OCSP server: " + error);
    });

    // job.start();
    console.log( (new Date()) + " Server is listening on port " + PORT);
});


// Server stop routine and events
var stopServer = function() {
    console.log("Received termination signal.");
    console.log("Stopping OCSP server ...");
    kill(yyy.pid, 'SIGKILL', function(err) {
        if(err){
            console.log(err.message);
        }
        else{
            console.log("Server stoped!");
            process.exit();
        }
    });
};

process.on('SIGINT', stopServer);
process.on('SIGHUP', stopServer);
process.on('SIGQUIT', stopServer);