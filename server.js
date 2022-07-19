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
const CronJob = require('cron').CronJob;

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

wss.on('connection', function connection(ws, req) {

    // console.log(req.connection.remoteAddress);
    // console.log(req.socket.getPeerCertificate().subject.CN);
    // console.log(req.method);
    // console.log(req.url);
    
    const cert = req.socket.getPeerCertificate(true);
    const rawCert = cert.raw;
    const rawIssuer = cert.issuerCertificate.raw;

    ws.on('message', function incoming(message) {
      ocsp.check({cert: rawCert, issuer: rawIssuer}, function(err, res) {
          if(err) {
              console.log(err);
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

const job = new CronJob('1 * * * * *', function() {
	console.log('Restart the ocsp');
    ocsp_server.startServer();
});

server.listen(PORT, ()=>{
    api.initAPI(app);
    ocsp_server.startServer();
    job.start();
    console.log( (new Date()) + " Server is listening on port " + PORT);
});