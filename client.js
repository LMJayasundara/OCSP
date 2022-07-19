const WebSocket = require('ws');
const fs = require('fs');

// In order to handle self-signed certificates
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const ws = new WebSocket('wss://localhost:8080',{
  key: fs.readFileSync(`${__dirname}/pki/shanz/private/client.key.pem`),
  cert: fs.readFileSync(`${__dirname}/pki/shanz/certs/client.cert.pem`),

  // To enable security option 2, comment out the ca certificate and change the rejectUnauthorized: false
  ca: [
    fs.readFileSync(`${__dirname}/pki/intermediate/certs/ca-chain.cert.pem`)
  ],
  requestCert: true,
  rejectUnauthorized: true
});

ws.on('open', function open() {
  ws.send('hello from client');
});

ws.on('message', function incoming(data) {
  console.log(data.toString());
  // ws.close();
});

ws.addEventListener('error', (err) => {
  console.log(err.message)
});