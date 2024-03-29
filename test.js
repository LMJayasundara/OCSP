// ///////////////////////////////////////////////////////////////////////////////////////////

// var rfc2560 = require('asn1.js-rfc2560');
// var crypto = require('crypto');
// var rfc5280 = require('asn1.js-rfc5280');
// var http = require('http');
// var util = require('util');
// var url = require('url');

// exports['id-kp-OCSPSigning'] = [ 1, 3, 6, 1, 5, 5, 7, 3, 9 ];
// const sign = {
//     '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
//     '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
//     '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
//     '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption'
// };

// var checkCert = function() {
//     console.log(">>> Check Client Certificate");
//     return new Promise(function(resolve, reject) {
//         check({cert: rawCert, issuer: rawIssuer}, function(err, res) {
//             if(err) {
//                 console.log(err);
//             } else {
//                 resolve(res);
//             }                         
//         });
//     });
// };

// function check(options, cb) {
//     var sync = true;
//     var req;
  
//     function done(err, data) {
//       if (sync) {
//         sync = false;
//         process.nextTick(function() {
//           cb(err, data);
//         });
//         return;
//       }
  
//       cb(err, data);
//     }
  
//     try {
//       req = generate(options.cert, options.issuer);
//     } catch (e) {
//       return done(e);
//     }
  
//     var ocspMethod = rfc2560['id-pkix-ocsp'].join('.');
//     getAuthorityInfo(req.cert, ocspMethod, function(err, uri) {
//       if (err)
//         return done(err);
  
//         getResponse(uri, req.data, function(err, raw) {
//             if (err)
//               return done(err);
      
//             verify({
//               request: req,
//               response: raw
//             }, done);
//         });
//     });
  
//     sync = false;
// };

// function verify(options, cb) {
//     var req = options.request;
//     var issuer;
//     var res;
  
//     function done(err) {
//       process.nextTick(function() {
//         cb(err, res);
//       });
//     }
  
//     try {
//       issuer = req.issuer || rfc5280.Certificate.decode(toDER(options.issuer, 'CERTIFICATE'), 'der');
//       res = parseResponse(options.response);
//     } catch (e) {
//       return done(e);
//     }
  
//     var rawTBS = options.response.slice(res.start, res.end);
//     var certs = res.certs;
//     var raws = res.certsTbs.map(function(tbs) {
//       return options.response.slice(tbs.start, tbs.end);
//     });
//     res = res.value;
  
//     // Verify signature using CAs Public Key
//     var signAlg = ocsp.utils.sign[res.signatureAlgorithm.algorithm.join('.')];
//     if (!signAlg) {
//       done(new Error('Unknown signature algorithm ' + res.signatureAlgorithm.algorithm));
//       return;
//     }
  
//     var responderKey = findResponder(issuer, certs, raws);
  
//     var verify = crypto.createVerify(signAlg);
//     var tbs = res.tbsResponseData;
  
//     var signature = res.signature.data;
  
//     verify.update(rawTBS);
//     if (!verify.verify(responderKey, signature))
//       return done(new Error('Invalid signature'));
  
//     if (tbs.responses.length < 1)
//       return done(new Error('Expected at least one response'));
  
//     var res = tbs.responses[0];
  
//     // // Verify CertID
//     // // XXX(indutny): verify parameters
//     // if (res.certId.hashAlgorithm.algorithm.join('.') !==
//     //     req.certID.hashAlgorithm.algorithm.join('.')) {
//     //   return done(new Error('Hash algorithm mismatch'));
//     // }
  
//     // if (res.certId.issuerNameHash.toString('hex') !==
//     //     req.certID.issuerNameHash.toString('hex')) {
//     //   return done(new Error('Issuer name hash mismatch'));
//     // }
  
//     // if (res.certId.issuerKeyHash.toString('hex') !==
//     //     req.certID.issuerKeyHash.toString('hex')) {
//     //   return done(new Error('Issuer key hash mismatch'));
//     // }
  
//     // if (res.certId.serialNumber.cmp(req.certID.serialNumber) !== 0)
//     //   return done(new Error('Serial number mismatch'));
  
//     // // if (res.certStatus.type !== 'good') {
//     // //   return done(new Error('OCSP Status: ' + res.certStatus.type));
//     // // }
  
//     // if (res.certStatus.type !== 'good') {
//     //   return done('OCSP Status: ' + res.certStatus.type);
//     // }
  
//     // var now = +new Date();
//     // var nudge = options.nudge || 60000;
//     // if (res.thisUpdate - nudge > now || res.nextUpdate + nudge < now)
//     //   return done(new Error('OCSP Response expired'));
  
//     return done(null);
// };

// function toPEM(buf, label) {
//     var p = buf.toString('base64');
//     var out = [ '-----BEGIN ' + label + '-----' ];
//     for (var i = 0; i < p.length; i += 64)
//       out.push(p.slice(i, i + 64));
//     out.push('-----END ' + label + '-----');
//     return out.join('\n');
// };

// // TODO(indutny): verify issuer, etc...
// function findResponder(issuer, certs, raws) {
//     var issuerKey = issuer.tbsCertificate.subjectPublicKeyInfo;
//     issuerKey = toPEM(rfc5280.SubjectPublicKeyInfo.encode(issuerKey, 'der'), 'PUBLIC KEY');

//     for (var i = 0; i < certs.length; i++) {
//     var cert = certs[i];
//     var signAlg = sign[cert.signatureAlgorithm.algorithm.join('.')];
//     if (!signAlg) {
//         throw new Error('Unknown signature algorithm ' + cert.signatureAlgorithm.algorithm);
//     }

//     var verify = crypto.createVerify(signAlg);

//     verify.update(raws[i]);
//     if (!verify.verify(issuerKey, cert.signature.data))
//         throw new Error('Invalid signature');

//     var certKey = cert.tbsCertificate.subjectPublicKeyInfo;
//     certKey = toPEM(rfc5280.SubjectPublicKeyInfo.encode(certKey, 'der'), 'PUBLIC KEY');

//     return certKey;
//     }

//     return issuerKey;
// }


// function getResponse(uri, req, cb) {
//     uri = url.parse(uri);
  
//     var options = util._extend({
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/ocsp-request',
//         'Content-Length': req.length
//       }
//     }, uri);
  
//     function done(err, response) {
//       if (cb)
//         cb(err, response);
//       cb = null;
//     }
  
//     function onResponse(response) {
//       if (response.statusCode < 200 || response.statusCode >= 400) {
//         return done(
//           new Error('Failed to obtain OCSP response: ' + response.statusCode));
//       }
  
//       var chunks = [];
//       response.on('readable', function() {
//         var chunk = response.read();
//         if (!chunk)
//           return;
//         chunks.push(chunk);
//       });
//       response.on('end', function() {
//         var ocsp = Buffer.concat(chunks);
  
//         done(null, ocsp);
//       });
//     }
  
//     http.request(options, onResponse)
//         .on('error', done)
//         .end(req);
// };


// function getAuthorityInfo(cert, key, done) {
//     var exts = cert.tbsCertificate.extensions;
//     if (!exts)
//       exts = [];
  
//     var infoAccess = exts.filter(function(ext) {
//       return ext.extnID === 'authorityInformationAccess';
//     });
  
//     if (infoAccess.length === 0)
//       return done(new Error('AuthorityInfoAccess not found in extensions'));
  
//     var res = null;
//     var found = infoAccess.some(function(info) {
//       var ext = info.extnValue;
  
//       return ext.some(function(ad) {
//         if (ad.accessMethod.join('.') !== key)
//           return false;
  
//         var loc = ad.accessLocation;
//         if (loc.type !== 'uniformResourceIdentifier')
//           return false;
  
//         res = loc.value + '';
  
//         return true;
//       });
//     });
  
//     if (!found)
//       return done(new Error(key + ' not found in AuthorityInfoAccess'));
  
//     return done(null, res);
// };


// function sha1(data) {
//     return crypto.createHash('sha1').update(data).digest();
// };


// function toDER(raw, what) {
//     var der = raw.toString().match(new RegExp(
//         '-----BEGIN ' + what + '-----([^-]*)-----END ' + what + '-----'));
//     if (der)
//       der = new Buffer(der[1].replace(/[\r\n]/g, ''), 'base64');
//     else if (typeof raw === 'string')
//       der = new Buffer(raw);
//     else
//       der = raw;
//     return der;
// };


// function generate(rawCert, rawIssuer) {
//     var cert;
//     if (rawCert.tbsCertificate) {
//       cert = rawCert;
//     } else {
//       cert = rfc5280.Certificate.decode(toDER(rawCert, 'CERTIFICATE'),'der');
//     }
//     var issuer;
//     if (rawIssuer.tbsCertificate) {
//       issuer = rawIssuer;
//     } else {
//       issuer = rfc5280.Certificate.decode(toDER(rawIssuer, 'CERTIFICATE'),'der');
//     }
  
//     var tbsCert = cert.tbsCertificate;
//     var tbsIssuer = issuer.tbsCertificate;
  
//     var certID = {
//       hashAlgorithm: {
//         // algorithm: [ 2, 16, 840, 1, 101, 3, 4, 2, 1 ]  // sha256
//         algorithm: [ 1, 3, 14, 3, 2, 26 ]  // sha1
//       },
//       issuerNameHash: sha1(rfc5280.Name.encode(tbsCert.issuer, 'der')),
//       issuerKeyHash: sha1(
//         tbsIssuer.subjectPublicKeyInfo.subjectPublicKey.data),
//       serialNumber: tbsCert.serialNumber
//     };
  
//     var tbs = {
//       version: 'v1',
//       requestList: [ {
//         reqCert: certID
//       } ],
//       requestExtensions: [ {
//         extnID: rfc2560['id-pkix-ocsp-nonce'],
//         critical: false,
//         extnValue: rfc2560.Nonce.encode(crypto.randomBytes(16), 'der')
//       } ]
//     };
  
//     var req = {
//       tbsRequest: tbs
//     };
  
//     return {
//       id: sha1(rfc2560.CertID.encode(certID, 'der')),
//       certID: certID,
//       data: rfc2560.OCSPRequest.encode(req, 'der'),
  
//       // Just to avoid re-parsing DER
//       cert: cert,
//       issuer: issuer
//     };
// };


// function parseResponse(raw) {
//     var body = { start: 0, end: raw.length };
//     var response = rfc2560.OCSPResponse.decode(raw, 'der', {
//       track: function(key, start, end, type) {
//         if (type !== 'content' || key !== 'responseBytes/response')
//           return;
//         body.start = start;
//         body.end = end;
//       }
//     });
  
//     var status = response.responseStatus;
//     if (status !== 'successful')
//       throw new Error('Bad OCSP response status: ' + status);
  
//     // Unknown response type
//     var responseType = response.responseBytes.responseType;
//     if (responseType !== 'id-pkix-ocsp-basic')
//       throw new Error('Unknown OCSP response type: ' + responseType);
  
//     var bytes = response.responseBytes.response;
  
//     var tbs = { start: body.start, end: body.end };
//     var certsTbs = [];
//     var basic = rfc2560.BasicOCSPResponse.decode(bytes, 'der', {
//       track: function(key, start, end, type) {
//         if (type !== 'tagged')
//           return;
  
//         if (key === 'tbsResponseData') {
//           tbs.start = body.start + start;
//           tbs.end = body.start + end;
//         } else if (key === 'certs/tbsCertificate') {
//           certsTbs.push({ start: body.start + start, end: body.start + end });
//         }
//       }
//     });
  
//     var OCSPSigning = exports['id-kp-OCSPSigning'].join('.');
//     var certs = (basic.certs || []).filter(function(cert) {
//       return cert.tbsCertificate.extensions.some(function(ext) {
//         if (ext.extnID !== 'extendedKeyUsage')
//           return false;
  
//         return ext.extnValue.some(function(value) {
//           return value.join('.') === OCSPSigning;
//         });
//       });
//     });
  
//     return {
//       start: tbs.start,
//       end: tbs.end,
//       value: basic,
//       certs: certs,
//       certsTbs: certsTbs
//     };
// };

// ws.on('message', function incoming(message) {
//     checkCert().then(function(res) {
//         var status = (res.certStatus.type);
//         console.log(status);

//         if(status == 'good'){
//             console.log('Received: %s', message);
//             ws.send('Hello from server!');
//         }else{
//             ws.send('Certificate is revoked!');
//         }
        
//     });
// });

// ///////////////////////////////////////////////////////////////////////////////////////////

// var checkCert = function() {
//     console.log(">>> Check Client Certificate");
//     return new Promise(function(resolve, reject) {
//         var ocsp_openssl = spawn('openssl', [
//             'ocsp',
//             '-CAfile', 'intermediate/certs/ca-chain.cert.pem',
//             '-url', 'http://127.0.0.1:2560',
//             '-resp_text',
//             '-issuer', 'intermediate/certs/intermediate.cert.pem',
//             '-cert', 'client/certs/client.cert.pem'
//          ], {
//             cwd: __dirname + '/pki/'
//         });

//         resolve(ocsp_openssl);
//     });
// };

// checkCert().then(function(ocsp_openssl) {
//     ocsp_openssl.stdout.on('data', function(raw) {
//         console.log(raw);
//     });
// });

// ///////////////////////////////////////////////////////////////////////////////////////////

// const path = require('path');
// const pkidir = path.resolve(__dirname + '/pki/').split(path.sep).join("/")+"/";
// certificates = new Array();

// var regex = /([R,E,V])(\t)(.*)(\t)(.*)(\t)([\dA-F]*)(\t)(unknown)(\t)(.*)/;

// var reindex = function() {
//     return new Promise(function(resolve, reject) {
//         console.log("Reindexing CertDB ...");

//         var lineReader = require('readline').createInterface({
//             input: require('fs').createReadStream(pkidir + 'intermediate/index.txt')
//         });

//         certificates = [];

//         lineReader.on('line', function (line) {
//             var columns = regex.exec(line);

//             if(columns !== null){
//                 var certificate = {
//                     state:   columns[1],
//                     expirationtime:    columns[3],
//                     revocationtime:     columns[5],
//                     serial:     columns[7],
//                     subject:    columns[11]
//                 };

//                 certificates.push(certificate);
//             } else {
//                 console.log("Error while parsing index.txt line :(");
//             }
//         });

//         lineReader.on('close', function() {
//             console.log("Reindexing finished");
//             resolve();
//         });
//     });
// }

// var result = new Array();
// var serial = '1007'

// reindex().then(function () {
//     certificates.forEach(certificate => {
//         if (certificate.serial == serial) {
//             result.push(certificate);
//         }
//     });
//     console.log(result);
// });

////////////////////////////////////////////////////////////////////////////////////////

// const replace = require('replace-in-file');
// const options = {
//   files: './user.db',
//   from: "sss",
//   to: 'ttt',
// };

// replace(options)
//   .then(results => {
//     console.log('Replacement results:', results);
//   })
//   .catch(error => {
//     console.error('Error occurred:', error);
//   });

////////////////////////////////////////////////////////////////////////////////////////////

// var fs = require('fs')
// fs.readFile('user.db', {encoding: 'utf-8'}, function(err, data) {
//     if (err) throw error;

//     let dataArray = data.split('\n'); // convert file data in an array
//     const searchKeyword = 'ttt'; // we are looking for a line, contains, key word 'user1' in the file
//     let lastIndex = -1; // let say, we have not found the keyword

//     for (let index=0; index<dataArray.length; index++) {
//         if (dataArray[index].includes(searchKeyword)) { // check if a line contains the 'user1' keyword
//             lastIndex = index; // found a line includes a 'user1' keyword
//             break; 
//         }
//     }

//     dataArray.splice(lastIndex, 1); // remove the keyword 'user1' from the data Array

//     // UPDATE FILE WITH NEW DATA
//     // IN CASE YOU WANT TO UPDATE THE CONTENT IN YOUR FILE
//     // THIS WILL REMOVE THE LINE CONTAINS 'user1' IN YOUR shuffle.txt FILE
//     const updatedData = dataArray.join('\n');
//     fs.writeFile('user.db', updatedData, (err) => {
//         if (err) throw err;
//         console.log ('Successfully updated the file data');
//     });

// });