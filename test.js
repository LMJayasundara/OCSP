var rfc2560 = require('asn1.js-rfc2560');



check({cert: rawCert, issuer: rawIssuer}, function(err, res) {
    if(err) {
        console.log(err);
    } else {
        console.log(res);
    }                              
});


function check(options, cb) {
    var sync = true;
    var req;
  
    function done(err, data) {
      if (sync) {
        sync = false;
        process.nextTick(function() {
          cb(err, data);
        });
        return;
      }
  
      cb(err, data);
    }
  
    try {
      req = generate(options.cert, options.issuer);
    } catch (e) {
      return done(e);
    }
  
    var ocspMethod = rfc2560['id-pkix-ocsp'].join('.');
    getAuthorityInfo(req.cert, ocspMethod, function(err, uri) {
      if (err)
        return done(err);
  
      getResponse(uri, req.data, function(err, raw) {
        if (err){
            return done(err);
        }
        
        else{
            res = parseResponse(raw); //options.response)

            function doneres(err) {
                process.nextTick(function() {
                  cb(err, res && res.certStatus);
                });
            }
            return doneres(null);
        }
  
        // verify({
        //   request: req,
        //   response: raw
        // }, done);

      });
    });
  
    sync = false;
};


function getResponse(uri, req, cb) {
    uri = url.parse(uri);
  
    var options = util._extend({
      method: 'POST',
      headers: {
        'Content-Type': 'application/ocsp-request',
        'Content-Length': req.length
      }
    }, uri);
  
    function done(err, response) {
      if (cb)
        cb(err, response);
      cb = null;
    }
  
    function onResponse(response) {
      if (response.statusCode < 200 || response.statusCode >= 400) {
        return done(
          new Error('Failed to obtain OCSP response: ' + response.statusCode));
      }
  
      var chunks = [];
      response.on('readable', function() {
        var chunk = response.read();
        if (!chunk)
          return;
        chunks.push(chunk);
      });
      response.on('end', function() {
        var ocsp = Buffer.concat(chunks);
  
        done(null, ocsp);
      });
    }
  
    http.request(options, onResponse)
        .on('error', done)
        .end(req);
};


function getAuthorityInfo(cert, key, done) {
    var exts = cert.tbsCertificate.extensions;
    if (!exts)
      exts = [];
  
    var infoAccess = exts.filter(function(ext) {
      return ext.extnID === 'authorityInformationAccess';
    });
  
    if (infoAccess.length === 0)
      return done(new Error('AuthorityInfoAccess not found in extensions'));
  
    var res = null;
    var found = infoAccess.some(function(info) {
      var ext = info.extnValue;
  
      return ext.some(function(ad) {
        if (ad.accessMethod.join('.') !== key)
          return false;
  
        var loc = ad.accessLocation;
        if (loc.type !== 'uniformResourceIdentifier')
          return false;
  
        res = loc.value + '';
  
        return true;
      });
    });
  
    if (!found)
      return done(new Error(key + ' not found in AuthorityInfoAccess'));
  
    return done(null, res);
};


function sha1(data) {
    return crypto.createHash('sha1').update(data).digest();
};


function toDER(raw, what) {
    var der = raw.toString().match(new RegExp(
        '-----BEGIN ' + what + '-----([^-]*)-----END ' + what + '-----'));
    if (der)
      der = new Buffer(der[1].replace(/[\r\n]/g, ''), 'base64');
    else if (typeof raw === 'string')
      der = new Buffer(raw);
    else
      der = raw;
    return der;
};


function generate(rawCert, rawIssuer) {
    var cert;
    if (rawCert.tbsCertificate) {
      cert = rawCert;
    } else {
      cert = rfc5280.Certificate.decode(toDER(rawCert, 'CERTIFICATE'),'der');
    }
    var issuer;
    if (rawIssuer.tbsCertificate) {
      issuer = rawIssuer;
    } else {
      issuer = rfc5280.Certificate.decode(toDER(rawIssuer, 'CERTIFICATE'),'der');
    }
  
    var tbsCert = cert.tbsCertificate;
    var tbsIssuer = issuer.tbsCertificate;
  
    var certID = {
      hashAlgorithm: {
        // algorithm: [ 2, 16, 840, 1, 101, 3, 4, 2, 1 ]  // sha256
        algorithm: [ 1, 3, 14, 3, 2, 26 ]  // sha1
      },
      issuerNameHash: sha1(rfc5280.Name.encode(tbsCert.issuer, 'der')),
      issuerKeyHash: sha1(
        tbsIssuer.subjectPublicKeyInfo.subjectPublicKey.data),
      serialNumber: tbsCert.serialNumber
    };
  
    var tbs = {
      version: 'v1',
      requestList: [ {
        reqCert: certID
      } ],
      requestExtensions: [ {
        extnID: rfc2560['id-pkix-ocsp-nonce'],
        critical: false,
        extnValue: rfc2560.Nonce.encode(crypto.randomBytes(16), 'der')
      } ]
    };
  
    var req = {
      tbsRequest: tbs
    };
  
    return {
      id: sha1(rfc2560.CertID.encode(certID, 'der')),
      certID: certID,
      data: rfc2560.OCSPRequest.encode(req, 'der'),
  
      // Just to avoid re-parsing DER
      cert: cert,
      issuer: issuer
    };
};


function parseResponse(raw) {
    var body = { start: 0, end: raw.length };
    var response = rfc2560.OCSPResponse.decode(raw, 'der', {
      track: function(key, start, end, type) {
        if (type !== 'content' || key !== 'responseBytes/response')
          return;
        body.start = start;
        body.end = end;
      }
    });
  
    var status = response.responseStatus;
    if (status !== 'successful')
      throw new Error('Bad OCSP response status: ' + status);
  
    // Unknown response type
    var responseType = response.responseBytes.responseType;
    if (responseType !== 'id-pkix-ocsp-basic')
      throw new Error('Unknown OCSP response type: ' + responseType);
  
    var bytes = response.responseBytes.response;
  
    var tbs = { start: body.start, end: body.end };
    var certsTbs = [];
    var basic = rfc2560.BasicOCSPResponse.decode(bytes, 'der', {
      track: function(key, start, end, type) {
        if (type !== 'tagged')
          return;
  
        if (key === 'tbsResponseData') {
          tbs.start = body.start + start;
          tbs.end = body.start + end;
        } else if (key === 'certs/tbsCertificate') {
          certsTbs.push({ start: body.start + start, end: body.start + end });
        }
      }
    });
  
    var OCSPSigning = exports['id-kp-OCSPSigning'].join('.');
    var certs = (basic.certs || []).filter(function(cert) {
      return cert.tbsCertificate.extensions.some(function(ext) {
        if (ext.extnID !== 'extendedKeyUsage')
          return false;
  
        return ext.extnValue.some(function(value) {
          return value.join('.') === OCSPSigning;
        });
      });
    });
  
    return {
      start: tbs.start,
      end: tbs.end,
      value: basic,
      certs: certs,
      certsTbs: certsTbs
    };
};