VERIFY-SSL
==========

Simple ssl certificate verification for node.js

## Docs
You can check out openssl documentatin at [openSSL] (http://www.openssl.org/docs/apps/openssl.html).

## Simple Usage

    var ssl = require('ssl');
    var cert = 'cert.pem';

    ssl.verify(cert, function(err, status) {
      if(err) {
        console.log(err);
      }
      console.log('this certificate is ok');
    });
