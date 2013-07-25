VERIFY-SSL
==========

SSL certificate verification for node.js

[![Build Status](https://travis-ci.org/onmodulus/ssl.png?branch=develop)](https://travis-ci.org/onmodulus/ssl)

## Docs
You can check out openssl documentation at [openSSL](http://www.openssl.org/docs/apps/openssl.html).

## Simple Usage

    var ssl = require('ssl');
    var cert = '';
    var key = 'key.pem';
    var pass = 'abcdefg';

    var str_cert = 'encrypted certificate';
    var opts {};
    opts.fileName = 'cert.pem';

    ssl.toFile(str_cert, function(err, file) {
      if(err) {
        return console.log(err)
      }
      cert = file;
    });

    ssl.verify(cert, function(err, status) {
      if(err) {
        return console.log(err);
      }
      return console.log('this certificate is ok');
    });

    var opts = {};
    opts.newkeyName = 'newKey.pem';
    ssl.removePassphrase(cert, pass, opts, function(err) {
      if(err) {
        return console.log(err);
      }
      return console.log('passphrase removed');
    });
