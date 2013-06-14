var fs = require('fs');
var exec = require('child_process').exec, child;
var ssl = {};


ssl.toDER = function(file, derFileName, callback) {
  exec('openssl x509 -in ' + file + ' -outform der -out ' + derFileName, function(error, stdout) {
    if(error) {
      callback(error);
    }
    console.log(file + ' was changed to ' + derFileName);
    callback(null);
  })
};

ssl.toPEM = function(file, pemFileName, callback) {
  exec('openssl x509 -in ' + file + ' -outform pem -out ' + pemFileName, function(error, stdout) {
    if(error) {
      callback(error);
    }
    callback(null);
  })
};

ssl.verify = function(file, callback) {
  exec('openssl verify ' + file, function(error, stdout, stderr) {
    if(error) {
      return callback(error, null);
    } else if (stderr){
      return callback(stderr, null);
    }
    var remaining = stdout;
    var index = stdout.indexOf('\n');
    while (index > -1) {
      var line = remaining.substring(0, index);
      remaining = remaining.substring(index + 1);
      index = line.indexOf(' ');
      var firstWord = line.substring(0, index);
      if(firstWord === 'error') {
        return callback(line);
      }
      index = remaining.indexOf('\n');
    }
    callback(null);
  })
};

ssl.removePasspharse = function(file, pass, opts, callback) {
  if(typeof opts === 'function') {
    callback = opts;
    opts = {};
  }
  opts.newKeyName = opts.newKeyName || 'newPrivteKey.pem';
  opts.informExt = opts.informExt || 'PEM';
  opts.outformExt = opts.outformExt || 'PEM';
  exec('openssl rsa -passin pass:' + pass + ' -inform  ' + opts.informExt + ' -in '+ file + ' -outform '+ opts.outformExt + ' -out ' +  opts.newKeyName
    , function(error, stdout) {
    if(error) {
      console.log('removePasspharse Error :', error);
      callback(error);
    }
    console.log('passphrase removed');
    fs.readFileSync('newPrivateKey.pem', function(err, data) {
      if(err) {
        return callback(err);
      }
      fs.writeFileSync(file, data, function(err) {
        if(err) {
          return callback(err);
        }
        return console.log('saved back to original file without passphrase');
      })
      return callback(null);
    })
  })
  return callback(null);
};


ssl.toFile = function(string, opts, callback) {
  if(typeof opts === 'function') {
    callback = opts;
    opts = {};
  }
  opts.folderName = opts.folderName || 'temp';
  opts.name = opts.name || 'temp';
  opts.ext = opts.ext || '.pem';
  fs.mkdirSync('./' + opts.folderName, function(err) {
    if(err) {
      return console.log(err);
    }
  })
    fs.writeFile(opts.folderName + '/' + opts.name + opts.ext, string, function(err) {
        if(err) {
          return callback(err, null);
        }
        return callback(null, opts.name + opts.ext);
    })
};


module.exports = ssl;