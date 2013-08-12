var fs = require('fs');
var exec = require('child_process').exec, child;
var ssl = {};
/*********************************************

  Verify SSl Certificates
  Change string to file
  convert files from .pem to .der (vise versa)
  remove passcode on private keys

***********************************************/

/***************************************************************************************

  Changing a .pem to .der
  @param {string} file name of file to change must include .pem
  @prarm {string} give a file name to save the contents to must include .der
  @param {function} callback throw an error if command does not execute properly or null

******************************************************************************************/
ssl.toDER = function(file, derFileName, callback) {
  exec('openssl x509 -in ' + file + ' -outform der -out ' + derFileName, function(error, stdout) {
    if(error) {
      callback(error);
    }
    console.log(file + ' was changed to ' + derFileName);
    callback(null);
  })
};

/***************************************************************************************

  Changing a .der to .pem
  @param {string} file name of file to change must include .der
  @prarm {string} give a file name to save the contents to must include .pem
  @param {function} callback throw an error if command does not execute properly or null

******************************************************************************************/

ssl.toPEM = function(file, pemFileName, callback) {
  exec('openssl x509 -in ' + file + ' -outform pem -out ' + pemFileName, function(error, stdout) {
    if(error) {
      callback(error);
    }
    callback(null);
  })
};

/***************************************************************************************

  Simple command to verify a certificate
  **IMPORTANT NOTE CERTIFICATE MUST BE A .PEM FILE
  @param {string} file name of certificate must include .pem
  @param {function} callback throw an error if command does not execute properly or if the
                    certificate is not verified - if the certificate is verified it will
                    return a string.

******************************************************************************************/

ssl.verify = function(caFile, file, callback) {
  exec('openssl verify -CAfile ' + caFile + ' ' + file, function(error, stdout, stderr) {
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
      if(firstWord === 'error' || firstWord === 'unable') {
        return callback(line, null);
      }
      index = remaining.indexOf('\n');
    }
    callback(null, "this certificate has been verified");
  });
};

/****************************************************************************************

  Simple command to remove a passphrase from a key and rewrites back to the original file
  @param  {string} file name of certificate must include extension
  @param  {string} pass key password
  @param  {object} opts optional parameters
  @config {string} [opts.newKeyName] specify the new files name with extension .pem or
                                     default to newPrivateKey.pem
  @config {string} [opts.inform]     specify the original key files extension or
                                     default to PEM
  @config {string} [opts.inform]     specify the new key files extension or
                                     default to PEM
  @param {function} callback throw an error if command does not execute properly, if there
                    is an error reading or writing the files

******************************************************************************************/


ssl.removePassphrase = function(file, pass, opts, callback) {
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
      return callback(error);
    }
    fs.readFile(opts.newKeyName, function(err, data) {
      if(err) {
        return callback('read file', err);
      }
      fs.writeFile(file, data, function(err) {
        if(err) {
          return callback('write file', err);
        }
        console.log('saved back to original file without passphrase');
        callback(null);
      });
    });
  });
};

/****************************************************************************************

  Simple command to write a string to a file to use the functions above
  @param  {string} string encrypted certificate or key
  @param  {object} opts optional parameters
  @config {string} [opts.folderName] specify the new folder name or
                                     default to temp
  @config {string} [opts.name]       specify the files name or
                                     default to temp
  @config {string} [opts.inform]     specify the files extension or
                                     default to .pem
  @param {function} callback throw an error if making folder or writing a file does or
                    returns the filename

******************************************************************************************/


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
      return callback(err, null);
    }
  })
    fs.writeFile(opts.folderName + '/' + opts.name + opts.ext, string, function(err) {
        if(err) {
          return callback(err, null);
        }
        return callback(null, opts.name + opts.ext);
    });
};


module.exports = ssl;