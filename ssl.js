/*********************************************

  Verify SSl Certificates
  Change string to file
  convert files from .pem to .der (vise versa)
  remove passcode on private keys

***********************************************/

var fs = require('fs');
var exec = require('child_process').exec;
var path = require('path');
var util = require('util');
var ssl = {};

/***************************************************************************************

  Changing a .pem to .der
  @param {string} file name of file to change must include .pem
  @prarm {string} give a file name to save the contents to must include .der
  @param {function} callback throw an error if command does not execute properly or null

******************************************************************************************/

ssl.toDER = function(file, derFileName, callback) {
  exec('openssl x509 -in ' + file + ' -outform der -out ' + derFileName, function(error) {
    if (error) return callback(error);
    callback(null);
  });
};

/***************************************************************************************

  Changing a .der to .pem
  @param {string} file name of file to change must include .der
  @prarm {string} give a file name to save the contents to must include .pem
  @param {function} callback throw an error if command does not execute properly or null

******************************************************************************************/

ssl.toPEM = function(file, pemFileName, callback) {
  exec('openssl x509 -in ' + file + ' -inform der -text -outform pem -out ' + pemFileName, function(error) {
    if (error) return callback(error);
    callback(null);
  });
};

/***************************************************************************************

  Simple command to verify a certificate
  **IMPORTANT NOTE CERTIFICATE MUST BE A .PEM FILE
  @param {string} file name of certificate must include .pem
  @param {function} callback throw an error if command does not execute properly or if the
                    certificate is not verified - if the certificate is verified it will
                    return a string.

******************************************************************************************/

ssl.verify = function(file, callback) {
  exec('openssl verify ' + file, function(error, stdout, stderr) {
    if (error || stderr) return callback(error || stderr, null);

    var remaining = stdout;
    var index = stdout.indexOf('\n');
    while (index > -1) {
      var line = remaining.substring(0, index);
      remaining = remaining.substring(index + 1);
      index = line.indexOf(' ');
      var firstWord = line.substring(0, index);

      if (firstWord === 'error') {
        return callback(line, null);
      }

      index = remaining.indexOf('\n');
    }

    callback(null, 'this certificate has been verified');
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
  if (typeof opts === 'function') {
    callback = opts;
    opts = {};
  }

  opts.newKeyName = opts.newKeyName || 'newPrivteKey.pem';
  opts.informExt = opts.informExt || 'PEM';
  opts.outformExt = opts.outformExt || 'PEM';

  var cmd = util.format('openssl rsa -passin pass:%s -inform %s -in %s -outform %s -out',
    pass,
    opts.informExt,
    file,
    opts.outformExt,
    opts.newKeyName);

  exec(cmd, function(error) {
    if (error) return callback(error);

    fs.readFile(opts.newKeyName, function(err, data) {
      if (err) return callback(err);
      fs.writeFile(file, data, function(err) {
        if (err) return callback(err);

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
  if (typeof opts === 'function') {
    callback = opts;
    opts = {};
  }

  opts.folderName = opts.folderName || 'temp';
  opts.name = opts.name || 'temp';
  opts.ext = opts.ext || '.pem';

  fs.mkdirSync(path.resolve(opts.folderName));

  fs.writeFile(opts.folderName + '/' + opts.name + opts.ext, string, function(err) {
    if (err) return callback(err, null);
    return callback(null, opts.name + opts.ext);
  });
};

module.exports = ssl;
