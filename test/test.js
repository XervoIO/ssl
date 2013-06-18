var ssl = require('../ssl');
var assert = require('assert');
var fs = require('fs');

var files = [];

var key = './privkey.pem';

var string = '-----BEGIN ENCRYPTED PRIVATE KEY-----' + '\n' +
'MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIXm2FMdwCVu8CAggA' + '\n' +
'MBQGCCqGSIb3DQMHBAgP5I+dolfZrwSCAoA2HFh8GO5T8OA0WapbPSL3v1UXRX2M' + '\n' +
'ObFN7wbc8ZE61Yoi9ZGBP9SOFakrOnUO6zHVE1laYdjFp3sJ8cZGu348Z4tjNTnu' + '\n' +
'bPKh5PeE6AJt0KCMRjkd42xLKEKL3b2+4BoxD/2dTTvFZImQO61j4YnOkd15JiYc' + '\n' +
'G5XOIwhRI54leezpUYZv6e3jfYj7bRAXEePY/yBY6xpwRv26uinQViTQ7V6sEex5' + '\n' +
'A5dTM+Z4Okf798PN65RIO1KjS57VNG/Eabgs/3gUInJ/Lep/ZOUq9JiNLvUqm1/p' + '\n' +
'F0mO/dMMM1JWa3PKBBUP7X1g1nahywBCf/n3gFmNiw96QGY6HRhMbbEs0y3pyVMk' + '\n' +
'PoES91op8mfZERZRnjcLjUq6QOFiGUDAdAHoiOO1sC1Q6RpwADK2Q4MfAu4VCle0' + '\n' +
'6iKd6+OcM87J0DDIAS0HgIIULdBLNYHI8F7q13keF1UqUK/lk5iKXWZVg3X/VGQV' + '\n' +
'wcGPkd64XezPBDrOzqSALzEz4ZvZ4oRBYgXSykMLgEtId6viH9adi8MC4WxB0qa8' + '\n' +
'6Efuufy1BjIySbCoK3q4tQRWmggsbKucQGCPZQ2aF2SNrP5FfwuHQMKbWM2wnBXD' + '\n' +
'bWMHQsBftaneso6tnEYxlDqJwLTLDmqp5NDOTFUIbx/htZZDQzduUdhbjTKFicym' + '\n' +
'kFURcnZF21iAa5jVgXkxMwsz2m50M99TFtGIrU/PHIVlhNqAAQPfOGPvs7MvIZqx' + '\n' +
'KfQDYg626gEI/uv/8Lune4gvgFH1mbwgdpaGVXT9iXwv1kghHk7l5IA1+dzMA/xx' + '\n' +
'myds9j7Yk08z06PRrNOIc55J9sXCnlQ6hhl113W/1hjlPetD26BpykIt' + '\n' +
'-----END ENCRYPTED PRIVATE KEY-----';

describe('ssl', function() {
  //---------------TEST FOR toFile(file,opts,callback)----------------------------
  // it('should create a new folder, and add the string in a file' , function(done) {
  //   if(fs.existsSync('./temp')) {
  //     files = fs.readdirSync('./temp');
  //     files.forEach(function(file, index) {
  //       console.log(file);
  //       fs.unlinkSync('./temp/' + file);
  //     });
  //       fs.rmdirSync('./temp');
  //     }
  //   ssl.toFile(string, function(err, file) {
  //     if(err) {
  //       console.log(err);
  //       done();
  //     }
  //     assert.equal('temp.pem', file, 'there should be a folder in test named temp with temp.pem in it.');
  //     done();
  //   });
  // });
  //-----------------TEST FOR removePassphrase(file, opts, callback)--------------------------
  it('should remove the given passphrase from the file and write it back to the original file', function(done) {
    var oldKey = '';
    var newKey = '';
    ssl.removePasspharse('./privkey.pem', 'foobar', function(err) {
      if(err){
        console.log('error in removePassphrase', err);
        //done();
      }
      console.log('reading...files....');
       fs.readFile('./privkey.pem', function(err, data) {
        if(err) {
          console.log(err);
          //done();
        }
        console.log(data.toString());
        oldKey = data.toString();
       });
       fs.readFile('./newPrivteKey.pem', function(err, data) {
        if(err) {
          console.log(err);
          //done();
        }
        console.log(data.toString());
        newKey = data.toString();
       });
    });
     assert.equal(oldKey, newKey, 'the contents of the two key files should be the same');
     done();
  });
  //-----------------TEST FOR verify(file, callback)--------------------------------------
  it('should verify the certificate given the file that has a passpharse removed', function(done) {
    var verifyBool = 'false';
    ssl.verify('./privKey.pem', function(err, results) {
      if(err) {
        return console.log('error on verify', err);
        done();
      }
      console.log(results);
      assert.equal(results, null, 'it should have verified the certificate');
      done();
    });
  });
  //-----------------TEST FOR toDER(file,derFileName,callback)----------------------------
  // it('should turn a .pem file to a .der file', function(done) {
  //   if(fs.existsSync('./test.der')) {
  //     fs.unlinkSync('./test.der');
  //   }
  //   var exists = 'false';
  //   ssl.toDER('./privkey.pem', 'test.der', function(err) {
  //     if(err) {
  //       console.log(err)
  //     }
  //    if(fs.existsSync('./test.der')) {
  //     exists = 'true';
  //    }
  //    assert.equal('true', exists, 'there should be a file named test.der');
  //   });
  // });
  //-----------------TEST FOR toPEM(file,derFileName,callback)----------------------------
});
