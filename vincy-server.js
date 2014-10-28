var net = require("net"),
    tls = require("tls"),
    fs = require("fs"),
    binary = require("binary"),
    Put = require("put"),
    crypto = require("crypto");



var confDir = process.env.VINCY_DIR || "./config";

var tlsOptions = {
  //key: fs.readFileSync(confDir + "/server-key.pem"),
  //cert: fs.readFileSync(confDir + "/server-cert.pem"),
  
};

var server = net.createServer(tlsOptions, function(cleartextStream) {
  console.log("------------------------");
  var client = {};
  var hostlist;
  
  cleartextStream.on("error", function(err) {
    console.log("Stream error: "+err);
  })
  
  var ws = binary()
  .buffer("versionStr", 12)
  .word16lu("uaLen").buffer("ua", "uaLen")
  .tap(function(v) {
    var vrstr = v.versionStr.toString("ascii");
    if (vrstr.match("VINCY-(......)")) {
      client.version = vrstr;
      client.ua = v.ua.toString("ascii");
      console.log("Protocol version: "+vrstr+" UA: "+client.ua);
      cleartextStream.write(new Buffer("VINCY-SERVER")); 
      requestAuth();
    } else {
      console.log("invalid magic str: "+vrstr);
      sendErrmes("Invalid magic str.");
      cleartextStream.pause();
      cleartextStream.end();
    }
  });
  ws.debugName="-> ws"
  
  function requestAuth() {
    ws.word16lu("reserved1")
    .word16lu("userLen").buffer("user", "userLen")
    .word16lu("passLen").buffer("pass", "passLen")
    .tap(function(v) {
      var user = v.user.toString("ascii"), pass = v.pass.toString("ascii");
      var shasum = crypto.createHash('sha1');
      var passHash = shasum.update(pass).digest('hex');
      var users = getUserlist();
      for(var i = 0; i<users.length; i++) {
        if (users[i].username == user && users[i].password == passHash) {
          Put().word16le(0).write(cleartextStream);
          client.user = users[i];
          authSuccess();
          return;
        }
      }
      sendErrmes("Invalid username or password.");
    });
  }
  
  function sendErrmes(str) {
    var errMes = new Buffer(str);
    Put().word16le(errMes.length).put(errMes).write(cleartextStream);
  }
  
  function authSuccess() {
    hostlist = getHostlist();
    ws//.loop(function(end, v) {
      //this
      .word16le("command")
      .word16le("argLen")
      .buffer("arg", "argLen")
      .tap(function(v) {
        var cmdArg = v.arg.toString("ascii");
        switch(v.command) {
        case 0x01:
          //retrieve hostlist
          cmd_hostlist();
          break;
        case 0x02:
          //end();
          cmd_connectVnc(this, cmdArg);
          break;
        default:
          sendErrmes("Unknown command.");
          break;
        }
      });
      //});
  }
  
  function cmd_hostlist() {
    var out = "";
    for(var i in hostlist ) {
      if (client.user.allowedhosts.indexOf(hostlist[i].id) == -1) continue;
      out += hostlist[i].id+"\t"+hostlist[i].hostname+"\t"+hostlist[i].tunnel+"\t"+hostlist[i].comment+"\n";
    }
    var outBuf = new Buffer(out);
    Put().word16le(0).word16le(outBuf.length).put(outBuf).write(cleartextStream);
  }
  
  function cmd_connectVnc(ws, targetId) {
    if (client.user.allowedhosts.indexOf(targetId) == -1) {
      sendErrmes("Forbidden."); return;
    }
    var out = "";
    for(var i in hostlist ) {
      var host = hostlist[i];
      if(host.id==targetId) {
        Put().word16le(0).write(cleartextStream);
        startVncPipe(host);
        
        return;
      }
    }
    sendErrmes("Internal error.");
  }
  
  function startVncPipe(host) {
    
    var newStream = net.connect(host.vncport, host.hostname);
    newStream.on("error", function(err) {
      sendErrmes("Network error: "+err);
    });
    
    var rfb = binary()
    .buffer("prelude", 12)
    .tap(function(v) {
      console.log("received server prelude:"+v.prelude);
      
      Put().put(v.prelude).write(cleartextStream);
      ws
      .buffer("prelude2", 12)
      .tap(function(v) {
        console.log("received client prelude: "+v.prelude2);
        Put().word8le(1).word8le(1).write(cleartextStream);
        Put().put(v.prelude2).write(newStream);
      });/*
      .word8lu("secType")
      .tap(function(v) {
        if (v.secType == 1) {
          Put().word32le(1).write(cleartextStream);
          
          rfb.word8le("secTypeLen").buffer("secTypes", "secTypeLen")
          .buffer("challenge", 16)
          .tap(function(v) {
            var response = require('./d3des').response(v.challenge, host.vncpassword);
            newStream.write(response);
            
          })
          .word32le("secResponse")
          tap(function(v) {
            newStream.unpipe();
            cleartextStream.unpipe();
            
            cleartextStream.write(rfb._internalBuffer.toBuffer());
            newStream.write(ws._internalBuffer.toBuffer());
            
            cleartextStream.pipe(newStream);
            newStream.pipe(cleartextStream);
          });
          
        }
      });*/
      
    });
    rfb.debugName="<- vncServer";
    newStream.pipe(rfb);
    
  }
  
  cleartextStream.pipe(ws);
});


function getHostlist() {
  var hostlist = fs.readFileSync(confDir + '/hostlist.txt').toString().split(/\n/);
  var hosts = [];
  for(var i in hostlist) {
    if (/^(#.*)?$/.test(hostlist[i])) continue;
    var h = hostlist[i].split(/\t/);
    hosts.push({ 'id': h[0], 'hostname': h[1], 'tunnel': h[2], 'vncport': h[3], 'vncpassword': h[4], 
    'macaddress': h[5], 'comment': h[8] });
  }
  return hosts;
}
function getUserlist() {
  var list = fs.readFileSync(confDir + '/vincypasswd').toString().split(/\n/);
  var users = [];
  for(var i in list) {
    if (/^(#.*)?$/.test(list[i])) continue;
    var h = list[i].split(/\t/);
    users.push({ 'username': h[0], 'password': h[1], 'allowedhosts': h[2].split(/,/) });
  }
  return users;
}

server.listen(9292);

