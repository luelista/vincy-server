var net = require("net"),
    tls = require("tls"),
    fs = require("fs"),
    BinaryBuffer = require("./binaryBuffer"),
    Put = require("put"),
    crypto = require("crypto")
    ping = require("ping"),
    wol = require("wake_on_lan");


console.log("\n---------------------------------------------\n\
vincy-server 0.0.1\n\
Copyright (c) 2014 Max Weller\n\
This program comes with ABSOLUTELY NO WARRANTY; This is free software, and\n\
you are welcome to redistribute it under certain conditions; see LICENSE\n\
file in this folder for details.\n\
---------------------------------------------\n\
");

var confDir = process.env.VINCY_DIR || "./config";

if (!fs.existsSync(confDir+"/config.json")) fs.writeFileSync(confDir+"/config.json", '{\n"listen_port": 44711\n}\n');
if (!fs.existsSync(confDir+"/authorized_clients")) fs.writeFileSync(confDir+"/authorized_clients", '# put client keys in this file\n\n\n');
if (!fs.existsSync(confDir+"/vincypasswd")) fs.writeFileSync(confDir+"/vincypasswd", '# User\tPassword Hash\tAllowed Hosts\n\n\n');
if (!fs.existsSync(confDir+"/hostlist.txt")) fs.writeFileSync(confDir+"/hostlist.txt", '# hostlist.txt\n\n\n');


config = {};
try {
  config = JSON.parse(fs.readFileSync(confDir+"/config.json"));
}catch(Ex) {}

if (process.argv.length == 3 && process.argv[2] == "-hostlist") {
  printHostlist();
  return;
}

var pingInterval = config.ping_interval || 120000;
var pingResults = {};

var currConns = {};

var tlsOptions = {
  key: fs.readFileSync(confDir + "/server-key.pem"),
  cert: fs.readFileSync(confDir + "/server-cert.pem")
};

var server = tls.createServer(tlsOptions, function(cleartextStream) {
  console.log("------------------------");
  var client = {};
  var hostlist;
  
  cleartextStream.on("error", function(err) {
    console.log("Stream error: "+err);
  })
  
  var ws = new BinaryBuffer(cleartextStream);
  ws.maxLength = 0xFFFF;
  ws.request(12, function(versionStr) {
    var vrstr = versionStr.toString("ascii");
    if (vrstr.match("VINCY-(......)")) {
      client.version = vrstr;
      ws.request("word", function(uaLength) {
        ws.request(uaLength, function(uaBuf) {
          client.ua = uaBuf.toString("ascii");
          console.log("Protocol version: "+vrstr+" UA: "+client.ua);
          cleartextStream.write(new Buffer("VINCY-SERVER\x00\x00\x00\x04")); 
          ws.request(66, function(clientKey){
            client.clientKey = clientKey.toString("ascii", 2);
            if(checkClientKey(client.clientKey)) {
              requestAuth();
            } else {
              sendErrmes("Client not known yet.");
              fs.appendFileSync("/tmp/vincy.log", new Date()+"\t"+client.ua+"\t"+"-"+"\t"+getRemoteEnd()+"\t"+"LoginAttempt"+"\t"+client.ua+"\t"+client.clientKey+"\n");
              cleartextStream.end();
            }
          })
        });
      });
      
    } else {
      console.log("invalid magic str: "+vrstr);
      sendErrmes("Invalid magic str.");
      cleartextStream.pause();
      cleartextStream.end();
    }
  });
  
  ws.debugName="-> ws";
  
  function requestAuth() {
    ws.request(4, function(buf) {
      var reserved1 = buf.readUInt16BE(0),
          authLen = buf.readUInt16BE(2);
      ws.request(authLen, function(buf) {
        var auth = buf.toString("ascii").split(/:/, 2);
        if (auth.length==2) {
          var user=auth[0], pass=auth[1];
          var shasum = crypto.createHash('sha1');
          var passHash = shasum.update(pass).digest('hex');
          var users = getUserlist();
          for(var i = 0; i<users.length; i++) {
            if (users[i].username == user && users[i].password == passHash) {
              Put().word16le(0).write(cleartextStream);
              client.user = users[i];
              hostlist = getHostlist();
              authSuccess();
              return;
            }
          }
        }
        fs.appendFileSync("/tmp/vincy.log", new Date()+"\t"+"-"+"\t"+getRemoteEnd()+"\t"+"LoginFailed"+"\t"+client.ua+"\t"+buf.toString("ascii")+"\t"+client.clientKey+"\n");
        sendErrmes("Invalid username or password.");
      })
    })
  }
  
  function sendErrmes(str, andClose) {
    try {
      var errMes = new Buffer(str);
      Put().word16be(errMes.length).put(errMes).write(cleartextStream);
      if (andClose)  cleartextStream.end();
    } catch(ex) { console.log("Error sending error message ''"+str+"'': "+ex); }
  }
  function sendErrmesVNC(str) {
    try {
      var errMes = new Buffer(str);
      Put().word32be(1).word32be(errMes.length).put(errMes).write(cleartextStream);
    } catch(ex) { console.log("Error sending VNC error message ''"+str+"'': "+ex); }
  }
  
  function authSuccess() {
    ws.request(4, function(buf) {
      var command = buf.readUInt16BE(0), argLen = buf.readUInt16BE(2);
      ws.request(argLen, function(buf) {
        var cmdArg = buf.toString("ascii");
        switch(command) {
        case 0x01:
          //retrieve hostlist
          cmd_hostlist();
          break;
        case 0x02:
          //end();
          cmd_connectVnc(this, cmdArg);
          break;
        case 0x03:
          cmd_sendWakeonlan(cmdArg);
          break;
        default:
          sendErrmes("Unknown command.", true);
          break;
        }
      })
    })
  }
  
  function isAuthorized(host) {
    return (client.user.allowedhosts.indexOf(host.id) > -1 ||
        client.user.allowedhosts.indexOf("%"+host.group) > -1);
  }
  function getHostById(id) {
    for(var i in hostlist ) {
      var host = hostlist[i];
      if(host.id==id) {
        return host;
      }
    }
    return null;
  }
  function getRemoteEnd() {
    return cleartextStream.remoteAddress+":"+cleartextStream.remotePort;
  }
  function writeAuditLog(action,param) {
    fs.appendFileSync("/tmp/vincy.log", new Date()+"\t"+client.user.username+"\t"+getRemoteEnd()+"\t"+action+"\t"+client.ua+"\t"+param+"\n");
  }
  
  function cmd_hostlist() {
    var out = "";
    for(var i in hostlist ) {
      var d = hostlist[i];
      if (!isAuthorized(d)) continue;
      out += d.id+"\t"+d.hostname+"\t"+d.group+"\t"+pingResults[d.id]+"\t"+d.macaddress+"\t"+d.comment+"\n";
    }
    var outBuf = new Buffer(out);
    Put().word16be(0).word16be(outBuf.length).put(outBuf).write(cleartextStream);
    cleartextStream.end();
  }
  
  function cmd_sendWakeonlan(targetId) {
    var host = getHostById(targetId);
    
    if(!host)               { sendErrmes("Host not found.", true); return; }
    if(!isAuthorized(host)) { sendErrmes("Forbidden.", true); return; }
    if(!host.macaddress || host.macaddress.length<12) { sendErrmes("Internal error", true); return; }
    
    writeAuditLog("WakeOnLan", targetId);
    
    wol.wake(host.macaddress, function(error) {
      if (error) {
        sendErrmes("Wake on lan failed: "+error, true);
      } else {
        try {
          Put().word16be(0x00).write(cleartextStream); //tell the vincy client everything's fine
          cleartextStream.end();
        } catch(ex) {console.log("Error sending success message:"+ex);}
      }
    });
  }
  
  function cmd_connectVnc(ws, targetId) {
    var host = getHostById(targetId);
    
    if(!host)               { sendErrmes("Internal error.", true); return; }
    if(!isAuthorized(host)) { sendErrmes("Forbidden.", true); return; }
    
    writeAuditLog("ConnectVNC", targetId);
    
    startVncPipe(host);
    
  }
  
  var connKeyCounter = 1;
  function startVncPipe(host) {
    var connKey = ++connKeyCounter;
    currConns[connKey] = { to: host.id, from: client.user.username+'@'+getRemoteEnd(), start: new Date() };
    
    console.log("starting vnc connection to "+host.hostname+":"+host.vncport);
    var sTarget = net.connect(host.vncport, host.hostname, function() {
      console.log("vnc connection established");
    });
    sTarget.on("error", function(err) {
      sendErrmes("Network error: "+err); tearDown();
    });
    
    function tearDown() {
      console.log("Tearing down connection"); delete currConns[connKey]; writeAuditLog("TearDown", host.id);
      sTarget.end(); cleartextStream.end();
    }
    
    var bbTarget = new BinaryBuffer(sTarget);
    bbTarget.request(12, function(prelude) {
      console.log("received server prelude:"+prelude);
    
      Put().word16be(0x00).write(cleartextStream); //tell the vincy client everything's fine
      
      Put().put(prelude).write(cleartextStream); //pass the prelude received from targetserver to client
      
      ws.request(12, function(prelude2) {
        console.log("received client prelude: "+prelude2);
        var clientPrelude = prelude2.toString("ascii").trim(),
            oldClient = (clientPrelude == "RFB 003.003" || clientPrelude == "RFB 003.007");
        
        Put().put(prelude2).write(sTarget); //pass the prelude from client to the targetserver
        
        if (oldClient) { //f*cking borked apple vnc client!
          var emptyChallenge = new Buffer(16); emptyChallenge.fill(0);
          Put().word32be(0x02).put(emptyChallenge).write(cleartextStream); //tell the client what sectype to use
          ws.request(16, function(throwAway) {
            //Put().word32be(0x00).write(cleartextStream); //say login is ok (not checking...)
            bbTarget.request("dword", function(secType) {  //ask server what secType to use (old rfb protocol...)
              if (secType != 0x02) {
                console.log("server decided to use unsupported sectype", secType); 
                sendErrmesVNC("server decided to use unsupported sectype"); tearDown(); return;
              }
              secContinue();
            });
          });
        } else {
          Put().word8be(1).word8be(1).write(cleartextStream); //tell the client the available sectypes (only 0x01)
          ws.request("byte", function(secType) {
            if (secType == 1) {
              bbTarget.request("byte", function(secTypeLen) {  //receive supported sectypes from targetserver
                bbTarget.request(secTypeLen, function(secTypeArray) {
                  Put().word8be(2).write(sTarget); //tell the targetserver to use sectype 0x02=vnc auth
                  secContinue();
                });
              });
            } else {
              console.log("client decided to use unsupported sectype", secTypeToUse); 
              sendErrmesVNC("client decided to use unsupported sectype"); tearDown(); return;
            }
          });
        }
        function secContinue() {
          bbTarget.request(16, function(challenge) {
            var response = require('./d3des').response(challenge, host.vncpassword);
            sTarget.write(response);
            bbTarget.request("dword", function(secResponse) {
              // received securityResponse 0x01 ? ...so there is an error
              if (secResponse == 1 ) {
                console.log("security fail from targetserver", secResponse); 
                bbTarget.request("dword", function(secErrLen) {
                  bbTarget.request(secErrLen, function(secErr) {
                    console.log("sec err:", secErr.toString());
                    sendErrmesVNC(secErr.toString());
                    tearDown(); 
                  })
                })
                
                return;
              }
              Put().word32be(0).write(cleartextStream); 
                      //send the securityResponse 0x00 - this means everything all right
              
              ws.stopListening();
              bbTarget.stopListening();
    
              cleartextStream.write(bbTarget.buffer);
              sTarget.write(ws.buffer);
              
              cleartextStream.pipe(sTarget);
              sTarget.pipe(cleartextStream);
            })
          });
        }
      });
    });
    bbTarget.debugName="<- vncServer";
  }
});
server.on("error", function(err) {
  console.log("Server error: ",err);
})

function getHostlist() {
  var hostlist = fs.readFileSync(confDir + '/hostlist.txt').toString().split(/\n/);
  var hosts = [];
  for(var i in hostlist) {
    if (/^(#.*)?$/.test(hostlist[i])) continue;
    var h = hostlist[i].split(/\t/);
    hosts.push({ 'id': h[0], 'hostname': h[1], 'group': h[2], 'vncport': h[3], 'vncpassword': h[4], 
    'macaddress': h[5]?h[5]:"", 'comment': h[8]?h[8]:'' });
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
function checkClientKey(key) {
  if (key.length != 64) return false;
  var list = fs.readFileSync(confDir + '/authorized_clients').toString().split(/\n/);
  for(var i in list) {
    if (/^(#.*)?$/.test(list[i])) continue;
    var h = list[i].split(/\t/);
    if (key == h[0]) return true;
  }
  return false;
}

server.listen(config.listen_port || 44711);
console.log("Listening on "+(config.listen_port || 44711));

function printHostlist() {
  var h = getHostlist();
  console.log(h.map(function(x){return x.id;}).join(","));
  
}

function doPingProbe() {
  var hosts = getHostlist();
  hosts.forEach(function (host) {
    ping.sys.probe(host.hostname, function(isAlive){
      var msg =new Date()+"\t"+ host.id + "\t" +(isAlive ? 'online' : 'n/a');
      if (isAlive !== pingResults[host.id]) {
        fs.appendFileSync('/tmp/pingprobes.log', msg+"\n"); console.log(msg);
      }
      pingResults[host.id] = isAlive;
    });
  });
}

setInterval(function() {
  doPingProbe();
}, pingInterval);

setTimeout(function() {
  doPingProbe();
}, 4000);


