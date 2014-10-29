var net = require("net"),
    tls = require("tls"),
    fs = require("fs"),
    BinaryBuffer = require("./binaryBuffer"),
    Put = require("put"),
    crypto = require("crypto");


console.log("\n---------------------------------------------\n\
vincy-server 0.0.1\n\
Copyright (c) 2014 Max Weller\n\
This program comes with ABSOLUTELY NO WARRANTY; This is free software, and\n\
you are welcome to redistribute it under certain conditions; see LICENSE\n\
file in this folder for details.\n\
---------------------------------------------\n\
");

var confDir = process.env.VINCY_DIR || "./config";

var tlsOptions = {
  key: fs.readFileSync(confDir + "/server-key.pem"),
  cert: fs.readFileSync(confDir + "/server-cert.pem"),
  
};

var server = tls.createServer(tlsOptions, function(cleartextStream) {
  console.log("------------------------");
  var client = {};
  var hostlist;
  
  cleartextStream.on("error", function(err) {
    console.log("Stream error: "+err);
  })
  
  var ws = new BinaryBuffer(cleartextStream);
  ws.request(12, function(versionStr) {
    var vrstr = versionStr.toString("ascii");
    if (vrstr.match("VINCY-(......)")) {
      client.version = vrstr;
      ws.request("word", function(uaLength) {
        ws.request(uaLength, function(uaBuf) {
          client.ua = uaBuf.toString("ascii");
          console.log("Protocol version: "+vrstr+" UA: "+client.ua);
          cleartextStream.write(new Buffer("VINCY-SERVER")); 
          requestAuth();
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
        sendErrmes("Invalid username or password.");
      })
    })
  }
  
  function sendErrmes(str) {
    var errMes = new Buffer(str);
    Put().word16be(errMes.length).put(errMes).write(cleartextStream);
  }
  function sendErrmesVNC(str) {
    var errMes = new Buffer(str);
    Put().word32be(1).word32be(errMes.length).put(errMes).write(cleartextStream);
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
        default:
          sendErrmes("Unknown command.");
          break;
        }
      })
    })
  }
  
  function cmd_hostlist() {
    var out = "";
    for(var i in hostlist ) {
      if (client.user.allowedhosts.indexOf(hostlist[i].id) == -1) continue;
      out += hostlist[i].id+"\t"+hostlist[i].hostname+"\t"+hostlist[i].tunnel+"\t"+hostlist[i].comment+"\n";
    }
    var outBuf = new Buffer(out);
    Put().word16be(0).word16be(outBuf.length).put(outBuf).write(cleartextStream);
    cleartextStream.end();
  }
  
  function cmd_connectVnc(ws, targetId) {
    
    var out = "";
    for(var i in hostlist ) {
      var host = hostlist[i];
      if(host.id==targetId) {
        if (client.user.allowedhosts.indexOf(targetId) == -1 &&
            client.user.allowedhosts.indexOf("%"+host.group) == -1) {
          sendErrmes("Forbidden."); return;
        }
        Put().word16be(0x00).write(cleartextStream); //tell the vincy client everything's fine
        startVncPipe(host);
        
        return;
      }
    }
    sendErrmes("Internal error.");
  }
  
  function startVncPipe(host) {
    console.log("starting vnc connection to "+host.hostname+":"+host.vncport);
    var sTarget = net.connect(host.vncport, host.hostname, function() {
      console.log("vnc connection established");
    });
    sTarget.on("error", function(err) {
      sendErrmes("Network error: "+err); tearDown();
    });
    
    function tearDown() {
      console.log("Tearing down connection");
      sTarget.end(); cleartextStream.end();
    }
    
    var bbTarget = new BinaryBuffer(sTarget);
    bbTarget.request(12, function(prelude) {
      console.log("received server prelude:"+prelude);
      
      
      Put().put(prelude).write(cleartextStream); //pass the prelude received from targetserver to client
      
      ws.request(12, function(prelude2) {
        console.log("received client prelude: "+prelude2);
        var clientPrelude = prelude2.toString("ascii").trim(),
            oldClient = (clientPrelude == "RFB 003.003" || clientPrelude == "RFB 003.007");
        
        Put().put(prelude2).write(sTarget); //pass the prelude from client to the targetserver
        
        if (oldClient) { //f*cking borked apple vnc client!
          Put().word32be(0x02).put(new Buffer(16).fill(20)).write(cleartextStream); //tell the client what sectype to use
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


function getHostlist() {
  var hostlist = fs.readFileSync(confDir + '/hostlist.txt').toString().split(/\n/);
  var hosts = [];
  for(var i in hostlist) {
    if (/^(#.*)?$/.test(hostlist[i])) continue;
    var h = hostlist[i].split(/\t/);
    hosts.push({ 'id': h[0], 'hostname': h[1], 'group': h[2], 'vncport': h[3], 'vncpassword': h[4], 
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

