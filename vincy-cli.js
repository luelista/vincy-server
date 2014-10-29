// vincy command-line client

var url = require("url"),
    BinaryBuffer = require("./binaryBuffer"),
    tls = require("tls"),
    net = require("net"),
    fs = require("fs");

var userVersion = "0.0.1", protoVersion = "000001"; 
var userAgent = "vincy-cli "+userVersion+"; "+require("os").type()+"; "+require("os").hostname();
function showVersionAndUsage() {
  
console.log("\n---------------------------------------------\n\
vincy-cli 0.0.1\n\
ViNCy - VNC Proxy, Command Line Client\n\n\
Copyright (c) 2014 Max Weller\n\
This program comes with ABSOLUTELY NO WARRANTY; This is free software, and\n\
you are welcome to redistribute it under certain conditions; see LICENSE\n\
file in this folder for details.\n\
---------------------------------------------\n\
\n\
\n\
Usage: node vincy-cli.js COMMAND [args]\n\
\n\
The commands are:\n\
    list          Lists all vincy hosts you are allowed to access\n\
    connect HOST  Establishes a VNC connection to HOST \n\
\n\
  -bm NAME     Access a server bookmarked with NAME\n\
  -url vincy://username:passw@host:ip  Access a server by url\n\
");
  
}

var confDir = process.env.VINCY_DIR || "./config",
config = {};
try {
  config = JSON.parse(fs.readFileSync(confDir+"/config.json"));
}catch(Ex) {}


function connect(vUrl, cb) {
  if (!vUrl) {
    console.log("Please configure a URL to connect to.\nFormat: vincy://username:password@server:port"); process.exit(111);
  }
  console.log("Connecting to "+vUrl.hostname+":"+vUrl.port);
  var stream = tls.connect({
    port: vUrl.port, host: vUrl.hostname,
    ca: [ fs.readFileSync("config/server-cert.pem") ],
    servername: "vincy-server"
  }, function() {
    var bin = new BinaryBuffer(stream);
    stream.write(new Buffer("VINCY-"+protoVersion, "ascii"));
    BinaryBuffer.writeVbStr(stream, userAgent, "ascii");
    bin.request(12, function(serverUa) {
      console.log("Server says: "+ serverUa, " Now authenticating...");
      stream.write(new Buffer(2).fill(0)); //reserved
      BinaryBuffer.writeVbStr(stream, vUrl.auth, "ascii");
      bin.request("word", function(authResponse) {
        if (authResponse == 0x00) {
          cb(stream, bin);
        } else {
          bin.request(authResponse, function(authErrMsg) {
            console.log("Auth error: "+authErrMsg);
            process.exit(403);
          });
        }
      })
      
      
    })
  })
  return stream;
}

function listHosts(vUrl, args) {
  connect(vUrl, function(stream, bin) {
    BinaryBuffer.writeWord(stream, 0x01);
    BinaryBuffer.writeVbStr(stream, "");
    bin.request(4, function(res) {
      var resLen = res.readUInt16BE(2);
      bin.request(resLen, function(hostlist) {
        console.log("Hostlist:");
        console.log(hostlist.toString());
      })
    })
  });
}

function connectHost(vUrl, args) {
  var hostId = args.rest[0];
  var somePort = args.named['-port'] || 49152+ (stringHashCode(hostId)%5000);
  net.createServer(function(localStream) {
    localStream.pause();
    
    //localStream.on("data", function(buf) { console.log("Data from vnc:",buf,""+buf) });
    var proxyStream = connect(vUrl, function(stream, bin) {
      localStream.on("end", function() {
        console.log("Connection gracefully closed.");
        process.exit(200);
      })
      //stream.on("data", function(buf) { console.log("Data from server:",buf,""+buf) });
      BinaryBuffer.writeWord(stream, 0x02);
      BinaryBuffer.writeVbStr(stream, hostId);
      bin.request("word", function(errLen) {
        if (errLen > 0) {
          bin.request(errLen, function(err) {
            console.log("ERROR: "+err);
            process.exit(500);
          });
          return;
        }

        bin.stopListening();

        localStream.write(bin.buffer);
        
        localStream.pipe(stream);
        stream.pipe(localStream);
      })
    });
    proxyStream.on("error", function(err) {
      console.log("ERROR in proxyConnection: "+ err);
      localStream.end();
    })
  }).listen(somePort);
  
  runVncViewer(somePort);
}



function runVncViewer(localPort) {
  console.log("Launching vnc viewer on local port :"+localPort+" ...");
  switch(process.platform) {
  case "darwin":
    require('child_process').spawn('/usr/bin/open', ['vnc://127.0.0.1:'+localPort], {detached:true}); break;
  case "win32":case "win64":
    require('child_process').spawn('tvnviewer.exe', ['127.0.0.1::'+localPort], {detached:true}); break;
  }
}


//--> Helper functions

var stringHashCode = function(str){
    var hash = 0;
    if (str.length == 0) return hash;
    for (i = 0; i < str.length; i++) {
        char = str.charCodeAt(i);
        hash = ((hash<<5)-hash)+char;
        hash = hash & hash; // Convert to 32bit integer
    }
    return hash;
}
function parseArgs(args, paramArgs, allAsNamed) {
  var boolArgs = {};
  for(var i = 0; i < args.length; i++) {
    var a = args[i];
    if (a.charAt(0)=='-' && (allAsNamed === true || paramArgs.hasOwnProperty(a))) paramArgs[a] = args[++i];
    else if (a.charAt(0)=='-') boolArgs[a] = boolArgs[a] ? boolArgs[a] + 1 : 1;
    else { args = args.slice(i); break; }
  }
  return { named: paramArgs, bool: boolArgs, rest: args };
}



//--> command dispatcher

function dispatch() {
  var command = "help", args = [];
  if (process.argv.length > 2) {
    command = process.argv[2]; args = process.argv.slice(3);
  }
  var a = parseArgs(args, {"-bm":null,"-url":null,"-port":null});
  var vUrlStr;
  if (a.named['-url']) {
    vUrlStr = a.named['-url'];
  } else if (a.named['-bm']) {
    vUrlStr = config.bookmarks[a.named['-bm']].url;
  } else {
    vUrlStr = process.env.VINCY_URL || (config.default && config.default.url);
  }
  var vUrl;
  try { vUrl = url.parse(vUrlStr); }catch(Ex) {console.log("This is no valid url: "+vUrlStr); }
  
  switch(command.toLowerCase()) {
  case "list":
    listHosts(vUrl, a);
    break;
  case "connect":
    connectHost(vUrl, a);
    break;
  case "help":
  default:
    showVersionAndUsage();
    break;
  }
}

dispatch();
