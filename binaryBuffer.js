
function BinaryBuffer(inStream) {
  this.buffer = new Buffer([]);
  this.pendingBytes = 0;
  this.pendingCallback = null;
  this.pendingType = "";
  this.inStream = inStream;
  this.onData = (function(data) {
    this.write(data);
  }.bind(this));
  if (inStream) {
    inStream.on('data', this.onData);
  }
}


BinaryBuffer.prototype.stopListening = function() {
  this.inStream.removeListener('data', this.onData);
}

BinaryBuffer.prototype.write = function(data) {
  this.buffer = Buffer.concat([this.buffer, data], this.buffer.length+data.length);
  console.log(this.debugName, this.buffer)
  this.process();
}

BinaryBuffer.prototype.request = function(bytes, callback) {
  if (typeof bytes == "string") {
    switch(bytes) {
    case "byte":
      this.pendingType = "readUInt8";
      this.pendingBytes = 1;
      break;
    case "word":
      this.pendingType = "readUInt16BE";
      this.pendingBytes = 2;
      break;
    case "dword":
      this.pendingType = "readUInt32BE";
      this.pendingBytes = 4;
      break;
    default:
      throw "BinaryBuffer: Invalid request type";
      break;
    }
  } else {
    this.pendingType = "";
    this.pendingBytes = bytes;
  }
  this.pendingCallback = callback;
  this.process();
}

BinaryBuffer.prototype.process = function() {
  //console.log("Buffer contents: ", this.buffer.length, this.buffer);
  if (this.pendingCallback != null && this.pendingBytes <= this.buffer.length) {
    console.log("Processing "+this.pendingBytes+" bytes as "+this.pendingType+": (str="+this.buffer.toString("ascii",0,this.pendingBytes).replace(/[^ a-zA-Z0-9:]/g, function(x){return "\\x"+x[0].charCodeAt(0).toString(16)})+")");
    var result = this.buffer.slice(0, this.pendingBytes);
    this.buffer = this.buffer.slice(this.pendingBytes);
    if (this.pendingType) {
      result = result[this.pendingType](0);
    }
    console.log("    ", result);
    this.pendingCallback(result);
    this.pendingCallback = null;
    this.pendingBytes = 0;
  }
}

module.exports = BinaryBuffer;