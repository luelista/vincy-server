
function BinaryBuffer() {
  this.buffer = new Buffer();
  this.pendingBytes = 0;
  this.pendingCallback = null;
  
  this.write = function(data) {
    this.buffer = Buffer.concat(this.buffer, data);
    this.process();
  }
  
  this.request = function(bytes, callback) {
    this.pendingBytes = bytes;
    this.pendingCallback = callback;
    this.process();
  }
  
  this.process = function() {
    if (this.pendingCallback != null && this.pendingBytes >= this.buffer.length) {
      var result = this.buffer.slice(0, this.pendingBytes - 1);
      this.buffer = this.buffer.slice(this.pendingBytes);
      this.pendingCallback(result);
      this.pendingCallback = null;
      this.pendingBytes = 0;
    }
  }
  
}

