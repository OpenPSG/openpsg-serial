// src/index.ts
var END = 192;
var ESC = 219;
var ESC_END = 220;
var ESC_ESC = 221;
var MAX_MESSAGE_SIZE = 256;
var MESSAGE_HEADER_SIZE = 10;
var MAX_PAYLOAD_SIZE = MAX_MESSAGE_SIZE - MESSAGE_HEADER_SIZE;
var REGISTER_VENDOR_ID = 0;
var REGISTER_PRODUCT_ID = 1;
var REGISTER_DEVICE_NAME = 2;
var REGISTER_FIRMWARE_VERSION = 3;
var REGISTER_DEVICE_START = 4096;
var Command = /* @__PURE__ */ ((Command2) => {
  Command2[Command2["Reset"] = 0] = "Reset";
  Command2[Command2["Ping"] = 1] = "Ping";
  Command2[Command2["Read"] = 2] = "Read";
  Command2[Command2["Write"] = 3] = "Write";
  Command2[Command2["SetTime"] = 4] = "SetTime";
  Command2[Command2["ReadMany"] = 5] = "ReadMany";
  return Command2;
})(Command || {});
var Flags = /* @__PURE__ */ ((Flags2) => {
  Flags2[Flags2["RESPONSE"] = 128] = "RESPONSE";
  Flags2[Flags2["ERROR"] = 64] = "ERROR";
  return Flags2;
})(Flags || {});
var Address = class _Address {
  constructor(value) {
    this.value = value;
  }
  static fromString(mac) {
    const parts = mac.split(":").map((p) => parseInt(p, 16));
    if (parts.length !== 8) throw new Error("Invalid MAC-style address format");
    let val = BigInt(0);
    for (const byte of parts) {
      val = val << BigInt(8) | BigInt(byte);
    }
    return new _Address(val);
  }
  toBytes() {
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setBigUint64(0, this.value, false);
    return new Uint8Array(buffer);
  }
  static fromBytes(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return new _Address(view.getBigUint64(0, false));
  }
};
var BROADCAST_ADDRESS = Address.fromString("ff:ff:ff:ff:ff:ff:ff:ff");
var ErrorCode = /* @__PURE__ */ ((ErrorCode2) => {
  ErrorCode2[ErrorCode2["UnsupportedCommand"] = 1] = "UnsupportedCommand";
  ErrorCode2[ErrorCode2["InvalidRegister"] = 2] = "InvalidRegister";
  ErrorCode2[ErrorCode2["WriteDenied"] = 3] = "WriteDenied";
  ErrorCode2[ErrorCode2["MalformedPayload"] = 4] = "MalformedPayload";
  ErrorCode2[ErrorCode2["InternalError"] = 5] = "InternalError";
  ErrorCode2[ErrorCode2["Timeout"] = 6] = "Timeout";
  ErrorCode2[ErrorCode2["Unauthorized"] = 7] = "Unauthorized";
  ErrorCode2[ErrorCode2["ProtocolViolation"] = 8] = "ProtocolViolation";
  return ErrorCode2;
})(ErrorCode || {});
var Message = class _Message {
  constructor(address, flags, command, payload) {
    this.address = address;
    this.flags = flags;
    this.command = command;
    this.payload = payload;
  }
  isRequest() {
    return (this.flags & 128 /* RESPONSE */) === 0;
  }
  encode() {
    const buffer = new Uint8Array(MAX_MESSAGE_SIZE);
    let offset = 0;
    buffer.set(this.address.toBytes(), offset);
    offset += 8;
    buffer[offset++] = this.flags;
    buffer[offset++] = this.command;
    const payloadBytes = encodePayload(this.payload);
    buffer.set(payloadBytes, offset);
    offset += payloadBytes.length;
    const crc = crc16(buffer.subarray(0, offset));
    buffer[offset++] = crc >> 8 & 255;
    buffer[offset++] = crc & 255;
    return escape(buffer.subarray(0, offset));
  }
  static decode(input) {
    const raw = unescape(input);
    const dataLen = raw.length - 2;
    const receivedCrc = raw[dataLen] << 8 | raw[dataLen + 1];
    const calculatedCrc = crc16(raw.subarray(0, dataLen));
    if (receivedCrc !== calculatedCrc) throw new Error("CRC mismatch");
    const address = Address.fromBytes(raw.subarray(0, 8));
    const flags = raw[8];
    const command = raw[9];
    const payloadBytes = raw.subarray(10, dataLen);
    const payload = decodePayload(command, flags, payloadBytes);
    return new _Message(address, flags, command, payload);
  }
};
function encodePayload(payload) {
  const buffer = new Uint8Array(MAX_PAYLOAD_SIZE);
  const view = new DataView(buffer.buffer);
  let offset = 0;
  switch (payload.type) {
    case "None":
      return new Uint8Array();
    case "Error": {
      buffer[offset++] = payload.code;
      const msgBytes = new TextEncoder().encode(payload.message);
      buffer.set(msgBytes, offset);
      return buffer.subarray(0, offset + msgBytes.length);
    }
    case "Read": {
      view.setUint16(offset, payload.register, false);
      return buffer.subarray(0, 2);
    }
    case "Data": {
      view.setUint16(offset, payload.register, false);
      offset += 2;
      buffer.set(payload.value, offset);
      return buffer.subarray(0, offset + payload.value.length);
    }
    case "Time": {
      view.setBigUint64(offset, payload.timestamp, false);
      offset += 8;
      view.setUint32(offset, payload.microseconds, false);
      return buffer.subarray(0, 12);
    }
    case "ReadMany": {
      view.setUint16(offset, payload.register, false);
      offset += 2;
      view.setUint16(offset, payload.count, false);
      return buffer.subarray(0, 4);
    }
  }
}
function decodePayload(command, flags, bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (flags & 64 /* ERROR */) {
    return {
      type: "Error",
      code: bytes[0],
      message: new TextDecoder().decode(bytes.subarray(1))
    };
  }
  switch (command) {
    case 0 /* Reset */:
    case 1 /* Ping */:
      return { type: "None" };
    case 2 /* Read */:
      return flags & 128 /* RESPONSE */ ? {
        type: "Data",
        register: view.getUint16(0, false),
        value: bytes.subarray(2)
      } : { type: "Read", register: view.getUint16(0, false) };
    case 3 /* Write */:
      return {
        type: "Data",
        register: view.getUint16(0, false),
        value: bytes.subarray(2)
      };
    case 4 /* SetTime */:
      return {
        type: "Time",
        timestamp: view.getBigUint64(0, false),
        microseconds: view.getUint32(8, false)
      };
    case 5 /* ReadMany */:
      return {
        type: "ReadMany",
        register: view.getUint16(0, false),
        count: view.getUint16(2, false)
      };
  }
}
function escape(input) {
  const output = [];
  for (const byte of input) {
    switch (byte) {
      case END:
        output.push(ESC, ESC_END);
        break;
      case ESC:
        output.push(ESC, ESC_ESC);
        break;
      default:
        output.push(byte);
        break;
    }
  }
  output.push(END);
  return new Uint8Array(output);
}
function unescape(input) {
  const output = [];
  for (let i = 0; i < input.length; ++i) {
    const byte = input[i];
    if (byte === END) break;
    if (byte === ESC) {
      const next = input[++i];
      if (next === ESC_END) output.push(END);
      else if (next === ESC_ESC) output.push(ESC);
      else throw new Error("Invalid escape sequence");
    } else {
      output.push(byte);
    }
  }
  return new Uint8Array(output);
}
function crc16(data) {
  let crc = 65535;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      if ((crc & 1) !== 0) crc = crc >> 1 ^ 40961;
      else crc >>= 1;
    }
  }
  return (crc << 8 | crc >> 8) & 65535;
}
export {
  Address,
  BROADCAST_ADDRESS,
  Command,
  ErrorCode,
  Flags,
  Message,
  REGISTER_DEVICE_NAME,
  REGISTER_DEVICE_START,
  REGISTER_FIRMWARE_VERSION,
  REGISTER_PRODUCT_ID,
  REGISTER_VENDOR_ID
};
