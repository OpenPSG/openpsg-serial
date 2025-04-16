// OpenPSG Serial Protocol for Web Browsers (TypeScript)
//
// This file provides a TypeScript implementation of the OpenPSG serial protocol
// suitable for use in web-based applications (e.g., over Web Serial API).
//
// The OpenPSG serial protocol consists of the following message structure:
//
// | Field      | Size (bytes) | Description                                |
// |-----------|-------------|----------------------------------------------|
// | Address   | 8           | Unique identifier for the recipient device   |
// | Flags     | 1           | Message flags (e.g., request/response)       |
// | Command   | 1           | Command identifier                           |
// | Data      | N           | Variable-length payload data                 |
// | CRC       | 2           | CRC-16 checksum for integrity validation     |
// | END       | 1           | Message delimiter                            |
//
// - The message is encoded in big-endian format.
// - The CRC is computed over all fields except the CRC itself.
// - Flags indicate whether the message is a request (0) or a response (0x80).
// - Commands define specific operations, such as reading/writing registers.
// - The END byte (0xC0) is used as a message delimiter.
//
// ## Escaping
//
// To avoid confusion with the `END` and `ESC` bytes during transmission, those
// values are escaped:
//
// - `END (0xC0)` becomes `ESC (0xDB) + ESC_END (0xDC)`
// - `ESC (0xDB)` becomes `ESC (0xDB) + ESC_ESC (0xDD)`
//
// ## Commands
//
// | Command  | Code | Description                      | Payload Format      |
// |----------|------|----------------------------------|---------------------|
// | Reset    | 0x00 | Resets the device                | None                |
// | Ping     | 0x01 | Health check                     | None                |
// | Read     | 0x02 | Reads from a register            | [`ReadPayload`]     |
// | Write    | 0x03 | Writes to a register             | [`DataPayload`]     |
// | SetTime  | 0x04 | Sets the system time             | [`TimePayload`]     |
// | ReadMany | 0x05 | Read multiple values from a FIFO | [`ReadManyPayload`] |
//
// Responses to `Read` and `Write` commands may also use [`DataPayload`] as a payload.
//
// ## Error Handling
//
// If a message results in an error, the response will contain:
//
// - `Flags::Response | Flags::Error`
// - `command` equal to the original command
// - A payload of type [`ErrorPayload`] containing an error code and optional message.
//
// ## Payloads
//
// ### ErrorPayload
//
// This payload contains an error code and an optional error message.
//
// | Field    | Size (bytes) | Description              |
// |----------|--------------|--------------------------|
// | Code     | 1            | Error code               |
// | Message  | N            | Optional error message   |
//
// ### ReadPayload
//
// This payload contains the register address that the sender wants to read from
//
// | Field    | Size (bytes) | Description              |
// |----------|--------------|--------------------------|
// | Register | 2            | Big-endian register ID   |
//
// # DataPayload
//
// The payload used for `Write` command requests and `Read` command responses.
//
// It includes both the register address and the associated data bytes.
//
// | Field    | Size (bytes) | Description              |
// |----------|--------------|--------------------------|
// | Register | 2            | Big-endian register ID   |
// | Value    | N            | Data bytes               |
//
// ### TimePayload
//
// This payload contains a UTC timestamp in seconds since the Unix epoch
// and the microseconds part.
//
// | Field       | Size (bytes) | Description              |
// |-------------|--------------|--------------------------|
// | Timestamp   | 8            | Big-endian timestamp     |
// | Microseconds| 4            | Big-endian microseconds  |

// Message framing delimiters/escape characters
const END = 0xc0;
const ESC = 0xdb;
const ESC_END = 0xdc;
const ESC_ESC = 0xdd;

const MAX_MESSAGE_SIZE = 256; // Total including all fields
const MESSAGE_HEADER_SIZE = 10; // Address (8) + Flags (1) + Command (1)
const MAX_PAYLOAD_SIZE = MAX_MESSAGE_SIZE - MESSAGE_HEADER_SIZE;

// Well known registers
// These are common registers that should be implemented by all devices
export const REGISTER_VENDOR_ID = 0x0000; // 16-bit vendor id
export const REGISTER_PRODUCT_ID = 0x0001; // 16-bit product id
export const REGISTER_DEVICE_NAME = 0x0002; // UTF-8 device name
export const REGISTER_FIRMWARE_VERSION = 0x0003; // UTF-8 firmware version

// Start of device-specific registers
export const REGISTER_DEVICE_START = 0x1000;

// Serial commands
export enum Command {
  // Reset the device
  Reset = 0x00,
  // Ping the device
  Ping = 0x01,
  // Read a register
  Read = 0x02,
  // Write to a register
  Write = 0x03,
  // Set the system time
  SetTime = 0x04,
  // Read multiple values from a FIFO
  ReadMany = 0x05,
}

// Message flags
export enum Flags {
  RESPONSE = 0x80,
  ERROR = 0x40,
}

// An OpenPSG device address
export class Address {
  constructor(public value: bigint) {}

  static fromString(mac: string): Address {
    const parts = mac.split(":").map((p) => parseInt(p, 16));
    if (parts.length !== 8) throw new Error("Invalid MAC-style address format");
    let val = BigInt(0);
    for (const byte of parts) {
      val = (val << BigInt(8)) | BigInt(byte);
    }
    return new Address(val);
  }

  toBytes(): Uint8Array {
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setBigUint64(0, this.value, false);
    return new Uint8Array(buffer);
  }

  static fromBytes(bytes: Uint8Array): Address {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return new Address(view.getBigUint64(0, false));
  }
}

// All devices on the network will respond to this address
export const BROADCAST_ADDRESS = Address.fromString("ff:ff:ff:ff:ff:ff:ff:ff");

// Standard error codes
export enum ErrorCode {
  // The requested command is not supported
  UnsupportedCommand = 0x01,
  // The register is not readable or does not exist
  InvalidRegister = 0x02,
  // Attempted to write to a read-only register
  WriteDenied = 0x03,
  // Payload data is malformed or incorrect length
  MalformedPayload = 0x04,
  // The operation failed due to an internal device error
  InternalError = 0x05,
  // Message timed out or device not responding
  Timeout = 0x06,
  // Command requires authentication or authorization
  Unauthorized = 0x07,
  // Message format violated protocol specification
  ProtocolViolation = 0x08,
}

// OpenPSG serial message payload types
export type Payload =
  | { type: "None" }
  | { type: "Error"; code: ErrorCode; message: string }
  | { type: "Read"; register: number }
  | { type: "Data"; register: number; value: Uint8Array }
  | { type: "Time"; timestamp: bigint; microseconds: number }
  | { type: "ReadMany"; register: number; count: number };

// OpenPSG serial messages
export class Message {
  constructor(
    public address: Address,
    public flags: number,
    public command: Command,
    public payload: Payload,
  ) {}

  isRequest(): boolean {
    return (this.flags & Flags.RESPONSE) === 0;
  }

  encode(): Uint8Array {
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
    buffer[offset++] = (crc >> 8) & 0xff;
    buffer[offset++] = crc & 0xff;

    return escape(buffer.subarray(0, offset));
  }

  static decode(input: Uint8Array): Message {
    const raw = unescape(input);
    const dataLen = raw.length - 2;
    const receivedCrc = (raw[dataLen] << 8) | raw[dataLen + 1];
    const calculatedCrc = crc16(raw.subarray(0, dataLen));
    if (receivedCrc !== calculatedCrc) throw new Error("CRC mismatch");

    const address = Address.fromBytes(raw.subarray(0, 8));
    const flags = raw[8];
    const command = raw[9] as Command;
    const payloadBytes = raw.subarray(10, dataLen);

    const payload = decodePayload(command, flags, payloadBytes);
    return new Message(address, flags, command, payload);
  }
}

function encodePayload(payload: Payload): Uint8Array {
  const buffer = new Uint8Array(MAX_PAYLOAD_SIZE);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  switch (payload.type) {
    case "None":
      return new Uint8Array();
    case "Error": {
      buffer[offset++] = payload.code as number;
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

function decodePayload(
  command: Command,
  flags: number,
  bytes: Uint8Array,
): Payload {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (flags & Flags.ERROR) {
    return {
      type: "Error",
      code: bytes[0],
      message: new TextDecoder().decode(bytes.subarray(1)),
    };
  }

  switch (command) {
    case Command.Reset:
    case Command.Ping:
      return { type: "None" };
    case Command.Read:
      return flags & Flags.RESPONSE
        ? {
            type: "Data",
            register: view.getUint16(0, false),
            value: bytes.subarray(2),
          }
        : { type: "Read", register: view.getUint16(0, false) };
    case Command.Write:
      return {
        type: "Data",
        register: view.getUint16(0, false),
        value: bytes.subarray(2),
      };
    case Command.SetTime:
      return {
        type: "Time",
        timestamp: view.getBigUint64(0, false),
        microseconds: view.getUint32(8, false),
      };
    case Command.ReadMany:
      return {
        type: "ReadMany",
        register: view.getUint16(0, false),
        count: view.getUint16(2, false),
      };
  }
}

function escape(input: Uint8Array): Uint8Array {
  const output: number[] = [];
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

function unescape(input: Uint8Array): Uint8Array {
  const output: number[] = [];
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

// Simple CRC-16 MODBUS implementation
function crc16(data: Uint8Array): number {
  let crc = 0xffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      if ((crc & 1) !== 0) crc = (crc >> 1) ^ 0xa001;
      else crc >>= 1;
    }
  }
  return ((crc << 8) | (crc >> 8)) & 0xffff; // convert to big-endian
}
