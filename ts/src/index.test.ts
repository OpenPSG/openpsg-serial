import { describe, it, expect } from "vitest";
import {
  Address,
  Command,
  ErrorCode,
  Flags,
  Message,
  type Payload,
} from "./index";

describe("OpenPSG Protocol", () => {
  const deviceAddress = Address.fromString("01:23:45:67:89:ab:cd:ef");

  it("should encode and decode a Ping request correctly", () => {
    const msg = new Message(deviceAddress, 0x00, Command.Ping, { type: "None" });
    const encoded = msg.encode();
    const decoded = Message.decode(encoded);

    expect(decoded.address.value).toBe(deviceAddress.value);
    expect(decoded.flags).toBe(0x00);
    expect(decoded.command).toBe(Command.Ping);
    expect(decoded.payload.type).toBe("None");
  });

  it("should encode and decode a Read command", () => {
    const payload: Payload = { type: "Read", register: 0x1001 };
    const msg = new Message(deviceAddress, 0x00, Command.Read, payload);
    const encoded = msg.encode();
    const decoded = Message.decode(encoded);

    expect(decoded.command).toBe(Command.Read);
    expect(decoded.payload).toEqual(payload);
  });

  it("should encode and decode a Data response", () => {
    const payload: Payload = {
      type: "Data",
      register: 0x1002,
      value: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    };
    const msg = new Message(deviceAddress, Flags.RESPONSE, Command.Read, payload);
    const encoded = msg.encode();
    const decoded = Message.decode(encoded);

    expect(decoded.flags & Flags.RESPONSE).toBeTruthy();
    expect(decoded.payload.type).toBe("Data");
    expect((decoded.payload as any).register).toBe(0x1002);
    expect((decoded.payload as any).value).toEqual(payload.value);
  });

  it("should encode and decode an Error payload", () => {
    const errorPayload: Payload = {
      type: "Error",
      code: ErrorCode.InvalidRegister,
      message: "Bad register",
    };
    const msg = new Message(deviceAddress, Flags.RESPONSE | Flags.ERROR, Command.Read, errorPayload);
    const encoded = msg.encode();
    const decoded = Message.decode(encoded);

    expect(decoded.flags & Flags.ERROR).toBeTruthy();
    expect(decoded.payload.type).toBe("Error");
    expect((decoded.payload as any).code).toBe(ErrorCode.InvalidRegister);
    expect((decoded.payload as any).message).toBe("Bad register");
  });

  it("should encode and decode a SetTime message", () => {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const payload: Payload = {
      type: "Time",
      timestamp: now,
      microseconds: 123456,
    };
    const msg = new Message(deviceAddress, 0x00, Command.SetTime, payload);
    const encoded = msg.encode();
    const decoded = Message.decode(encoded);

    expect(decoded.payload.type).toBe("Time");
    expect((decoded.payload as any).timestamp).toBe(now);
    expect((decoded.payload as any).microseconds).toBe(123456);
  });

  it("should correctly escape and unescape END and ESC characters", () => {
    const payload: Payload = {
      type: "Data",
      register: 0x1004,
      value: new Uint8Array([0xc0, 0xdb, 0x00, 0x01]), // includes END and ESC
    };
    const msg = new Message(deviceAddress, 0x00, Command.Write, payload);
    const encoded = msg.encode();

    // Should contain ESC sequences
    expect(Array.from(encoded)).toContain(0xdb); // ESC
    expect(Array.from(encoded)).toContain(0xdc); // ESC_END
    expect(Array.from(encoded)).toContain(0xdd); // ESC_ESC

    const decoded = Message.decode(encoded);
    expect(decoded.payload.type).toBe("Data");
    expect((decoded.payload as any).value).toEqual(payload.value);
  });

  it("should detect CRC mismatch", () => {
    const msg = new Message(deviceAddress, 0x00, Command.Ping, { type: "None" });
    const encoded = msg.encode();
    encoded[encoded.length - 3] ^= 0xff; // Corrupt data before CRC

    expect(() => Message.decode(encoded)).toThrow("CRC mismatch");
  });
});
