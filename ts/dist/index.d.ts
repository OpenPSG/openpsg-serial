declare const REGISTER_VENDOR_ID = 0;
declare const REGISTER_PRODUCT_ID = 1;
declare const REGISTER_DEVICE_NAME = 2;
declare const REGISTER_FIRMWARE_VERSION = 3;
declare const REGISTER_DEVICE_START = 4096;
declare enum Command {
    Reset = 0,
    Ping = 1,
    Read = 2,
    Write = 3,
    SetTime = 4,
    ReadMany = 5
}
declare enum Flags {
    RESPONSE = 128,
    ERROR = 64
}
declare class Address {
    value: bigint;
    constructor(value: bigint);
    static fromString(mac: string): Address;
    toBytes(): Uint8Array;
    static fromBytes(bytes: Uint8Array): Address;
}
declare const BROADCAST_ADDRESS: Address;
declare enum ErrorCode {
    UnsupportedCommand = 1,
    InvalidRegister = 2,
    WriteDenied = 3,
    MalformedPayload = 4,
    InternalError = 5,
    Timeout = 6,
    Unauthorized = 7,
    ProtocolViolation = 8
}
type Payload = {
    type: "None";
} | {
    type: "Error";
    code: ErrorCode;
    message: string;
} | {
    type: "Read";
    register: number;
} | {
    type: "Data";
    register: number;
    value: Uint8Array;
} | {
    type: "Time";
    timestamp: bigint;
    microseconds: number;
} | {
    type: "ReadMany";
    register: number;
    count: number;
};
declare class Message {
    address: Address;
    flags: number;
    command: Command;
    payload: Payload;
    constructor(address: Address, flags: number, command: Command, payload: Payload);
    isRequest(): boolean;
    encode(): Uint8Array;
    static decode(input: Uint8Array): Message;
}

export { Address, BROADCAST_ADDRESS, Command, ErrorCode, Flags, Message, type Payload, REGISTER_DEVICE_NAME, REGISTER_DEVICE_START, REGISTER_FIRMWARE_VERSION, REGISTER_PRODUCT_ID, REGISTER_VENDOR_ID };
