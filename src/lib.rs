//! OpenPSG Serial Format
//!
//! The OpenPSG serial protocol consists of the following message structure:
//!
//! | Field      | Size (bytes) | Description                                |
//! |-----------|-------------|----------------------------------------------|
//! | Address   | 8           | Unique identifier for the recipient device   |
//! | Flags     | 1           | Message flags (e.g., request/response)       |
//! | Command   | 1           | Command identifier                           |
//! | Data      | N           | Variable-length payload data                 |
//! | CRC       | 2           | CRC-16 checksum for integrity validation     |
//! | END       | 1           | Message delimiter                            |
//!
//! - The message is encoded in big-endian format.
//! - The CRC is computed over all fields except the CRC itself.
//! - Flags indicate whether the message is a request (0) or a response (0x80).
//! - Commands define specific operations, such as reading/writing registers.
//! - The END byte (0xC0) is used as a message delimiter.
//!
//! ## Escaping
//!
//! To avoid confusion with the `END` and `ESC` bytes during transmission, those
//! values are escaped:
//!
//! - `END (0xC0)` becomes `ESC (0xDB) + ESC_END (0xDC)`
//! - `ESC (0xDB)` becomes `ESC (0xDB) + ESC_ESC (0xDD)`
//!
//! ## Commands
//!
//! | Command  | Code | Description                      | Payload Format      |
//! |----------|------|----------------------------------|---------------------|
//! | Reset    | 0x00 | Resets the device                | None                |
//! | Ping     | 0x01 | Health check                     | None                |
//! | Read     | 0x02 | Reads from a register            | [`ReadPayload`]     |
//! | Write    | 0x03 | Writes to a register             | [`DataPayload`]     |
//! | SetTime  | 0x04 | Sets the system time             | [`TimePayload`]     |
//! | ReadMany | 0x05 | Read multiple values from a FIFO | [`ReadManyPayload`] |
//!
//! Responses to `Read` and `Write` commands may also use [`DataPayload`] as a payload.
//!
//! ## Error Handling
//!
//! If a message results in an error, the response will contain:
//!
//! - `Flags::Response | Flags::Error`
//! - `command` equal to the original command
//! - A payload of type [`ErrorPayload`] containing an error code and optional message.
//!
//! ## Payloads
//!
//! ### ErrorPayload
//!
//! This payload contains an error code and an optional error message.
//!
//! | Field    | Size (bytes) | Description              |
//! |----------|--------------|--------------------------|
//! | Code     | 1            | Error code               |
//! | Message  | N            | Optional error message   |
//!
//! ### ReadPayload
//!
//! This payload contains the register address that the sender wants to read from
//!
//! | Field    | Size (bytes) | Description              |
//! |----------|--------------|--------------------------|
//! | Register | 2            | Big-endian register ID   |
//!
//! # DataPayload
//!
//! The payload used for `Write` command requests and `Read` command responses.
//!
//! It includes both the register address and the associated data bytes.
//!
//! | Field    | Size (bytes) | Description              |
//! |----------|--------------|--------------------------|
//! | Register | 2            | Big-endian register ID   |
//! | Value    | N            | Data bytes               |
//!
//! ### TimePayload
//!
//! This payload contains a UTC timestamp in seconds since the Unix epoch
//! and the microseconds part.
//!     
//! | Field       | Size (bytes) | Description              |
//! |-------------|--------------|--------------------------|
//! | Timestamp   | 8            | Big-endian timestamp     |
//! | Microseconds| 4            | Big-endian microseconds  |
//!

#![cfg_attr(not(test), no_std)]


use core::convert::TryFrom;
use crc::{CRC_16_MODBUS, Crc};
use heapless::Vec;

#[cfg(not(feature = "defmt"))]
use bitflags::bitflags;
#[cfg(feature = "defmt")]
use defmt::bitflags;

pub const MAX_MESSAGE_SIZE: usize = 256; // Total including all fields
pub const MESSAGE_HEADER_SIZE: usize = 10; // Address (8) + Flags (1) + Command (1)
pub const MAX_PAYLOAD_SIZE: usize = MAX_MESSAGE_SIZE - MESSAGE_HEADER_SIZE;

const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_MODBUS);

pub const END: u8 = 0xC0;
const ESC: u8 = 0xDB;
const ESC_END: u8 = 0xDC;
const ESC_ESC: u8 = 0xDD;

/// Serial commands
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Command {
    /// Reset the device
    Reset = 0x00,
    /// Ping the device
    Ping = 0x01,
    /// Read a register
    Read = 0x02,
    /// Write to a register
    Write = 0x03,
    /// Set the system time
    SetTime = 0x04,
    /// Read multiple values from a FIFO
    ReadMany = 0x05,
}

impl TryFrom<u8> for Command {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Command::Reset),
            0x01 => Ok(Command::Ping),
            0x02 => Ok(Command::Read),
            0x03 => Ok(Command::Write),
            0x04 => Ok(Command::SetTime),
            0x05 => Ok(Command::ReadMany),
            _ => Err("Invalid command code"),
        }
    }
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> Self {
        cmd as u8
    }
}

bitflags! {
    /// Message flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Flags: u8 {
        const RESPONSE = 0x80;
        const ERROR    = 0x40;
    }
}

/// All devices on the network will respond to this address.
pub const BROADCAST_ADDRESS: Address = Address(0xFFFFFFFFFFFFFFFF);

/// An OpenPSG serial address
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Address(pub u64);

impl TryFrom<&str> for Address {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut addr: u64 = 0;
        let mut count = 0;

        for part in value.split(':') {
            if count >= 8 {
                return Err("Invalid MAC-style address format");
            }
            let byte = u8::from_str_radix(part, 16).map_err(|_| "Invalid hex byte")?;
            addr = (addr << 8) | byte as u64;
            count += 1;
        }

        if count != 8 {
            return Err("Invalid MAC-style address format");
        }

        Ok(Address(addr))
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, f: defmt::Formatter) {
        let bytes = self.0.to_be_bytes();
        defmt::write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7]
        );
    }
}

/// OpenPSG serial messages
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Message {
    pub address: Address,
    pub flags: u8,
    pub command: Command,
    pub data: Vec<u8, MAX_PAYLOAD_SIZE>,
}

impl Message {
    /// Encode a message into a byte array.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, &'static str> {
        let mut raw = [0u8; MAX_MESSAGE_SIZE];
        let mut i = 0;

        raw[i..i + 8].copy_from_slice(&self.address.0.to_be_bytes());
        i += 8;

        raw[i] = self.flags;
        i += 1;

        raw[i] = self.command.into();
        i += 1;

        if i + self.data.len() > raw.len() - 2 {
            return Err("Message too long");
        }

        raw[i..i + self.data.len()].copy_from_slice(&self.data);
        i += self.data.len();

        let crc = CRC16.checksum(&raw[..i]);
        raw[i..i + 2].copy_from_slice(&crc.to_be_bytes());
        i += 2;

        escape(&raw[..i], output)
    }

    /// Check if this message is a request
    pub fn is_request(&self) -> bool {
        !self.is_response()
    }

    /// Check if this message is a response
    pub fn is_response(&self) -> bool {
        Flags::from_bits_truncate(self.flags).contains(Flags::RESPONSE)
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = &'static str;

    /// Decode a byte array into a Message
    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let mut raw = [0u8; MAX_MESSAGE_SIZE];
        let len = unescape(input, &mut raw)?;

        if len < MESSAGE_HEADER_SIZE {
            return Err("Too short");
        }

        let address = Address(u64::from_be_bytes(raw[0..8].try_into().unwrap()));
        let flags = raw[8];
        let command = Command::try_from(raw[9])?;

        let data_len = len - 10;
        let data: Vec<u8, MAX_PAYLOAD_SIZE> = Vec::from_slice(&raw[10..10 + data_len]).unwrap();

        Ok(Message {
            address,
            flags,
            command,
            data,
        })
    }
}

fn escape(input: &[u8], output: &mut [u8]) -> Result<usize, &'static str> {
    let mut j = 0;
    for &b in input {
        if j >= output.len() - 2 {
            return Err("Buffer overflow");
        }
        match b {
            END => {
                output[j] = ESC;
                output[j + 1] = ESC_END;
                j += 2;
            }
            ESC => {
                output[j] = ESC;
                output[j + 1] = ESC_ESC;
                j += 2;
            }
            _ => {
                output[j] = b;
                j += 1;
            }
        }
    }
    if j >= output.len() {
        return Err("Buffer overflow");
    }
    output[j] = END;
    Ok(j + 1)
}

fn unescape(input: &[u8], output: &mut [u8]) -> Result<usize, &'static str> {
    let mut i = 0;
    let mut j = 0;

    while i < input.len() {
        match input[i] {
            END => break,
            ESC => {
                i += 1;
                if i >= input.len() {
                    return Err("Unescape error");
                }
                output[j] = match input[i] {
                    ESC_END => END,
                    ESC_ESC => ESC,
                    _ => return Err("Invalid escape"),
                };
            }
            _ => {
                output[j] = input[i];
            }
        }
        i += 1;
        j += 1;
    }

    if j < 2 {
        return Err("Message too short");
    }

    let data_len = j - 2;
    let received_crc = u16::from_be_bytes(output[data_len..j].try_into().unwrap());
    let crc = CRC16.checksum(&output[..data_len]);

    if crc != received_crc {
        return Err("CRC mismatch");
    }

    Ok(data_len)
}

/// Standard error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ErrorCode {
    /// The requested command is not supported.
    UnsupportedCommand = 0x01,
    /// The register is not readable or does not exist.
    InvalidRegister = 0x02,
    /// Attempted to write to a read-only register.
    WriteDenied = 0x03,
    /// Payload data is malformed or incorrect length.
    MalformedPayload = 0x04,
    /// The operation failed due to an internal device error.
    InternalError = 0x05,
    /// Message timed out or device not responding.
    Timeout = 0x06,
    /// Command requires authentication or authorization.
    Unauthorized = 0x07,
    /// Message format violated protocol spec.
    ProtocolViolation = 0x08,
}

impl TryFrom<u8> for ErrorCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(ErrorCode::UnsupportedCommand),
            0x02 => Ok(ErrorCode::InvalidRegister),
            0x03 => Ok(ErrorCode::WriteDenied),
            0x04 => Ok(ErrorCode::MalformedPayload),
            0x05 => Ok(ErrorCode::InternalError),
            0x06 => Ok(ErrorCode::Timeout),
            0x07 => Ok(ErrorCode::Unauthorized),
            0x08 => Ok(ErrorCode::ProtocolViolation),
            _ => Err("Invalid error code"),
        }
    }
}

pub const EMPTY_PAYLOAD: Vec<u8, MAX_PAYLOAD_SIZE> = Vec::new();

/// The payload of an error response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ErrorPayload<'a> {
    /// The error code.
    pub code: ErrorCode,
    /// An optional error message.
    pub message: &'a str,
}

impl From<ErrorPayload<'_>> for Vec<u8, MAX_PAYLOAD_SIZE> {
    fn from(payload: ErrorPayload) -> Self {
        let mut data = Vec::new();
        data.push(payload.code as u8).unwrap();
        data.extend_from_slice(payload.message.as_bytes()).unwrap();
        data
    }
}

impl<'a> TryFrom<&'a [u8]> for ErrorPayload<'a> {
    type Error = &'static str;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        let code = ErrorCode::try_from(input[0]).map_err(|_| "Invalid error code")?;

        Ok(ErrorPayload {
            code,
            message: core::str::from_utf8(&input[1..]).map_err(|_| "Invalid UTF-8")?,
        })
    }
}

/// Well known registers
/// These are common registers that should be implemented by all devices.
pub const REGISTER_VENDOR_ID: u16 = 0x0000; // 16-bit vendor id
pub const REGISTER_PRODUCT_ID: u16 = 0x0001; // 16-bit product id
pub const REGISTER_DEVICE_NAME: u16 = 0x0002; // UTF-8 device name
pub const REGISTER_FIRMWARE_VERSION: u16 = 0x0003; // 16-bit firmware version

/// Start of device-specific registers
pub const REGISTER_DEVICE_START: u16 = 0x1000;

/// The payload of a read request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadPayload {
    /// The register address to read
    pub register: u16,
}

impl ReadPayload {
    pub fn into_bytes(&self, output: &mut [u8]) {
        output[0..2].copy_from_slice(&self.register.to_be_bytes());
    }
}

impl From<ReadPayload> for Vec<u8, MAX_PAYLOAD_SIZE> {
    fn from(payload: ReadPayload) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&payload.register.to_be_bytes())
            .unwrap();
        data
    }
}

impl TryFrom<&[u8]> for ReadPayload {
    type Error = &'static str;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.len() != 2 {
            return Err("Invalid length");
        }

        Ok(ReadPayload {
            register: u16::from_be_bytes(input[0..2].try_into().unwrap()),
        })
    }
}

/// The payload of a write request or the payload of a read response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DataPayload<'a> {
    /// The register address to write / that was read from.
    pub register: u16,
    /// The data to write / that was read.
    pub value: &'a [u8],
}

impl From<DataPayload<'_>> for Vec<u8, MAX_PAYLOAD_SIZE> {
    fn from(payload: DataPayload) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&payload.register.to_be_bytes())
            .unwrap();
        data.extend_from_slice(payload.value).unwrap();
        data
    }
}

impl<'a> TryFrom<&'a [u8]> for DataPayload<'a> {
    type Error = &'static str;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        if input.len() < 3 {
            return Err("Invalid length");
        }

        Ok(DataPayload {
            register: u16::from_be_bytes(input[0..2].try_into().unwrap()),
            value: &input[2..],
        })
    }
}

/// The payload of a read many request.
/// This is used to read multiple values from a FIFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadManyPayload {
    /// The register address to read from.
    pub register: u16,
    /// The number of values to read.
    pub count: u16,
}

impl From<ReadManyPayload> for Vec<u8, MAX_PAYLOAD_SIZE> {
    fn from(payload: ReadManyPayload) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&payload.register.to_be_bytes())
            .unwrap();
        data.extend_from_slice(&payload.count.to_be_bytes())
            .unwrap();
        data
    }
}
impl TryFrom<&[u8]> for ReadManyPayload {
    type Error = &'static str;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.len() != 4 {
            return Err("Invalid length");
        }

        Ok(ReadManyPayload {
            register: u16::from_be_bytes(input[0..2].try_into().unwrap()),
            count: u16::from_be_bytes(input[2..4].try_into().unwrap()),
        })
    }
}

/// The payload of a time setting request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimePayload {
    /// The timestamp in UTC seconds since the Unix epoch.
    pub timestamp: u64,
    /// The microseconds part of the timestamp.
    pub microseconds: u32,
}

impl From<TimePayload> for Vec<u8, MAX_PAYLOAD_SIZE> {
    fn from(payload: TimePayload) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&payload.timestamp.to_be_bytes())
            .unwrap();
        data.extend_from_slice(&payload.microseconds.to_be_bytes())
            .unwrap();
        data
    }
}

impl TryFrom<&[u8]> for TimePayload {
    type Error = &'static str;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.len() != 12 {
            return Err("Invalid length");
        }

        Ok(TimePayload {
            timestamp: u64::from_be_bytes(input[0..8].try_into().unwrap()),
            microseconds: u32::from_be_bytes(input[8..12].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let msg = Message {
            address: Address::try_from("00:11:22:33:44:55:66:77").unwrap(),
            flags: 0, // Request
            command: Command::Write,
            data: DataPayload {
                register: 0x1234,
                value: &[0x01, 0x02, 0x03],
            }
            .into(),
        };

        let mut buffer = [0u8; MAX_MESSAGE_SIZE];
        let encoded_size = msg.encode(&mut buffer).expect("Encoding failed");
        let decoded: Message = buffer[..encoded_size].try_into().expect("Decoding failed");

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_invalid_command_code() {
        let invalid_code = 0xFF;
        assert!(Command::try_from(invalid_code).is_err());
    }
}
