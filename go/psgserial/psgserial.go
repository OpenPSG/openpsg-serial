// Package psgserial implements the OpenPSG serial protocol.
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
//

package psgserial

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/sigurn/crc16"
)

// Serial commands
type Command byte

const (
	// CommandReset the device
	CommandReset Command = 0x00
	// CommandPing the device
	CommandPing Command = 0x01
	// CommandRead a register
	CommandRead Command = 0x02
	// CommandWrite to a register
	CommandWrite Command = 0x03
	// Set the system time
	CommandSetTime Command = 0x04
	// Read multiple values from a FIFO
	CommandReadMany Command = 0x05
)

func (c Command) String() string {
	switch c {
	case CommandReset:
		return "Reset"
	case CommandPing:
		return "Ping"
	case CommandRead:
		return "Read"
	case CommandWrite:
		return "Write"
	case CommandSetTime:
		return "SetTime"
	case CommandReadMany:
		return "ReadMany"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", byte(c))
	}
}

// Message flags
type Flags byte

const (
	FlagsResponse Flags = 0x80
	FlagsError    Flags = 0x40
)

func (f Flags) IsResponse() bool { return f&FlagsResponse != 0 }
func (f Flags) IsError() bool    { return f&FlagsError != 0 }

func (f Flags) String() string {
	if f.IsError() {
		return "Error"
	}
	if f.IsResponse() {
		return "Response"
	}
	return "Request"
}

// All devices on the network will respond to this address.
const BroadcastAddress Address = 0xFFFFFFFFFFFFFFFF

// An OpenPSG device address
type Address uint64

func (a *Address) UnmarshalText(b []byte) error {
	parts := strings.Split(string(b), ":")
	if len(parts) != 8 {
		return errors.New("invalid MAC-style address format")
	}
	*a = 0
	for _, part := range parts {
		var b byte
		_, err := fmt.Sscanf(part, "%02x", &b)
		if err != nil {
			return fmt.Errorf("invalid hex byte: %v", err)
		}
		*a = Address((uint64(*a) << 8) | uint64(b))
	}
	return nil
}

func (a Address) String() string {
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[7-i] = fmt.Sprintf("%02x", byte(a>>(i*8)))
	}
	return strings.Join(parts, ":")
}

func (a Address) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(a))
	return buf, nil
}

// Frame delimiters and escape sequences.
const (
	END     byte = 0xC0
	ESC     byte = 0xDB
	ESC_END byte = 0xDC
	ESC_ESC byte = 0xDD
)

const (
	// The fixed size of the message header in bytes.
	HEADER_SIZE = 10
)

// Message is the structure of a message sent to or received from the device.
type Message struct {
	Address Address
	Flags   Flags
	Command Command
	Payload Payload
}

func (m *Message) MarshalBinary() ([]byte, error) {
	marshaledAddress, err := m.Address.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal address: %w", err)
	}

	marshaledPayload, err := m.Payload.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	buf := new(bytes.Buffer)
	buf.Write(marshaledAddress)
	buf.WriteByte(byte(m.Flags))
	buf.WriteByte(byte(m.Command))
	buf.Write(marshaledPayload)

	crc := crc16.Checksum(buf.Bytes(), crc16.MakeTable(crc16.CRC16_MODBUS))
	if err := binary.Write(buf, binary.BigEndian, crc); err != nil {
		return nil, fmt.Errorf("failed to write CRC: %w", err)
	}

	escaped := escape(buf.Bytes())
	escaped = append(escaped, END)
	return escaped, nil
}

func (m *Message) UnmarshalBinary(data []byte) error {
	unescaped, err := unescape(data)
	if err != nil {
		return err
	}

	if len(unescaped) < HEADER_SIZE+2 {
		return errors.New("message too short")
	}

	header := unescaped[:HEADER_SIZE]
	payload := unescaped[HEADER_SIZE : len(unescaped)-2]
	crcReceived := binary.BigEndian.Uint16(unescaped[len(unescaped)-2:])
	crcCalculated := crc16.Checksum(unescaped[:len(unescaped)-2], crc16.MakeTable(crc16.CRC16_MODBUS))
	if crcReceived != crcCalculated {
		return errors.New("CRC mismatch")
	}

	addr := Address(binary.BigEndian.Uint64(header[0:8]))
	flags := Flags(header[8])
	cmd := Command(header[9])

	unmarshaledPayload, err := unmarshalPayload(cmd, flags, payload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	*m = Message{
		Address: addr,
		Flags:   flags,
		Command: cmd,
		Payload: unmarshaledPayload,
	}

	return nil
}

func (m *Message) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Address: %s\n", m.Address.String()))
	sb.WriteString(fmt.Sprintf("Flags: %02X\n", byte(m.Flags)))
	sb.WriteString(fmt.Sprintf("Command: %s\n", m.Command.String()))
	if m.Payload != nil {
		sb.WriteString(fmt.Sprintf("Payload: %v\n", m.Payload))
	}
	return sb.String()
}

func escape(input []byte) []byte {
	var out []byte
	for _, b := range input {
		switch b {
		case END:
			out = append(out, ESC, ESC_END)
		case ESC:
			out = append(out, ESC, ESC_ESC)
		default:
			out = append(out, b)
		}
	}
	return out
}

func unescape(input []byte) ([]byte, error) {
	var out []byte
	i := 0
	for i < len(input) {
		if input[i] == END {
			break
		} else if input[i] == ESC {
			i++
			if i >= len(input) {
				return nil, errors.New("unescape error")
			}
			switch input[i] {
			case ESC_END:
				out = append(out, END)
			case ESC_ESC:
				out = append(out, ESC)
			default:
				return nil, errors.New("invalid escape")
			}
		} else {
			out = append(out, input[i])
		}
		i++
	}
	return out, nil
}

// Payload Interface
type Payload interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	fmt.Stringer
}

func unmarshalPayload(command Command, flags Flags, bytes []byte) (Payload, error) {
	if flags.IsError() {
		var p ErrorPayload
		if err := p.UnmarshalBinary(bytes); err != nil {
			return nil, err
		}
		return &p, nil
	}

	if flags.IsResponse() {
		switch command {
		case CommandReset, CommandPing, CommandWrite, CommandSetTime:
			return &EmptyPayload{}, nil
		case CommandRead:
			var p DataPayload
			if err := p.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			return &p, nil
		case CommandReadMany:
			var p DataPayload
			if err := p.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			return &p, nil
		default:
			return nil, fmt.Errorf("unknown command: %s", command)
		}
	} else {
		switch command {
		case CommandReset, CommandPing:
			return &EmptyPayload{}, nil
		case CommandRead:
			var p ReadPayload
			if err := p.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			return &p, nil
		case CommandWrite:
			var p DataPayload
			if err := p.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			return &p, nil
		case CommandSetTime:
			var p TimePayload
			if err := p.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			return &p, nil
		case CommandReadMany:
			var p ReadManyPayload
			if err := p.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			return &p, nil
		default:
			return nil, fmt.Errorf("unknown command: %s", command)
		}
	}
}

// A placeholder for commands that don't have a payload.
type EmptyPayload struct{}

func (p *EmptyPayload) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (p *EmptyPayload) UnmarshalBinary([]byte) error {
	return nil
}

func (p *EmptyPayload) String() string {
	return "{}"
}

// Standard error codes.
type ErrorCode byte

const (
	// The requested command is not supported.
	ErrorCodeUnsupportedCommand ErrorCode = 0x01
	// The register is not readable or does not exist.
	ErrorCodeInvalidRegister ErrorCode = 0x02
	// Attempted to write to a read-only register.
	ErrorCodeWriteDenied ErrorCode = 0x03
	// Payload data is malformed or incorrect length.
	ErrorCodeMalformedPayload ErrorCode = 0x04
	// The operation failed due to an internal device error.
	ErrorCodeInternalError ErrorCode = 0x05
	// Message timed out or device not responding.
	ErrorCodeTimeout ErrorCode = 0x06
	// Command requires authentication or authorization.
	ErrorCodeUnauthorized ErrorCode = 0x07
	// Message format violated protocol spec.
	ErrorCodeProtocolViolation ErrorCode = 0x08
)

// The payload of an error response.
type ErrorPayload struct {
	// The error code.
	Code ErrorCode
	// An optional error message.
	Message string
}

func (p *ErrorPayload) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(p.Code))
	buf.WriteString(p.Message)
	return buf.Bytes(), nil
}

func (p *ErrorPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return errors.New("payload too short")
	}
	p.Code = ErrorCode(data[0])
	p.Message = string(data[1:])
	return nil
}

func (p *ErrorPayload) String() string {
	if p.Message == "" {
		return fmt.Sprintf("ErrorPayload{Code: %02X}", byte(p.Code))
	}
	return fmt.Sprintf("ErrorPayload{Code:%02X Message:%s}", byte(p.Code), p.Message)
}

func (p *ErrorPayload) Error() error {
	return fmt.Errorf("code: %02X, message: %s", byte(p.Code), p.Message)
}

// Well known registers
// These are common registers that should be implemented by all devices.
const (
	REGISTER_VENDOR_ID        uint16 = 0x0000 // 16-bit vendor id
	REGISTER_PRODUCT_ID       uint16 = 0x0001 // 16-bit product id
	REGISTER_DEVICE_NAME      uint16 = 0x0002 // UTF-8 device name
	REGISTER_FIRMWARE_VERSION uint16 = 0x0003 // UTF-8 firmware version
)

// Start of device-specific registers
const REGISTER_DEVICE_START uint16 = 0x1000

type ReadPayload struct {
	// The register address to read
	Register uint16
}

func (p *ReadPayload) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, p.Register)
	return buf.Bytes(), err
}

func (p *ReadPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("payload too short")
	}
	p.Register = binary.BigEndian.Uint16(data[:2])
	return nil
}

func (p *ReadPayload) String() string {
	return fmt.Sprintf("ReadPayload{Register:0x%04X}", p.Register)
}

// The payload of a write request or the payload of a read response.
type DataPayload struct {
	// The register address to write / that was read from.
	Register uint16
	// The data to write / that was read.
	Value []byte
}

func (p *DataPayload) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, p.Register)
	buf.Write(p.Value)
	return buf.Bytes(), err
}

func (p *DataPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("payload too short")
	}
	p.Register = binary.BigEndian.Uint16(data[:2])
	p.Value = data[2:]
	return nil
}

func (p *DataPayload) String() string {
	if len(p.Value) == 0 {
		return fmt.Sprintf("DataPayload{Register:0x%04X}", p.Register)
	}
	return fmt.Sprintf("DataPayload{Register:0x%04X Value:%v}", p.Register, p.Value)
}

// The payload of a time setting request.
type TimePayload struct {
	// The timestamp in UTC seconds since the Unix epoch.
	Timestamp uint64
	// The microseconds part of the timestamp.
	Microseconds uint32
}

func (p *TimePayload) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, p.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.Microseconds); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *TimePayload) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return errors.New("payload too short")
	}
	p.Timestamp = binary.BigEndian.Uint64(data[:8])
	p.Microseconds = binary.BigEndian.Uint32(data[8:12])
	return nil
}

func (p *TimePayload) String() string {
	return fmt.Sprintf("TimePayload{Timestamp:%d Microseconds:%d}", p.Timestamp, p.Microseconds)
}

// The payload of a read many request.
// This is used to read multiple values from a FIFO.
type ReadManyPayload struct {
	// The register address to read from.
	Register uint16
	// The number of values to read.
	Count uint16
}

func (p *ReadManyPayload) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, p.Register); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.Count); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *ReadManyPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("payload too short")
	}
	p.Register = binary.BigEndian.Uint16(data[:2])
	p.Count = binary.BigEndian.Uint16(data[2:4])
	return nil
}

func (p *ReadManyPayload) String() string {
	return fmt.Sprintf("ReadManyPayload{Register:0x%04X Count:%d}", p.Register, p.Count)
}
