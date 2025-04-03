package psgserial_test

import (
	"testing"

	"github.com/OpenPSG/psgserial/go/psgserial"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddressMarshalAndUnmarshal(t *testing.T) {
	str := "01:02:03:04:05:06:07:08"
	var addr psgserial.Address
	err := addr.UnmarshalText([]byte(str))
	require.NoError(t, err)
	assert.Equal(t, str, addr.String())

	bin, err := addr.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, bin, 8)
}

func TestMessageRoundTrip(t *testing.T) {
	addr := psgserial.Address(0x0102030405060708)
	msg := &psgserial.Message{
		Address: addr,
		Flags:   0,
		Command: psgserial.CommandRead,
		Payload: &psgserial.ReadPayload{Register: 0x1234},
	}

	bin, err := msg.MarshalBinary()
	require.NoError(t, err)

	var parsed psgserial.Message
	err = parsed.UnmarshalBinary(bin)
	require.NoError(t, err)

	assert.Equal(t, msg.Address, parsed.Address)
	assert.Equal(t, msg.Flags, parsed.Flags)
	assert.Equal(t, msg.Command, parsed.Command)

	origPayload, _ := msg.Payload.(*psgserial.ReadPayload)
	parsedPayload, _ := parsed.Payload.(*psgserial.ReadPayload)
	assert.Equal(t, origPayload.Register, parsedPayload.Register)
}

func TestReadPayloadMarshalUnmarshal(t *testing.T) {
	p := &psgserial.ReadPayload{Register: 0x1234}
	data, err := p.MarshalBinary()
	require.NoError(t, err)

	var newP psgserial.ReadPayload
	err = newP.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.Equal(t, p.Register, newP.Register)
}

func TestDataPayloadMarshalUnmarshal(t *testing.T) {
	p := &psgserial.DataPayload{Register: 0x1234, Value: []byte{0xDE, 0xAD, 0xBE, 0xEF}}
	data, err := p.MarshalBinary()
	require.NoError(t, err)

	var newP psgserial.DataPayload
	err = newP.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.Equal(t, p.Register, newP.Register)
	assert.Equal(t, p.Value, newP.Value)
}

func TestErrorPayloadMarshalUnmarshal(t *testing.T) {
	p := &psgserial.ErrorPayload{Code: psgserial.ErrorCodeMalformedPayload, Message: "bad data"}
	data, err := p.MarshalBinary()
	require.NoError(t, err)

	var newP psgserial.ErrorPayload
	err = newP.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.Equal(t, p.Code, newP.Code)
	assert.Equal(t, p.Message, newP.Message)
}
