//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
	//	"encoding/hex"
	"errors"
	//"fmt"
)

/******************************************************************************/
type NegotiateMessage struct {
	// All bytes of the message
	Bytes []byte
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType MessageType
	// negotiate flags - 4bytes
	NegotiateFlags uint32
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainName *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	Workstation *PayloadStruct
	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload       []byte
	PayloadOffset int
}

/******************************************************************************/
func ParseNegotiateMessage(body []byte) (*NegotiateMessage, error) {
	var err error
	neg := new(NegotiateMessage)

	neg.Signature = body[0:8]
	if !bytes.Equal(neg.Signature, []byte(SIGN_NTLMSSP)) {
		return neg, errors.New("Invalid NTLM message signature")
	}

	neg.MessageType = binary.LittleEndian.Uint32(body[8:12])
	if neg.MessageType != NEGOTIATE_MESSAGE {
		return neg, errors.New("Invalid NTLM message type should be 0x00000001 for Negotiate message")
	}

	neg.NegotiateFlags = binary.LittleEndian.Uint32(body[12:16])

	offset := 16

	if NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.IsSet(neg.NegotiateFlags) {
		neg.DomainName, err = ReadStringPayload(offset, body)
		if err != nil {
			return nil, err
		}
		offset = offset + 8
	}

	if NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.IsSet(neg.NegotiateFlags) {
		neg.Workstation, err = ReadStringPayload(offset, body)
		if err != nil {
			return nil, err
		}
		offset = offset + 8
	}

	if NTLMSSP_NEGOTIATE_VERSION.IsSet(neg.NegotiateFlags) {
		neg.Version, err = ReadVersionStruct(body[offset : offset+8])
		if err != nil {
			return nil, err
		}
		offset = offset + 8
	}

	neg.Payload = body[offset:]
	return neg, nil
}

/******************************************************************************/
