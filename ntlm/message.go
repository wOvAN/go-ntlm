package ntlm

import (
	//"bytes"
	"encoding/binary"
	//"encoding/hex"
	//"errors"
	//"fmt"
)

type (
	MessageType = uint32
	Signature   = [8]byte
)

/******************************************************************************/
const (
	// NTLM message type 1
	NEGOTIATE_MESSAGE MessageType = 1
	// NTLM message type 2
	CHALLENGE_MESSAGE MessageType = 2
	// NTLM message type 3
	AUTHENTICATE_MESSAGE MessageType = 3
	// NTLM message signature
	SIGN_NTLMSSP = "NTLMSSP\x00"
)

/******************************************************************************/
// gets message type from message, if it is invalid then returns 0
func GetMessageType(aMsg []byte) MessageType {
	msgType := MessageType(binary.LittleEndian.Uint32(aMsg[8:12]))
	switch msgType {
	case AUTHENTICATE_MESSAGE,
		NEGOTIATE_MESSAGE,
		CHALLENGE_MESSAGE:
		return msgType
	default:
		return 0
	}
}

/******************************************************************************/
