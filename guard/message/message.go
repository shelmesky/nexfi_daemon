package message

import (
	"encoding/json"
)

/* payload size don't include message header */
const (
	MAX_MSG_PAYLOAD_SEZE = 1000
)

/* message header */
type MessageHeader struct {
	MsgType   uint32 //Message type
	MsgSeq    uint16 //Message sequence number
	MsgPayLen uint16 //Message payload length
}

func (msg *MessageHeader) GetMessageHeaderLen() int      { return 8 }
func (msg *MessageHeader) SetMsgType(msgtype uint32)     { msg.MsgType = msgtype }
func (msg *MessageHeader) GetMsgType() uint32            { return msg.MsgType }
func (msg *MessageHeader) SetMsgSeq(msgseq uint16)       { msg.MsgSeq = msgseq }
func (msg *MessageHeader) GetMsgSeq() uint16             { return msg.MsgSeq }
func (msg *MessageHeader) SetMsgPayLen(msgpaylen uint16) { msg.MsgPayLen = msgpaylen }
func (msg *MessageHeader) GetMsgPayLen() uint16          { return msg.MsgPayLen }

type Message struct {
	MessageHeader
	Payload []byte
}

func (msg *Message) GetMsgPayload() []byte        { return msg.Payload }
func (msg *Message) SetMsgPayload(payload []byte) { msg.Payload = payload }

func (msg *Message) Marshal() ([]byte, error) {
	return json.Marshal(msg)
}

func (msg *Message) Unmarshal(data []byte) error {
	return json.Unmarshal(data, msg)
}
