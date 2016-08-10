package message

import (
	json "encoding/json"
)

/* payload size don't include message header */
const (
	MAX_MSG_PAYLOAD_SEZE = 1024
)

/* message type */
const (
	MSG_DATA = 1 << iota /* message is data type */
	MSG_CMD              /* message is command type */
)

/* control message id */
const (
	MSG_DATA_SYNC_SECRET_KEY = iota
	MSG_DATA_SYNC_SECRET_KEY_ACK
)

/* message header */
type MessageHeader struct {
	MsgType   uint8  //Message type
	MsgID     uint8  //Message ID
	MsgSeq    uint16 //Message sequence number
	MsgPayLen uint16 //Message payload length
	// MsgCRC    uint32 Message CRC code
}

func (msg *MessageHeader) GetMessageHeaderLen() int {
	return 6
}

func (msg *MessageHeader) SetMsgType(msgtype uint8) {
	msg.MsgType = msgtype
}

func (msg *MessageHeader) GetMsgType() uint8 {
	return msg.MsgType
}

func (msg *MessageHeader) SetMsgID(msgid uint8) {
	msg.MsgID = msgid
}

func (msg *MessageHeader) GetMsgID() uint8 {
	return msg.MsgID
}

func (msg *MessageHeader) SetMsgSeq(msgseq uint16) {
	msg.MsgSeq = msgseq
}

func (msg *MessageHeader) GetMsgSeq() uint16 {
	return msg.MsgSeq
}

func (msg *MessageHeader) SetPayLen(msgpaylen uint16) {
	msg.MsgPayLen = msgpaylen
}

func (msg *MessageHeader) GetMsgPayLen(msgpaylen uint16) {
	return
}

type Message struct {
	MsgHeader MessageHeader
	Payload   []byte
}

func (msg *Message) GetPlayload() []byte {
	return msg.Payload
}

func (msg *Message) SetPayload(payload []byte) {
	msg.Payload = payload
}

func (msg *Message) Marshal() ([]byte, error) {
	return nil, nil

}

func (msg *Message) UnMarshal(data []byte) error {
	return json.Unmarshal(data, msg)
}

func (msg *Message) Parse() {
}
