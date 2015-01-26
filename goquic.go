package goquic

// #cgo CXXFLAGS: -DUSE_OPENSSL=1 -Iquic_test/src/ -std=gnu++11
// #cgo LDFLAGS: -pthread -Lquic_test/boringssl/build/crypto -Lquic_test/boringssl/build/ssl quic_test/build/libquic.a -lssl -lcrypto
// #include <stddef.h>
// #include "adaptor.h"
import "C"
import (
	"time"
	"unsafe"
)
import "net"
import "strings"

// API Interfaces -------------------------------------------------------------
//  -> For QuicSpdyServerStream
type DataStreamProcessor interface {
	ProcessData(writer *QuicSpdyServerStream, buffer []byte) int
	OnFinRead(writer *QuicSpdyServerStream)
	//ParseRequestHeaders()
}

//  -> For QuicServerSession

type DataStreamCreator interface {
	CreateIncomingDataStream(stream_id uint32) DataStreamProcessor
}

// Go <-> C++ Intermediate objects --------------------------------------------
type QuicConnection struct {
	quic_connection unsafe.Pointer
}

type QuicEncryptedPacket struct {
	encrypted_packet unsafe.Pointer
}

type QuicDispatcher struct {
	quic_dispatcher            unsafe.Pointer
	quic_server_sessions       []*QuicServerSession
	task_runner                *TaskRunner
	create_quic_server_session func() DataStreamCreator
}

type IPAddressNumber struct {
	ip_address_number unsafe.Pointer
}

type IPEndPoint struct {
	ip_end_point unsafe.Pointer
}

type QuicSpdyServerStream struct {
	user_stream DataStreamProcessor
	wrapper     unsafe.Pointer
	session     *QuicServerSession
}

type QuicServerSession struct {
	quic_server_session unsafe.Pointer
	quic_server_streams []*QuicSpdyServerStream
	stream_creator      DataStreamCreator
	remote_addr         *net.UDPAddr
}

type GoQuicAlarm struct {
	deadline     int64
	isCanceled   bool
	invalidateCh chan bool
	wrapper      unsafe.Pointer
	clock        unsafe.Pointer
	taskRunner   *TaskRunner
	timer        *time.Timer
}

type TaskRunner struct {
	AlarmChan chan *GoQuicAlarm
	WriteChan chan *WriteCallback
	alarmList []*GoQuicAlarm
}

type WriteCallback struct {
	rv                   int
	server_packet_writer unsafe.Pointer
}

/*
func CreateQuicConnection(connection_id int, ip_addr net.IP) QuicConnection {
	ip := CreateIPAddressNumber(ip_addr)
	defer DeleteIPAddressNumber(ip)
	ip_endpoint := CreateIPEndPointC(ip, 80)
	defer DeleteIPEndPoint(ip_endpoint)
	ptr := C.create_quic_connection(C.int(connection_id), unsafe.Pointer(ip_endpoint.ip_end_point))

	return QuicConnection{quic_connection: ptr}
}

func (c *QuicConnection) Version() int {
	ver := C.quic_connection_version(c.quic_connection)
	return int(ver)
}

func (c *QuicConnection) ProcessUdpPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	packet := CreateQuicEncryptedPacket(buffer)
	defer DeleteQuicEncryptedPacket(packet)
	self_address_c := CreateIPEndPoint(self_address)
	defer DeleteIPEndPoint(self_address_c)
	peer_address_c := CreateIPEndPoint(peer_address)
	defer DeleteIPEndPoint(peer_address_c)
	C.quic_connection_process_udp_packet(c.quic_connection, self_address_c.ip_end_point, peer_address_c.ip_end_point, packet.encrypted_packet)
}
*/

func (writer *QuicSpdyServerStream) WriteHeader(header map[string][]string, is_body_empty bool) {
	header_c := C.initialize_map()
	for key, values := range header {
		value := strings.Join(values, ", ")
		C.insert_map(header_c, C.CString(key), C.CString(value)) //(*C.char)(unsafe.Pointer(&key[0])), (*C.char)(unsafe.Pointer(&value[0])))
	}

	if is_body_empty {
		C.quic_spdy_server_stream_write_headers(writer.wrapper, header_c, 1)
	} else {
		C.quic_spdy_server_stream_write_headers(writer.wrapper, header_c, 0)
	}
}

func (writer *QuicSpdyServerStream) WriteOrBufferData(body []byte, fin bool) {
	fin_int := C.int(0)
	if fin {
		fin_int = C.int(1)
	}

	if len(body) == 0 {
		C.quic_spdy_server_stream_write_or_buffer_data(writer.wrapper, (*C.char)(unsafe.Pointer(nil)), C.size_t(0), fin_int)
	} else {
		C.quic_spdy_server_stream_write_or_buffer_data(writer.wrapper, (*C.char)(unsafe.Pointer(&body[0])), C.size_t(len(body)), fin_int)
	}
}

func Initialize() {
	C.initialize()
}

func SetLogLevel(level int) {
	C.set_log_level(C.int(level))
}

// Note that the buffer is NOT copied. So it is the callers responsibility to retain the buffer until it is processed by QuicConnection
func CreateQuicEncryptedPacket(buffer []byte) QuicEncryptedPacket {
	return QuicEncryptedPacket{
		encrypted_packet: C.create_quic_encrypted_packet((*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer))),
	}
}

func DeleteQuicEncryptedPacket(packet QuicEncryptedPacket) {
	C.delete_quic_encrypted_packet(packet.encrypted_packet)
}

func CreateIPAddressNumber(ip net.IP) IPAddressNumber {
	return IPAddressNumber{
		ip_address_number: (C.create_ip_address_number((*C.uchar)(unsafe.Pointer(&ip[0])), C.size_t(len(ip)))),
	}
}

func DeleteIPAddressNumber(ip_address IPAddressNumber) {
	C.delete_ip_address_number(ip_address.ip_address_number)
}

func CreateIPEndPointC(ip_address IPAddressNumber, port uint16) IPEndPoint {
	return IPEndPoint{
		ip_end_point: (C.create_ip_end_point(unsafe.Pointer(ip_address.ip_address_number), C.uint16_t(port))),
	}
}

func CreateIPEndPoint(ip_endpoint *net.UDPAddr) IPEndPoint {
	ip_address_c := CreateIPAddressNumber(ip_endpoint.IP)
	defer DeleteIPAddressNumber(ip_address_c)
	return IPEndPoint{
		ip_end_point: (C.create_ip_end_point(unsafe.Pointer(ip_address_c.ip_address_number), C.uint16_t(ip_endpoint.Port))),
	}
}

func (ip_endpoint *IPEndPoint) UDPAddr() *net.UDPAddr {
	ip_buf := make([]byte, 16)
	ip_sz := C.ip_endpoint_ip_address(ip_endpoint.ip_end_point, unsafe.Pointer(&ip_buf[0]))
	port := int(C.ip_endpoint_port(ip_endpoint.ip_end_point))
	return &net.UDPAddr{
		IP:   net.IP(ip_buf[:int(ip_sz)]),
		Port: port,
	}
}

func DeleteIPEndPoint(ip_endpoint IPEndPoint) {
	C.delete_ip_end_point(ip_endpoint.ip_end_point)
}

func CreateQuicDispatcher(conn *net.UDPConn, create_quic_server_session func() DataStreamCreator, taskRunner *TaskRunner) *QuicDispatcher {
	dispatcher := &QuicDispatcher{
		create_quic_server_session: create_quic_server_session,
		task_runner:                taskRunner,
	}

	dispatcher.quic_dispatcher = C.create_quic_dispatcher(unsafe.Pointer(conn), unsafe.Pointer(dispatcher), unsafe.Pointer(taskRunner))
	return dispatcher
}

func (d *QuicDispatcher) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	packet := CreateQuicEncryptedPacket(buffer)
	defer DeleteQuicEncryptedPacket(packet)
	self_address_c := CreateIPEndPoint(self_address)
	defer DeleteIPEndPoint(self_address_c)
	peer_address_c := CreateIPEndPoint(peer_address)
	defer DeleteIPEndPoint(peer_address_c)
	C.quic_dispatcher_process_packet(d.quic_dispatcher, self_address_c.ip_end_point, peer_address_c.ip_end_point, packet.encrypted_packet)
}

//export CreateGoSession
func CreateGoSession(dispatcher_c unsafe.Pointer, session_c unsafe.Pointer) unsafe.Pointer {
	dispatcher := (*QuicDispatcher)(dispatcher_c)
	user_session := dispatcher.create_quic_server_session()
	session := &QuicServerSession{
		quic_server_session: session_c,
		stream_creator:      user_session,
		// TODO(serialx): Set remoteAddr here
	}
	dispatcher.quic_server_sessions = append(dispatcher.quic_server_sessions, session)

	return unsafe.Pointer(session)
}

func (t *TaskRunner) RunAlarm(alarm *GoQuicAlarm) {
	go func() {
		if alarm.timer == nil {
			return
		}

		select {
		//TODO (hodduc) alarm.timer.C will block infinitely if timer is resetted before deadline.
		case <-alarm.timer.C:
			if !alarm.isCanceled {
				t.AlarmChan <- alarm // To keep thread-safety, callback should be called in the main message loop, not in seperated goroutine.
			}
		}
	}()
}

func (t *TaskRunner) RegisterAlarm(alarm *GoQuicAlarm) {
	t.alarmList = append(t.alarmList, alarm)
}

func (t *TaskRunner) CallWriteCallback(server_packet_writer_c unsafe.Pointer, rv int) {
	t.WriteChan <- (&WriteCallback{
		rv:                   rv,
		server_packet_writer: server_packet_writer_c,
	})
}

func (alarm *GoQuicAlarm) SetImpl(now int64) {
	alarm.isCanceled = false

	duration_i64 := alarm.deadline - now
	if duration_i64 < 0 {
		duration_i64 = 0
	}

	if alarm.timer != nil {
		alarm.timer.Reset(time.Duration(duration_i64) * time.Microsecond)
	} else {
		alarm.timer = time.NewTimer(time.Duration(duration_i64) * time.Microsecond)
		alarm.taskRunner.RunAlarm(alarm)
	}
}

func (alarm *GoQuicAlarm) CancelImpl(now int64) {
	alarm.isCanceled = true

	if alarm.timer != nil {
		alarm.timer.Stop()
		alarm.timer = nil
	}
}

func (alarm *GoQuicAlarm) OnAlarm() {
	if now := int64(C.clock_now(alarm.clock)); now < alarm.deadline {
		alarm.SetImpl(now)
		return
	}

	alarm.timer = nil
	C.go_quic_alarm_fire(alarm.wrapper)
}

func (cb *WriteCallback) Callback() {
	C.packet_writer_on_write_complete(cb.server_packet_writer, C.int(cb.rv))
}

//export WriteToUDP
func WriteToUDP(conn_c unsafe.Pointer, ip_endpoint_c unsafe.Pointer, buffer_c unsafe.Pointer, length_c C.size_t, server_packet_writer_c unsafe.Pointer, task_runner_c unsafe.Pointer) {
	conn := (*net.UDPConn)(conn_c)
	ip_endpoint := IPEndPoint{
		ip_end_point: ip_endpoint_c,
	}
	peer_addr := ip_endpoint.UDPAddr()
	buf := C.GoBytes(buffer_c, C.int(length_c))
	task_runner := (*TaskRunner)(task_runner_c)

	go func() {
		conn.WriteToUDP(buf, peer_addr)
		task_runner.CallWriteCallback(server_packet_writer_c, len(buf))
	}()
}

//export CreateIncomingDataStream
func CreateIncomingDataStream(session_c unsafe.Pointer, stream_id uint32, wrapper_c unsafe.Pointer) unsafe.Pointer {
	session := (*QuicServerSession)(session_c)
	user_stream := session.stream_creator.CreateIncomingDataStream(stream_id)

	stream := &QuicSpdyServerStream{
		user_stream: user_stream,
		session:     session,
		wrapper:     wrapper_c,
	}

	session.quic_server_streams = append(session.quic_server_streams, stream)

	return unsafe.Pointer(stream)
}

//export DataStreamProcessorProcessData
func DataStreamProcessorProcessData(go_data_stream_processor_c unsafe.Pointer, data unsafe.Pointer, data_len uint32) uint32 {
	server_stream := (*QuicSpdyServerStream)(go_data_stream_processor_c)
	buf := C.GoBytes(data, C.int(data_len))
	return uint32(server_stream.user_stream.ProcessData(server_stream, buf))
}

//export DataStreamProcessorOnFinRead
func DataStreamProcessorOnFinRead(go_data_stream_processor_c unsafe.Pointer) {
	server_stream := (*QuicSpdyServerStream)(go_data_stream_processor_c)
	server_stream.user_stream.OnFinRead(server_stream)
}

//export CreateGoQuicAlarm
func CreateGoQuicAlarm(go_quic_alarm_go_wrapper_c unsafe.Pointer, clock_c unsafe.Pointer, task_runner_c unsafe.Pointer) unsafe.Pointer {
	alarm := &GoQuicAlarm{
		wrapper:    go_quic_alarm_go_wrapper_c,
		taskRunner: (*TaskRunner)(task_runner_c),
		clock:      clock_c,
		timer:      nil,
		isCanceled: false,
	}
	alarm.taskRunner.RegisterAlarm(alarm) // TODO(hodduc): Should unregister somewhen

	return unsafe.Pointer(alarm)
}

//export GoQuicAlarmSetImpl
func GoQuicAlarmSetImpl(alarm_c unsafe.Pointer, deadline int64, now int64) {
	alarm := (*GoQuicAlarm)(alarm_c)
	alarm.deadline = deadline
	alarm.SetImpl(now)
}

//export GoQuicAlarmCancelImpl
func GoQuicAlarmCancelImpl(alarm_c unsafe.Pointer, now int64) {
	alarm := (*GoQuicAlarm)(alarm_c)
	alarm.CancelImpl(now)
}

// Library Ends --------------------------------------------------------------
