package goquic

// #cgo CXXFLAGS: -DUSE_OPENSSL=1 -Iquic_test/src/ -std=gnu++11
// #cgo LDFLAGS: -pthread -Lquic_test/boringssl/build/crypto -Lquic_test/boringssl/build/ssl quic_test/build/libquic.a -lssl -lcrypto
// #include <stddef.h>
// #include "adaptor.h"
import "C"
import (
	"net"
	"strings"
	"time"
	"unsafe"
)

// User API Interfaces --------------------------------------------------------
//   (For QuicSpdyServerStream)
type DataStreamProcessor interface {
	ProcessData(writer *QuicSpdyServerStream, buffer []byte) int
	OnFinRead(writer *QuicSpdyServerStream)
}

//   (For QuicServerSession)
type DataStreamCreator interface {
	CreateIncomingDataStream(streamId uint32) DataStreamProcessor
}

// Go <-> C++ Intermediate objects --------------------------------------------
type QuicEncryptedPacket struct {
	encryptedPacket unsafe.Pointer
}

type QuicDispatcher struct {
	quicDispatcher          unsafe.Pointer
	quicServerSessions      []*QuicServerSession
	taskRunner              *TaskRunner
	createQuicServerSession func() DataStreamCreator
}

type IPAddressNumber struct {
	ipAddressNumber unsafe.Pointer
}

type IPEndPoint struct {
	ipEndPoint unsafe.Pointer
}

type QuicSpdyServerStream struct {
	userStream DataStreamProcessor
	wrapper    unsafe.Pointer
	session    *QuicServerSession
}

type QuicServerSession struct {
	quicServerSession unsafe.Pointer
	quicServerStreams []*QuicSpdyServerStream
	streamCreator     DataStreamCreator
	remoteAddr        *net.UDPAddr
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
	rv                 int
	serverPacketWriter unsafe.Pointer
}

// functions -----------------------------------------------------------------_
func (writer *QuicSpdyServerStream) WriteHeader(header map[string][]string, is_body_empty bool) {
	header_c := C.initialize_map()
	for key, values := range header {
		value := strings.Join(values, ", ")
		C.insert_map(header_c, C.CString(key), C.CString(value))
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
		encryptedPacket: C.create_quic_encrypted_packet((*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer))),
	}
}

func DeleteQuicEncryptedPacket(packet QuicEncryptedPacket) {
	C.delete_quic_encrypted_packet(packet.encryptedPacket)
}

func CreateIPAddressNumber(ip net.IP) IPAddressNumber {
	return IPAddressNumber{
		ipAddressNumber: (C.create_ip_address_number((*C.uchar)(unsafe.Pointer(&ip[0])), C.size_t(len(ip)))),
	}
}

func DeleteIPAddressNumber(ipAddr IPAddressNumber) {
	C.delete_ip_address_number(ipAddr.ipAddressNumber)
}

func CreateIPEndPointC(ipAddr IPAddressNumber, port uint16) IPEndPoint {
	return IPEndPoint{
		ipEndPoint: (C.create_ip_end_point(unsafe.Pointer(ipAddr.ipAddressNumber), C.uint16_t(port))),
	}
}

func CreateIPEndPoint(udpAddr *net.UDPAddr) IPEndPoint {
	ip_address_c := CreateIPAddressNumber(udpAddr.IP)
	defer DeleteIPAddressNumber(ip_address_c)
	return IPEndPoint{
		ipEndPoint: (C.create_ip_end_point(unsafe.Pointer(ip_address_c.ipAddressNumber), C.uint16_t(udpAddr.Port))),
	}
}

func (endpoint *IPEndPoint) UDPAddr() *net.UDPAddr {
	ip_buf := make([]byte, 16)
	ip_sz := C.ip_endpoint_ip_address(endpoint.ipEndPoint, unsafe.Pointer(&ip_buf[0]))
	port := int(C.ip_endpoint_port(endpoint.ipEndPoint))
	return &net.UDPAddr{
		IP:   net.IP(ip_buf[:int(ip_sz)]),
		Port: port,
	}
}

func DeleteIPEndPoint(endpoint IPEndPoint) {
	C.delete_ip_end_point(endpoint.ipEndPoint)
}

func CreateQuicDispatcher(conn *net.UDPConn, createQuicServerSession func() DataStreamCreator, taskRunner *TaskRunner) *QuicDispatcher {
	dispatcher := &QuicDispatcher{
		createQuicServerSession: createQuicServerSession,
		taskRunner:              taskRunner,
	}

	dispatcher.quicDispatcher = C.create_quic_dispatcher(unsafe.Pointer(conn), unsafe.Pointer(dispatcher), unsafe.Pointer(taskRunner))
	return dispatcher
}

func (d *QuicDispatcher) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	packet := CreateQuicEncryptedPacket(buffer)
	defer DeleteQuicEncryptedPacket(packet)
	self_address_c := CreateIPEndPoint(self_address)
	defer DeleteIPEndPoint(self_address_c)
	peer_address_c := CreateIPEndPoint(peer_address)
	defer DeleteIPEndPoint(peer_address_c)
	C.quic_dispatcher_process_packet(d.quicDispatcher, self_address_c.ipEndPoint, peer_address_c.ipEndPoint, packet.encryptedPacket)
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
		rv:                 rv,
		serverPacketWriter: server_packet_writer_c,
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
		alarm.timer.Reset(0)
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
	C.packet_writer_on_write_complete(cb.serverPacketWriter, C.int(cb.rv))
}

// Export to C ----------------------------------------------------------------

//export CreateGoSession
func CreateGoSession(dispatcher_c unsafe.Pointer, session_c unsafe.Pointer) unsafe.Pointer {
	dispatcher := (*QuicDispatcher)(dispatcher_c)
	userSession := dispatcher.createQuicServerSession()
	session := &QuicServerSession{
		quicServerSession: session_c,
		streamCreator:     userSession,
		// TODO(serialx): Set remoteAddr here
	}
	dispatcher.quicServerSessions = append(dispatcher.quicServerSessions, session) // TODO(hodduc): cleanup

	return unsafe.Pointer(session)
}

//export WriteToUDP
func WriteToUDP(conn_c unsafe.Pointer, ip_endpoint_c unsafe.Pointer, buffer_c unsafe.Pointer, length_c C.size_t, server_packet_writer_c unsafe.Pointer, task_runner_c unsafe.Pointer) {
	conn := (*net.UDPConn)(conn_c)
	endpoint := IPEndPoint{
		ipEndPoint: ip_endpoint_c,
	}
	peer_addr := endpoint.UDPAddr()

	bufOrig := C.GoBytes(buffer_c, C.int(length_c))
	buf := make([]byte, len(bufOrig))
	copy(buf, bufOrig) // XXX(hodduc) buffer copy?

	taskRunner := (*TaskRunner)(task_runner_c)

	go func() {
		conn.WriteToUDP(buf, peer_addr)
		taskRunner.CallWriteCallback(server_packet_writer_c, len(buf))
	}()
}

//export CreateIncomingDataStream
func CreateIncomingDataStream(session_c unsafe.Pointer, stream_id uint32, wrapper_c unsafe.Pointer) unsafe.Pointer {
	session := (*QuicServerSession)(session_c)
	userStream := session.streamCreator.CreateIncomingDataStream(stream_id)

	stream := &QuicSpdyServerStream{
		userStream: userStream,
		session:    session,
		wrapper:    wrapper_c,
	}

	session.quicServerStreams = append(session.quicServerStreams, stream) // TODO(hodduc): cleanup

	return unsafe.Pointer(stream)
}

//export DataStreamProcessorProcessData
func DataStreamProcessorProcessData(go_data_stream_processor_c unsafe.Pointer, data unsafe.Pointer, data_len uint32) uint32 {
	serverStream := (*QuicSpdyServerStream)(go_data_stream_processor_c)
	buf := C.GoBytes(data, C.int(data_len))
	return uint32(serverStream.userStream.ProcessData(serverStream, buf))
}

//export DataStreamProcessorOnFinRead
func DataStreamProcessorOnFinRead(go_data_stream_processor_c unsafe.Pointer) {
	serverStream := (*QuicSpdyServerStream)(go_data_stream_processor_c)
	serverStream.userStream.OnFinRead(serverStream)
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
