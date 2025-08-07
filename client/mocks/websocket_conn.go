package mocks

import (
	"net"
	"time"

	"github.com/stretchr/testify/mock"
)

// MockWebSocketConn is a mock implementation of WebSocketConn interface
type MockWebSocketConn struct {
	mock.Mock
}

func (m *MockWebSocketConn) WriteJSON(v interface{}) error {
	args := m.Called(v)
	return args.Error(0)
}

func (m *MockWebSocketConn) ReadJSON(v interface{}) error {
	args := m.Called(v)
	return args.Error(0)
}

func (m *MockWebSocketConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	args := m.Called(messageType, data)
	return args.Error(0)
}

func (m *MockWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	args := m.Called()
	return args.Int(0), args.Get(1).([]byte), args.Error(2)
}

func (m *MockWebSocketConn) SetReadDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockWebSocketConn) SetPongHandler(h func(appData string) error) {
	m.Called(h)
}

func (m *MockWebSocketConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	args := m.Called(messageType, data, deadline)
	return args.Error(0)
}

func (m *MockWebSocketConn) RemoteAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}