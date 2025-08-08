package client

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Pinger 负责定期向 websocket 连接发送 ping，并且在 Stop 或重启时能安全清理定时任务。
// 使用方法：创建一个 Pinger（NewPinger），在建立或重建连接后调用 Start(conn)，在断开或准备重连前调用 Stop()。
type Pinger struct {
	mu sync.Mutex
	// 使用包内定义的接口类型，避免在调用处进行类型断言
	conn     WebSocketConn
	cancel   context.CancelFunc
	running  bool
	interval time.Duration
}

// NewPinger 创建一个新的 Pinger，interval 为心跳间隔（建议 >= 5s）。
func NewPinger(interval time.Duration) *Pinger {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &Pinger{
		interval: interval,
	}
}

// Start 使用给定的 conn 启动或重启 pinger；如果已有正在运行的 pinger，会先将其停止以确保不会并存多个定时任务。
// 这里接受 WebSocketConn 接口，因此可以直接传入 controlConn（不需要类型断言）。
func (p *Pinger) Start(conn WebSocketConn) {
	p.mu.Lock()
	// 如果已有在运行的 pinger，先停止它以清理旧的定时任务
	if p.running {
		p.stopLocked()
	}
	// 绑定新的连接并启动新的运行上下文
	p.conn = conn
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.running = true
	p.mu.Unlock()

	go p.run(ctx)
}

// Stop 停止当前 pinger（如果有），并解除与 conn 的绑定。
// Stop 是幂等的，可以安全多次调用。
func (p *Pinger) Stop() {
	p.mu.Lock()
	p.stopLocked()
	p.mu.Unlock()
}

func (p *Pinger) stopLocked() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.running = false
	// 解除绑定连接引用以便 run 可以安全退出
	p.conn = nil
}

// run 在独立 goroutine 中运行心跳循环，遇到错误会停止自己并记录日志。
func (p *Pinger) run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 读取当前连接引用的快照，避免在发送期间被另一个 goroutine 修改
			p.mu.Lock()
			conn := p.conn
			p.mu.Unlock()

			if conn == nil {
				// 没有有效的连接，安全退出
				return
			}

			deadline := time.Now().Add(5 * time.Second)
			if err := conn.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
				// 在发送失败（例如连接已关闭）时，停止 pinger 并退出，避免持续写操作导致 "use of closed network connection"
				log.Printf("Pinger: Failed to send ping: %v", err)
				p.Stop()
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
