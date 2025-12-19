package ddos

import (
	"io"
	"net/http"
	"sync/atomic"
)

// AsyncSender sends HTTP requests asynchronously without waiting for responses
type AsyncSender struct {
	client     *http.Client
	sentCount  int64
	errorCount int64
}

// NewAsyncSender creates a new async sender
func NewAsyncSender(client *http.Client) *AsyncSender {
	return &AsyncSender{
		client: client,
	}
}

// SendAsync sends a request asynchronously without waiting for response
func (s *AsyncSender) SendAsync(req *http.Request, skipResponseReading bool) {
	atomic.AddInt64(&s.sentCount, 1)

	// Send request in goroutine, don't wait
	go func() {
		resp, err := s.client.Do(req)
		if err != nil {
			atomic.AddInt64(&s.errorCount, 1)
			return
		}

		// If skipResponseReading is true, close immediately without reading
		if skipResponseReading {
			resp.Body.Close()
		} else {
			// Minimal read - just enough to complete the request
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
}

// GetStats returns sender statistics
func (s *AsyncSender) GetStats() (sent int64, errors int64) {
	return atomic.LoadInt64(&s.sentCount), atomic.LoadInt64(&s.errorCount)
}

