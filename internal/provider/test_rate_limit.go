package provider

import (
	"sync"
	"testing"
	"time"
)

// Global rate limiter for tests
var (
	testRateLimiter = make(chan struct{}, 1) // Only allow 1 test at a time
	lastTestTime    time.Time
	testMutex       sync.Mutex
	minWaitTime     = 30 * time.Second // Minimum wait time between tests
)

// rateLimitedTest ensures we don't exceed 2 tests per minute
func rateLimitedTest(t *testing.T, testFunc func(), minInterval time.Duration) {
	testMutex.Lock()
	defer testMutex.Unlock()

	elapsed := time.Since(lastTestTime)

	if elapsed < minInterval {
		sleepTime := minInterval - elapsed
		t.Logf("Rate limiting: sleeping for %v to avoid API limits", sleepTime)
		time.Sleep(sleepTime)
	}

	testFunc()
	lastTestTime = time.Now()
}
