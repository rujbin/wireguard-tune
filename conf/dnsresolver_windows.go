package conf

import (
    "context"
    "log"
    "net/netip"
    "sync"
    "time"
    "unsafe"

    "golang.org/x/sys/windows"
    "golang.zx2c4.com/wireguard/windows/services"
    "golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var dnsCache = struct {
    sync.RWMutex
    entries map[string]cachedDNS
}{entries: make(map[string]cachedDNS)}

type cachedDNS struct {
    ip        string
    timestamp time.Time
}

const (
    dnsCacheDuration = 5 * time.Minute
    dnsTimeout       = 10 * time.Second
)

func resolveHostname(name string) (resolvedIPString string, err error) {
    dnsCache.RLock()
    if entry, exists := dnsCache.entries[name]; exists && time.Since(entry.timestamp) < dnsCacheDuration {
        dnsCache.RUnlock()
        return entry.ip, nil
    }
    dnsCache.RUnlock()

    maxTries := 5
    if services.StartedAtBoot() {
        maxTries = 10
    }

    for i := 0; i < maxTries; i++ {
        if i > 0 {
            backoff := time.Duration(min(1<<uint(i-1), 8)) * time.Second
            time.Sleep(backoff)
        }

        resolveCtx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
        defer cancel()

        resultCh := make(chan struct {
            ip  string
            err error
        }, 1)

        go func() {
            ip, err := resolveHostnameOnce(name)
            resultCh <- struct {
                ip  string
                err error
            }{ip, err}
        }()

        select {
        case result := <-resultCh:
            if result.err == nil {
                dnsCache.Lock()
                dnsCache.entries[name] = cachedDNS{
                    ip:        result.ip,
                    timestamp: time.Now(),
                }
                dnsCache.Unlock()
                return result.ip, nil
            }
            log.Printf("DNS resolution failed for %s: %v (attempt %d/%d)", name, result.err, i+1, maxTries)
            if result.err == windows.WSATRY_AGAIN {
                continue
            }
            if result.err == windows.WSAHOST_NOT_FOUND && services.StartedAtBoot() {
                continue
            }
            return "", result.err
        case <-resolveCtx.Done():
            log.Printf("DNS resolution timeout for %s (attempt %d/%d)", name, i+1, maxTries)
            continue
        }
    }
    return "", windows.WSAHOST_NOT_FOUND
}

func resolveHostnameOnce(name string) (resolvedIPString string, err error) {
    hints := windows.AddrinfoW{
        Family:   windows.AF_UNSPEC,
        Socktype: windows.SOCK_DGRAM,
        Protocol: windows.IPPROTO_IP,
    }
    var result *windows.AddrinfoW
    name16, err := windows.UTF16PtrFromString(name)
    if err != nil {
        return
    }
    err = windows.GetAddrInfoW(name16, nil, &hints, &result)
    if err != nil {
        return
    }
    if result == nil {
        err = windows.WSAHOST_NOT_FOUND
        return
    }
    defer windows.FreeAddrInfoW(result)
    var v6 netip.Addr
    for ; result != nil; result = result.Next {
        if result.Family != windows.AF_INET && result.Family != windows.AF_INET6 {
            continue
        }
        addr := (*winipcfg.RawSockaddrInet)(unsafe.Pointer(result.Addr)).Addr()
        if addr.Is4() {
            return addr.String(), nil
        } else if !v6.IsValid() && addr.Is6() {
            v6 = addr
        }
    }
    if v6.IsValid() {
        return v6.String(), nil
    }
    err = windows.WSAHOST_NOT_FOUND
    return
}

func (config *Config) ResolveEndpoints() error {
    var wg sync.WaitGroup
    var mu sync.Mutex
    var firstErr error

    for i := range config.Peers {
        if config.Peers[i].Endpoint.IsEmpty() {
            continue
        }
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            resolved, err := resolveHostname(config.Peers[i].Endpoint.Host)
            if err != nil {
                mu.Lock()
                if firstErr == nil {
                    firstErr = err
                }
                mu.Unlock()
                return
            }
            mu.Lock()
            config.Peers[i].Endpoint.Host = resolved
            mu.Unlock()
        }(i)
    }
    wg.Wait()
    return firstErr
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}