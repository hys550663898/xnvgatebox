package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// webServer 管理 HTTP 监听，支持在运行时切换端口/监听地址而不重启进程。
// 切换端口或监听地址会新起一个 net.Listener，旧的优雅关闭。
type webServer struct {
	handler http.Handler

	mu              sync.Mutex
	ln              net.Listener
	srv             *http.Server
	addr            string
	cfg             WebSettings
	hasCfg          bool
	prepareListener func(WebSettings) (*preparedManagementListener, error)
	managementHook  func(string) error
}

func newWebServer(h http.Handler) *webServer {
	return &webServer{handler: h}
}

// serve 用当前 WebSettings 起第一个监听并阻塞。返回时说明监听彻底退出。
// HTTPS 监听起不来（证书被删/过期/路径改名）时回退 HTTP 并打日志：
// 保存时证书是校验过的，走到这里多半是盘上文件后来变了，不能因此
// 把管理界面彻底锁死。
func (s *webServer) serve() error {
	cfg := getWebSettings()
	if err := s.reload(cfg); err != nil {
		if !cfg.HTTPS {
			return err
		}
		log.Printf("HTTPS 监听启动失败: %v；已回退为 HTTP，请到设置里检查证书路径", err)
		cfg.HTTPS = false
		if err := s.reload(cfg); err != nil {
			return err
		}
	}
	// 主 goroutine 就地阻塞，等监听被 reload 或退出替换。
	// 这里靠一个永不返回的 select 挂住：真正的 Serve 在 reload 里各自的 goroutine 跑。
	select {}
}

// reload 切换到新的监听地址：先探测能否绑上，绑得上再关旧的、启新的。
// 绑不上就保持旧监听不动，返回错误让调用方回报给用户。
func (s *webServer) reload(cfg WebSettings) error {
	prepared, err := s.prepareManagementListener(cfg)
	if err != nil {
		return err
	}
	prepared.activate()
	return nil
}

// startServing 在给定监听上开始服务并登记为当前监听，不动旧监听。
func (s *webServer) startServing(ln net.Listener, cfg WebSettings) {
	if cfg.HTTPS {
		ln = wrapManagementTLS(ln)
	}
	addr := cfg.listenAddrString()
	srv := &http.Server{Handler: s.handler}
	s.mu.Lock()
	s.srv = srv
	s.ln = ln
	s.addr = addr
	s.cfg = cfg
	s.hasCfg = true
	s.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP 监听 %s 退出: %v", addr, err)
		}
	}()
	log.Printf("管理界面监听已切换到 %s", addr)
}

// activateListener 登记新监听并优雅关闭旧监听（新旧地址不同时用：
// 新地址已在 prepare 阶段绑好，这里只负责交接）。
func (s *webServer) activateListener(ln net.Listener, cfg WebSettings) {
	s.mu.Lock()
	oldSrv := s.srv
	oldLn := s.ln
	s.mu.Unlock()

	s.startServing(ln, cfg)

	// 关掉旧监听。给正在处理的请求一点收尾时间，
	// 尤其是触发这次 reload 的那个请求本身要先把响应写完。
	if oldSrv != nil {
		go func() {
			time.Sleep(1 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = oldSrv.Shutdown(ctx)
			_ = oldLn.Close()
		}()
	}
}

// swapInPlace 在同一地址上原地切换协议（HTTP↔HTTPS）：端口被旧监听
// 占着，没法像换端口那样先绑新的，只能先等触发切换的响应写完，
// 再关旧、绑新。绑新失败时按旧配置把监听恢复回来，服务不中断太久。
func (s *webServer) swapInPlace(next WebSettings) {
	if next.HTTPS {
		if err := storeManagementCert(next.CertFile, next.KeyFile); err != nil {
			log.Printf("同端口切换 HTTPS 失败，证书不可用: %v", err)
			return
		}
	}
	go func() {
		time.Sleep(1 * time.Second)
		s.mu.Lock()
		oldSrv := s.srv
		oldLn := s.ln
		oldCfg := s.cfg
		s.mu.Unlock()
		if oldSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = oldSrv.Shutdown(ctx)
			cancel()
		}
		if oldLn != nil {
			_ = oldLn.Close()
		}
		addr := next.listenAddrString()
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("同端口切换监听失败: %v，尝试恢复原监听", err)
			ln2, err2 := net.Listen("tcp", addr)
			if err2 != nil {
				log.Printf("恢复原监听也失败: %v", err2)
				return
			}
			s.startServing(ln2, oldCfg)
			return
		}
		s.startServing(ln, next)
	}()
}

// applyWebSettings 校验、落盘并切换监听。任一步失败都不改动线上监听。
func (s *webServer) applyWebSettings(next WebSettings) error {
	managementMu.Lock()
	defer managementMu.Unlock()
	return commitManagementSettings(nil, s, next, nil, nil)
}
