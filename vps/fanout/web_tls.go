package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// 管理界面 HTTPS 的证书来自用户指定的本机文件路径（例如 3x-ui 已签发
// 的那套），程序只读取、不签发也不续期。这里负责三件事：路径成对校验、
// 证书对加载（含有效期检查）、域名格式校验。

// validateDomainName 校验可选的访问域名：留空合法（用 IP 访问）；
// 填了就必须是纯主机名，不带协议、端口或路径。
func validateDomainName(domain string) error {
	d := strings.TrimSpace(domain)
	if d == "" {
		return nil
	}
	if len(d) > 253 || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return fmt.Errorf("域名格式无效: %q", domain)
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("域名格式无效: %q", domain)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("域名只能含字母、数字、连字符和点，不要带协议或端口: %q", domain)
			}
		}
	}
	return nil
}

// loadManagementCert 加载并校验一对证书/私钥文件：必须成对匹配且
// 在有效期内。保存设置和每次（重新）准备监听时都调用，坏证书进不了
// 线上监听；服务运行中证书被续期替换后，重启或重新保存设置即生效。
func loadManagementCert(certFile, keyFile string) (tls.Certificate, error) {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, fmt.Errorf("启用 HTTPS 时证书文件和私钥文件路径都要填写")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("证书/私钥加载失败: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, fmt.Errorf("证书文件里没有可用证书: %s", certFile)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("证书解析失败: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return tls.Certificate{}, fmt.Errorf("证书尚未生效（生效时间 %s）", leaf.NotBefore.Format("2006-01-02"))
	}
	if now.After(leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("证书已过期（到期时间 %s），请先续期", leaf.NotAfter.Format("2006-01-02"))
	}
	cert.Leaf = leaf
	return cert, nil
}

// validateTLSSettings 校验 WebSettings 里与 HTTPS 有关的字段组合。
// 只在保存路径调用；启动读盘不因证书问题拒绝服务（监听准备失败时
// serve 会回退 HTTP 并打日志，避免证书误删把管理界面彻底锁死）。
func validateTLSSettings(s WebSettings) error {
	if err := validateDomainName(s.Domain); err != nil {
		return err
	}
	if s.HTTPS {
		if _, err := loadManagementCert(s.CertFile, s.KeyFile); err != nil {
			return err
		}
	}
	return nil
}
