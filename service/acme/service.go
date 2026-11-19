//go:build with_acme

package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	boxtls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/caddyserver/certmagic"
	"github.com/caddyserver/zerossl"
	"github.com/libdns/alidns"
	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func RegisterCertificateProvider(registry *certificate.Registry) {
	certificate.Register[option.ACMECertificateProviderOptions](registry, C.TypeACME, NewCertificateProvider)
}

var (
	_ adapter.CertificateProviderService = (*Service)(nil)
	_ adapter.ACMECertificateProvider    = (*Service)(nil)
)

type Service struct {
	certificate.Adapter
	ctx                 context.Context
	logger              log.ContextLogger
	config              *certmagic.Config
	zapLogger           *zap.Logger
	dataDirectory       string
	domain              []string
	nextProtos          []string
	openFirewall        bool
	openFirewallAddress bool
	firewallStopped     bool
}

type acmeFirewallKey struct {
	service    *Service
	identifier string
}

type acmeFirewallHold struct {
	port    int
	address net.IP
}

var (
	acmeFirewallGate        sync.Mutex
	acmeFirewallHeld        = map[acmeFirewallKey]acmeFirewallHold{}
	acmeFirewallOpened      bool
	acmeFirewallUnneeded    bool
	acmeFirewallDescription string
)

func NewCertificateProvider(ctx context.Context, logger log.ContextLogger, tag string, options option.ACMECertificateProviderOptions) (adapter.CertificateProviderService, error) {
	if len(options.Domain) == 0 {
		return nil, E.New("missing domain")
	}
	var acmeServer string
	switch options.Provider {
	case "", "letsencrypt":
		acmeServer = certmagic.LetsEncryptProductionCA
	case "zerossl":
		acmeServer = certmagic.ZeroSSLProductionCA
	default:
		if !strings.HasPrefix(options.Provider, "https://") {
			return nil, E.New("unsupported ACME provider: ", options.Provider)
		}
		acmeServer = options.Provider
	}
	if acmeServer == certmagic.ZeroSSLProductionCA &&
		(options.ExternalAccount == nil || options.ExternalAccount.KeyID == "") &&
		strings.TrimSpace(options.Email) == "" &&
		strings.TrimSpace(options.AccountKey) == "" {
		return nil, E.New("email is required to use the ZeroSSL ACME endpoint without external_account or account_key")
	}

	var (
		storage       certmagic.Storage
		dataDirectory string
	)
	if options.DataDirectory != "" {
		dataDirectory = filemanager.BasePath(ctx, os.ExpandEnv(options.DataDirectory))
		storage = &certmagic.FileStorage{Path: dataDirectory}
	} else {
		storage = certmagic.Default.Storage
	}

	zapLogger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(boxtls.ACMEEncoderConfig()),
		&boxtls.ACMELogWriter{Logger: logger},
		zap.DebugLevel,
	))

	config := &certmagic.Config{
		DefaultServerName: options.DefaultServerName,
		Storage:           storage,
		Logger:            zapLogger,
	}
	if options.KeyType != "" {
		var keyType certmagic.KeyType
		switch options.KeyType {
		case option.ACMEKeyTypeED25519:
			keyType = certmagic.ED25519
		case option.ACMEKeyTypeP256:
			keyType = certmagic.P256
		case option.ACMEKeyTypeP384:
			keyType = certmagic.P384
		case option.ACMEKeyTypeRSA2048:
			keyType = certmagic.RSA2048
		case option.ACMEKeyTypeRSA4096:
			keyType = certmagic.RSA4096
		default:
			return nil, E.New("unsupported ACME key type: ", string(options.KeyType))
		}
		config.KeySource = certmagic.StandardKeyGenerator{KeyType: keyType}
	}

	profile := options.Profile
	if profile == "" && acmeServer == certmagic.LetsEncryptProductionCA && slices.ContainsFunc(options.Domain, certmagic.SubjectIsIP) {
		profile = "shortlived"
	}

	acmeIssuer := certmagic.ACMEIssuer{
		CA:                      acmeServer,
		Email:                   options.Email,
		AccountKeyPEM:           options.AccountKey,
		Agreed:                  true,
		Profile:                 profile,
		DisableHTTPChallenge:    options.DisableHTTPChallenge,
		DisableTLSALPNChallenge: options.DisableTLSALPNChallenge,
		AltHTTPPort:             int(options.AlternativeHTTPPort),
		AltTLSALPNPort:          int(options.AlternativeTLSPort),
		Logger:                  zapLogger,
	}
	acmeHTTPClient, err := newACMEHTTPClient(ctx, logger, options)
	if err != nil {
		return nil, err
	}
	dnsSolver, err := newDNSSolver(options.DNS01Challenge, zapLogger, acmeHTTPClient)
	if err != nil {
		return nil, err
	}
	if dnsSolver != nil {
		acmeIssuer.DNS01Solver = dnsSolver
	}
	if options.ExternalAccount != nil && options.ExternalAccount.KeyID != "" {
		acmeIssuer.ExternalAccount = (*acme.EAB)(options.ExternalAccount)
	}
	if acmeServer == certmagic.ZeroSSLProductionCA {
		acmeIssuer.NewAccountFunc = func(ctx context.Context, acmeIssuer *certmagic.ACMEIssuer, account acme.Account) (acme.Account, error) {
			if acmeIssuer.ExternalAccount != nil {
				return account, nil
			}
			var err error
			acmeIssuer.ExternalAccount, account, err = createZeroSSLExternalAccountBinding(ctx, acmeIssuer, account, acmeHTTPClient)
			return account, err
		}
	}

	certmagicIssuer := certmagic.NewACMEIssuer(config, acmeIssuer)
	httpClientField := reflect.ValueOf(certmagicIssuer).Elem().FieldByName("httpClient")
	if !httpClientField.IsValid() || !httpClientField.CanAddr() {
		return nil, E.New("certmagic ACME issuer HTTP client field is unavailable")
	}
	reflect.NewAt(httpClientField.Type(), unsafe.Pointer(httpClientField.UnsafeAddr())).Elem().Set(reflect.ValueOf(acmeHTTPClient))
	config.Issuers = []certmagic.Issuer{certmagicIssuer}

	var nextProtos []string
	if !acmeIssuer.DisableTLSALPNChallenge && acmeIssuer.DNS01Solver == nil {
		nextProtos = []string{C.ACMETLS1Protocol}
	}
	return &Service{
		Adapter:             certificate.NewAdapter(C.TypeACME, tag),
		ctx:                 ctx,
		logger:              logger,
		config:              config,
		zapLogger:           zapLogger,
		dataDirectory:       dataDirectory,
		domain:              options.Domain,
		nextProtos:          nextProtos,
		openFirewall:        options.OpenFirewall,
		openFirewallAddress: options.OpenFirewallOnlyAddress,
	}, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if s.dataDirectory != "" {
			err := filemanager.MkdirAll(s.ctx, s.dataDirectory, 0o700)
			if err != nil {
				return E.Cause(err, "create ACME data directory")
			}
		}
		config := s.config
		cache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(certificate certmagic.Certificate) (*certmagic.Config, error) {
				return config, nil
			},
			Logger: s.zapLogger,
		})
		scope.Add(func() error {
			cache.Stop()
			return nil
		})
		config = certmagic.New(cache, *config)
		if s.openFirewall {
			s.cleanupLeftoverFirewall()
			if s.usesHTTPChallenge() {
				config.OnEvent = s.onCertEvent
				scope.Add(func() error {
					s.releaseFirewall()
					return nil
				})
			} else {
				s.logger.Info("open_firewall ignored because the HTTP-01 challenge is disabled")
			}
		}
		s.config = config
	case adapter.StartStateStart:
		return s.config.ManageAsync(s.ctx, s.domain)
	}
	return nil
}

func (s *Service) cleanupLeftoverFirewall() {
	acmeFirewallGate.Lock()
	defer acmeFirewallGate.Unlock()
	if acmeFirewallOpened || len(acmeFirewallHeld) > 0 {
		return
	}
	if err := closeACMEFirewall(); err != nil {
		s.logger.Warn("failed to clean up leftover ACME firewall: ", err)
	}
}

func (s *Service) onCertEvent(_ context.Context, event string, data map[string]any) error {
	switch event {
	case "cert_obtaining":
		s.activateFirewall(certEventIdentifier(data))
	case "cert_obtained", "cert_failed":
		s.deactivateFirewall(certEventIdentifier(data))
	}
	return nil
}

func certEventIdentifier(data map[string]any) string {
	if data == nil {
		return ""
	}
	identifier, _ := data["identifier"].(string)
	return identifier
}

func (s *Service) usesHTTPChallenge() bool {
	issuer := s.acmeIssuer()
	return issuer != nil && !issuer.DisableHTTPChallenge && issuer.DNS01Solver == nil
}

func (s *Service) httpChallengePort() int {
	if issuer := s.acmeIssuer(); issuer != nil && issuer.AltHTTPPort > 0 {
		return issuer.AltHTTPPort
	}
	return 80
}

func (s *Service) acmeIssuer() *certmagic.ACMEIssuer {
	if s.config == nil || len(s.config.Issuers) == 0 {
		return nil
	}
	issuer, _ := s.config.Issuers[0].(*certmagic.ACMEIssuer)
	return issuer
}

func (s *Service) activateFirewall(identifier string) {
	acmeFirewallGate.Lock()
	defer acmeFirewallGate.Unlock()
	if s.firewallStopped {
		return
	}
	key := acmeFirewallKey{service: s, identifier: identifier}
	if _, exists := acmeFirewallHeld[key]; exists {
		return
	}
	port := s.httpChallengePort()
	var address net.IP
	if s.openFirewallAddress {
		address = net.ParseIP(identifier)
		if address == nil {
			s.logger.Warn("open_firewall_only_address: ", identifier, " is not an IP, opening port ", port, " for all destinations")
		}
	}
	acmeFirewallHeld[key] = acmeFirewallHold{port: port, address: address}
	s.applyFirewallLocked()
}

func (s *Service) deactivateFirewall(identifier string) {
	acmeFirewallGate.Lock()
	defer acmeFirewallGate.Unlock()
	key := acmeFirewallKey{service: s, identifier: identifier}
	if _, exists := acmeFirewallHeld[key]; !exists {
		return
	}
	delete(acmeFirewallHeld, key)
	s.applyFirewallLocked()
}

func (s *Service) releaseFirewall() {
	acmeFirewallGate.Lock()
	defer acmeFirewallGate.Unlock()
	s.firewallStopped = true
	for key := range acmeFirewallHeld {
		if key.service == s {
			delete(acmeFirewallHeld, key)
		}
	}
	s.applyFirewallLocked()
}

func (s *Service) applyFirewallLocked() {
	allows := make([]firewallAllow, 0, len(acmeFirewallHeld))
	for _, hold := range acmeFirewallHeld {
		allows = append(allows, firewallAllow{port: hold.port, address: hold.address})
	}
	opened, err := syncACMEFirewall(allows)
	if err != nil {
		s.logger.Warn("failed to update firewall for ACME challenge: ", err)
		return
	}
	description := describeFirewallAllows(allows)
	if opened {
		acmeFirewallUnneeded = false
		if !acmeFirewallOpened || description != acmeFirewallDescription {
			s.logger.Info("opened firewall for ACME HTTP challenge on ", description)
		}
		acmeFirewallOpened = true
		acmeFirewallDescription = description
		return
	}
	if acmeFirewallOpened {
		s.logger.Info("closed firewall after ACME challenge")
	} else if len(allows) > 0 && !acmeFirewallUnneeded {
		s.logger.Info("no filter input chain; ACME challenge port is already reachable")
		acmeFirewallUnneeded = true
	}
	acmeFirewallOpened = false
	acmeFirewallDescription = ""
}

func describeFirewallAllows(allows []firewallAllow) string {
	allows = normalizeFirewallAllows(allows)
	parts := make([]string, 0, len(allows))
	for _, allow := range allows {
		if allow.address == nil {
			parts = append(parts, "port "+strconv.Itoa(allow.port))
			continue
		}
		parts = append(parts, "port "+strconv.Itoa(allow.port)+" address "+allow.address.String())
	}
	return strings.Join(parts, ", ")
}

func (s *Service) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.config.GetCertificate(hello)
}

func (s *Service) GetACMENextProtos() []string {
	return s.nextProtos
}

func newDNSSolver(dnsOptions *option.ACMEProviderDNS01ChallengeOptions, logger *zap.Logger, httpClient *http.Client) (*certmagic.DNS01Solver, error) {
	if dnsOptions == nil || dnsOptions.Provider == "" {
		return nil, nil
	}
	if dnsOptions.TTL < 0 {
		return nil, E.New("invalid ACME DNS01 ttl: ", dnsOptions.TTL.Build())
	}
	if dnsOptions.PropagationDelay < 0 {
		return nil, E.New("invalid ACME DNS01 propagation_delay: ", dnsOptions.PropagationDelay.Build())
	}
	if dnsOptions.PropagationTimeout < -1 {
		return nil, E.New("invalid ACME DNS01 propagation_timeout: ", dnsOptions.PropagationTimeout.Build())
	}
	solver := &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			TTL:                time.Duration(dnsOptions.TTL),
			PropagationDelay:   time.Duration(dnsOptions.PropagationDelay),
			PropagationTimeout: time.Duration(dnsOptions.PropagationTimeout),
			Resolvers:          dnsOptions.Resolvers,
			OverrideDomain:     dnsOptions.OverrideDomain,
			Logger:             logger.Named("dns_manager"),
		},
	}
	switch dnsOptions.Provider {
	case C.DNSProviderAliDNS:
		solver.DNSProvider = &alidns.Provider{
			CredentialInfo: alidns.CredentialInfo{
				AccessKeyID:     dnsOptions.AliDNSOptions.AccessKeyID,
				AccessKeySecret: dnsOptions.AliDNSOptions.AccessKeySecret,
				RegionID:        dnsOptions.AliDNSOptions.RegionID,
				SecurityToken:   dnsOptions.AliDNSOptions.SecurityToken,
			},
		}
	case C.DNSProviderCloudflare:
		solver.DNSProvider = &cloudflare.Provider{
			APIToken:   dnsOptions.CloudflareOptions.APIToken,
			ZoneToken:  dnsOptions.CloudflareOptions.ZoneToken,
			HTTPClient: httpClient,
		}
	case C.DNSProviderACMEDNS:
		solver.DNSProvider = &acmeDNSProvider{
			username:   dnsOptions.ACMEDNSOptions.Username,
			password:   dnsOptions.ACMEDNSOptions.Password,
			subdomain:  dnsOptions.ACMEDNSOptions.Subdomain,
			serverURL:  dnsOptions.ACMEDNSOptions.ServerURL,
			httpClient: httpClient,
		}
	default:
		return nil, E.New("unsupported ACME DNS01 provider type: ", dnsOptions.Provider)
	}
	return solver, nil
}

func createZeroSSLExternalAccountBinding(ctx context.Context, acmeIssuer *certmagic.ACMEIssuer, account acme.Account, httpClient *http.Client) (*acme.EAB, acme.Account, error) {
	email := strings.TrimSpace(acmeIssuer.Email)
	if email == "" {
		return nil, acme.Account{}, E.New("email is required to use the ZeroSSL ACME endpoint without external_account")
	}
	if len(account.Contact) == 0 {
		account.Contact = []string{"mailto:" + email}
	}
	if acmeIssuer.CertObtainTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, acmeIssuer.CertObtainTimeout)
		defer cancel()
	}

	form := url.Values{"email": []string{email}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, zerossl.BaseURL+"/acme/eab-credentials-email", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, account, E.Cause(err, "create ZeroSSL EAB request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", certmagic.UserAgent)

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, account, E.Cause(err, "request ZeroSSL EAB")
	}
	defer response.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, account, E.Cause(err, "decode ZeroSSL EAB response")
	}
	if response.StatusCode != http.StatusOK {
		return nil, account, E.New("failed getting ZeroSSL EAB credentials: HTTP ", response.StatusCode)
	}
	if result.Error.Code != 0 {
		return nil, account, E.New("failed getting ZeroSSL EAB credentials: ", result.Error.Type, " (code ", result.Error.Code, ")")
	}

	acmeIssuer.Logger.Info("generated ZeroSSL EAB credentials", zap.String("key_id", result.EABKID))

	return &acme.EAB{
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}, account, nil
}

func newACMEHTTPClient(ctx context.Context, logger log.ContextLogger, options option.ACMECertificateProviderOptions) (*http.Client, error) {
	httpClientOptions := common.PtrValueOrDefault(options.HTTPClient)
	httpClientManager := service.FromContext[adapter.HTTPClientManager](ctx)
	transport, err := httpClientManager.ResolveTransport(ctx, logger, httpClientOptions)
	if err != nil {
		return nil, E.Cause(err, "create ACME provider http client")
	}
	return &http.Client{
		Transport: transport,
		Timeout:   certmagic.HTTPTimeout,
	}, nil
}

type acmeDNSProvider struct {
	username   string
	password   string
	subdomain  string
	serverURL  string
	httpClient *http.Client
}

type acmeDNSRecord struct {
	resourceRecord libdns.RR
}

func (r acmeDNSRecord) RR() libdns.RR {
	return r.resourceRecord
}

func (p *acmeDNSProvider) AppendRecords(ctx context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	if p.username == "" {
		return nil, E.New("ACME-DNS username cannot be empty")
	}
	if p.password == "" {
		return nil, E.New("ACME-DNS password cannot be empty")
	}
	if p.subdomain == "" {
		return nil, E.New("ACME-DNS subdomain cannot be empty")
	}
	if p.serverURL == "" {
		return nil, E.New("ACME-DNS server_url cannot be empty")
	}
	appendedRecords := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		resourceRecord := record.RR()
		if resourceRecord.Type != "TXT" {
			return appendedRecords, E.New("ACME-DNS only supports adding TXT records")
		}
		requestBody, err := json.Marshal(map[string]string{
			"subdomain": p.subdomain,
			"txt":       resourceRecord.Data,
		})
		if err != nil {
			return appendedRecords, E.Cause(err, "marshal ACME-DNS update request")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.serverURL+"/update", bytes.NewReader(requestBody))
		if err != nil {
			return appendedRecords, E.Cause(err, "create ACME-DNS update request")
		}
		request.Header.Set("X-Api-User", p.username)
		request.Header.Set("X-Api-Key", p.password)
		request.Header.Set("Content-Type", "application/json")
		response, err := p.httpClient.Do(request)
		if err != nil {
			return appendedRecords, E.Cause(err, "update ACME-DNS record")
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return appendedRecords, E.New("update ACME-DNS record: HTTP ", response.StatusCode)
		}
		appendedRecords = append(appendedRecords, acmeDNSRecord{resourceRecord: libdns.RR{
			Type: "TXT",
			Name: resourceRecord.Name,
			Data: resourceRecord.Data,
		}})
	}
	return appendedRecords, nil
}

func (p *acmeDNSProvider) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}
