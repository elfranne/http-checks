/* Portions of this code are based on and/or derived from the HTTP
   check found in the NCR DevOps Platform nagiosfoundation collection of
   checks found at https://github.com/ncr-devops-platform/nagiosfoundation */

package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev2 "github.com/sensu/core/v2"
	"github.com/sensu/sensu-plugin-sdk/sensu"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	URL                string
	TrustedCAFile      string
	InsecureSkipVerify bool
	Timeout            int
	Headers            []string
	MTLSKeyFile        string
	MTLSCertFile       string
	Schema             string
	Warning            int64
	Critical           int64
	Above              bool
	Below              bool
	Equal              bool
}

var (
	tlsConfig tls.Config

	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "http-size",
			Short:    "HTTP GET Check",
			Keyspace: "sensu.io/plugins/http-size/config",
		},
	}

	options = []sensu.ConfigOption{
		&sensu.PluginConfigOption[string]{
			Path:      "url",
			Env:       "CHECK_URL",
			Argument:  "url",
			Shorthand: "u",
			Default:   "http://localhost:80/",
			Usage:     "URL to get",
			Value:     &plugin.URL,
		},
		&sensu.PluginConfigOption[bool]{
			Path:      "insecure-skip-verify",
			Env:       "",
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "Skip TLS certificate verification (not recommended!)",
			Value:     &plugin.InsecureSkipVerify,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "trusted-ca-file",
			Env:       "",
			Argument:  "trusted-ca-file",
			Shorthand: "t",
			Default:   "",
			Usage:     "TLS CA certificate bundle in PEM format",
			Value:     &plugin.TrustedCAFile,
		},
		&sensu.PluginConfigOption[int]{
			Path:      "timeout",
			Env:       "",
			Argument:  "timeout",
			Shorthand: "T",
			Default:   15,
			Usage:     "Request timeout in seconds",
			Value:     &plugin.Timeout,
		},
		&sensu.SlicePluginConfigOption[string]{
			Path:      "header",
			Env:       "",
			Argument:  "header",
			Shorthand: "H",
			Default:   []string{},
			Usage:     "Additional header(s) to send in check request",
			Value:     &plugin.Headers,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "mtls-key-file",
			Env:       "",
			Argument:  "mtls-key-file",
			Shorthand: "K",
			Default:   "",
			Usage:     "Key file for mutual TLS auth in PEM format",
			Value:     &plugin.MTLSKeyFile,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "mtls-cert-file",
			Env:       "",
			Argument:  "mtls-cert-file",
			Shorthand: "C",
			Default:   "",
			Usage:     "Certificate file for mutual TLS auth in PEM format",
			Value:     &plugin.MTLSCertFile,
		},
		&sensu.PluginConfigOption[string]{
			Path:      "schema",
			Argument:  "schema",
			Shorthand: "s",
			Default:   "",
			Usage:     "Schema to prepend perf data",
			Value:     &plugin.Schema,
		},
		&sensu.PluginConfigOption[int64]{
			Path:      "warning",
			Env:       "",
			Argument:  "warning",
			Shorthand: "w",
			Default:   0,
			Usage:     "Warning",
			Value:     &plugin.Warning,
		},
		&sensu.PluginConfigOption[int64]{
			Path:      "critical",
			Env:       "",
			Argument:  "critical",
			Shorthand: "c",
			Default:   0,
			Usage:     "Critical value",
			Value:     &plugin.Critical,
		},
		&sensu.PluginConfigOption[bool]{
			Path:      "above",
			Env:       "",
			Argument:  "above",
			Shorthand: "a",
			Default:   false,
			Usage:     "Comparaison type",
			Value:     &plugin.Above,
		},
		&sensu.PluginConfigOption[bool]{
			Path:      "below",
			Env:       "",
			Argument:  "below",
			Shorthand: "b",
			Default:   true,
			Usage:     "Comparaison type",
			Value:     &plugin.Below,
		},
		&sensu.PluginConfigOption[bool]{
			Path:      "equal",
			Env:       "",
			Argument:  "equal",
			Shorthand: "e",
			Default:   false,
			Usage:     "Comparaison type",
			Value:     &plugin.Equal,
		},
	}
)

func main() {
	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if len(plugin.URL) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--url or CHECK_URL environment variable is required")
	}
	if len(plugin.Headers) > 0 {
		for _, header := range plugin.Headers {
			headerSplit := strings.SplitN(header, ":", 2)
			if len(headerSplit) != 2 {
				return sensu.CheckStateWarning, fmt.Errorf("--header %q value malformed should be \"Header-Name: Header Value\"", header)
			}
		}
	}
	if len(plugin.TrustedCAFile) > 0 {
		caCertPool, err := corev2.LoadCACerts(plugin.TrustedCAFile)
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("error loading specified CA file")
		}
		tlsConfig.RootCAs = caCertPool
	}
	tlsConfig.InsecureSkipVerify = plugin.InsecureSkipVerify

	if (len(plugin.MTLSKeyFile) > 0 && len(plugin.MTLSCertFile) == 0) || (len(plugin.MTLSCertFile) > 0 && len(plugin.MTLSKeyFile) == 0) {
		return sensu.CheckStateWarning, fmt.Errorf("mTLS auth requires both --mtls-key-file and --mtls-cert-file")
	}
	if len(plugin.MTLSKeyFile) > 0 && len(plugin.MTLSCertFile) > 0 {
		cert, err := tls.LoadX509KeyPair(plugin.MTLSCertFile, plugin.MTLSKeyFile)
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("failed to load mTLS key pair %s/%s: %v", plugin.MTLSCertFile, plugin.MTLSKeyFile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return sensu.CheckStateOK, nil
}

func executeCheck(event *corev2.Event) (int, error) {

	client := http.DefaultClient
	client.Transport = http.DefaultTransport
	client.Timeout = time.Duration(plugin.Timeout) * time.Second

	checkURL, err := url.Parse(plugin.URL)
	if err != nil {
		fmt.Printf("http-size UNKNOWN: %s: %s | %ssize=0\n", plugin.URL, err, plugin.Schema)
		return sensu.CheckStateUnknown, nil
	}
	if checkURL.Scheme == "https" {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest("GET", plugin.URL, nil)
	if err != nil {
		fmt.Printf("http-size UNKNOWN: %s: %s | %ssize=0\n", plugin.URL, err, plugin.Schema)
		return sensu.CheckStateUnknown, nil
	}

	if len(plugin.Headers) > 0 {
		for _, header := range plugin.Headers {
			headerSplit := strings.SplitN(header, ":", 2)
			headerKey := strings.TrimSpace(headerSplit[0])
			headerValue := strings.TrimSpace(headerSplit[1])
			if strings.EqualFold(headerKey, "host") {
				req.Host = headerValue
				continue
			}
			req.Header.Set(headerKey, headerValue)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("http-size UNKNOWN: %s: %s | %ssize=0\n", plugin.URL, err, plugin.Schema)
		return sensu.CheckStateUnknown, nil
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	var buf bytes.Buffer
	size, err := buf.ReadFrom(resp.Body)
	if err != nil {
		fmt.Printf("http-size UNKNOWN: %s: %s | %ssize=0\n", plugin.URL, err, plugin.Schema)
		return sensu.CheckStateUnknown, nil
	}

	if (plugin.Above && size > plugin.Critical) || (plugin.Below && size < plugin.Critical) || (plugin.Equal && size == plugin.Critical) {
		fmt.Printf("http-size CRITICAL: %s Body: %d Bytes| %ssize=%d\n", plugin.URL, size, plugin.Schema, size)
		return sensu.CheckStateCritical, nil
	}

	if (plugin.Above && size > plugin.Warning) || (plugin.Below && size < plugin.Warning) || (plugin.Equal && size == plugin.Warning) {
		fmt.Printf("http-size WARNING: %s Body: %d Bytes | %ssize=%d\n", plugin.URL, size, plugin.Schema, size)
		return sensu.CheckStateWarning, nil
	}

	fmt.Printf("http-size OK: %s Body: %d Bytes | %ssize=%d\n", plugin.URL, size, plugin.Schema, size)
	return sensu.CheckStateOK, nil
}
