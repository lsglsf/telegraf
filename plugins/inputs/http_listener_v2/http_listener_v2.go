package http_listener_v2

import (
	"compress/gzip"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/internal/config"
	tlsint "github.com/influxdata/telegraf/internal/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/influxdata/telegraf/plugins/parsers"
)

// defaultMaxBodySize is the default maximum request body size, in bytes.
// if the request body is over this size, we will return an HTTP 413 error.
// 500 MB
type Agent struct {
	Config *config.Config
}

const defaultMaxBodySize = 500 * 1024 * 1024

type TimeFunc func() time.Time

type HTTPListenerV2 struct {
	ServiceAddress string
	Path           string
	Methods        []string
	ReadTimeout    internal.Duration
	WriteTimeout   internal.Duration
	MaxBodySize    internal.Size
	Port           int
	Allowip        string

	tlsint.ServerConfig

	BasicUsername string
	BasicPassword string

	TimeFunc

	wg sync.WaitGroup

	listener net.Listener

	parsers.Parser
	acc telegraf.Accumulator
}

const sampleConfig = `
  ## Address and port to host HTTP listener on
  service_address = ":8080"

  ## Path to listen to.
  # path = "/telegraf"

  ## HTTP methods to accept.
  # methods = ["POST", "PUT"]

  ## maximum duration before timing out read of the request
  # read_timeout = "10s"
  ## maximum duration before timing out write of the response
  # write_timeout = "10s"

  ## Maximum allowed http request body size in bytes.
  ## 0 means to use the default of 524,288,00 bytes (500 mebibytes)
  # max_body_size = "500MB"

  ## Set one or more allowed client CA certificate file names to 
  ## enable mutually authenticated TLS connections
  # tls_allowed_cacerts = ["/etc/telegraf/clientca.pem"]

  ## Add service certificate and key
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"

  ## Optional username and password to accept for HTTP basic authentication.
  ## You probably want to make sure you have TLS configured above for this.
  # basic_username = "foobar"
  # basic_password = "barfoo"

  ## Data format to consume.
  ## Each data format has its own unique set of configuration options, read
  ## more about them here:
  ## https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_INPUT.md
  data_format = "influx"
`

func (h *HTTPListenerV2) SampleConfig() string {
	return sampleConfig
}

func (h *HTTPListenerV2) Description() string {
	return "Generic HTTP write listener"
}

func (h *HTTPListenerV2) Gather(_ telegraf.Accumulator) error {
	//func (h *HTTPListenerV2) Gather(a *Agent) error {
	return nil
}

func (h *HTTPListenerV2) SetParser(parser parsers.Parser) {
	h.Parser = parser
}

// Start starts the http listener service.
func (h *HTTPListenerV2) Start(acc telegraf.Accumulator) error {
	if h.MaxBodySize.Size == 0 {
		h.MaxBodySize.Size = defaultMaxBodySize
	}

	if h.ReadTimeout.Duration < time.Second {
		h.ReadTimeout.Duration = time.Second * 10
	}
	if h.WriteTimeout.Duration < time.Second {
		h.WriteTimeout.Duration = time.Second * 10
	}

	h.acc = acc

	tlsConf, err := h.ServerConfig.TLSConfig()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:         h.ServiceAddress,
		Handler:      h,
		ReadTimeout:  h.ReadTimeout.Duration,
		WriteTimeout: h.WriteTimeout.Duration,
		TLSConfig:    tlsConf,
	}

	var listener net.Listener
	if tlsConf != nil {
		listener, err = tls.Listen("tcp", h.ServiceAddress, tlsConf)
	} else {
		listener, err = net.Listen("tcp", h.ServiceAddress)
	}
	if err != nil {
		return err
	}
	h.listener = listener
	h.Port = listener.Addr().(*net.TCPAddr).Port

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		server.Serve(h.listener)
	}()

	log.Printf("I! Started HTTP listener V2 service on %s\n", h.ServiceAddress)

	return nil
}

// Stop cleans up all resources
func (h *HTTPListenerV2) Stop() {
	h.listener.Close()
	h.wg.Wait()

	log.Println("I! Stopped HTTP listener V2 service on ", h.ServiceAddress)
}

func (h *HTTPListenerV2) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.URL.Path == h.Path {
		h.AuthenticateIfSet(h.serveWrite, res, req)
	} else {
		h.AuthenticateIfSet(http.NotFound, res, req)
	}
}

func RemoteIp(req *http.Request) string {
	remoteAddr := req.RemoteAddr
	if ip := req.Header.Get("XRealIP"); ip != "" {
		remoteAddr = ip
	} else if ip = req.Header.Get("XForwardedFor"); ip != "" {
		remoteAddr = ip
	} else {
		remoteAddr, _, _ = net.SplitHostPort(remoteAddr)
	}

	if remoteAddr == "::1" {
		remoteAddr = "127.0.0.1"
	}
	//fmt.Println(remoteAddr)
	return remoteAddr
}

func (h *HTTPListenerV2) serveWrite(res http.ResponseWriter, req *http.Request) {
	// Check that the content length is not too large for us to handle.
	remoteip := RemoteIp(req)
	//fmt.Println(strings.Contains(h.Allowip, remoteip))
	ipstatus := strings.Contains(h.Allowip, remoteip)
	if ipstatus == false {
		badRequest(res)
		return
	}
	if req.ContentLength > h.MaxBodySize.Size {
		tooLarge(res)
		return
	}

	// Check if the requested HTTP method was specified in config.
	isAcceptedMethod := false
	for _, method := range h.Methods {
		if req.Method == method {
			isAcceptedMethod = true
			break
		}
	}
	if !isAcceptedMethod {
		methodNotAllowed(res)
		return
	}

	// Handle gzip request bodies
	body := req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		var err error
		body, err = gzip.NewReader(req.Body)
		if err != nil {
			log.Println("D! " + err.Error())
			badRequest(res)
			return
		}
		defer body.Close()
	}

	//fmt.Println(string(body))
	body = http.MaxBytesReader(res, body, h.MaxBodySize.Size)
	//fmt.Println(string(body))
	bytes, err := ioutil.ReadAll(body)
	bytes1 := bytes

	var dat map[string]interface{}
	if err := json.Unmarshal(bytes1, &dat); err == nil {
		//fmt.Println(dat, "xxxxxxxxxxxxxxxxxxxxxxx")
		//fmt.Println(dat["key"], dat["xxx"])
		log.Println("info " + string(bytes1))
		if dat["key"] == "urlcode" {
			//fmt.Println(dat["value"].([]string))
			var datas string

			for _, elem := range dat["value"].([]interface{}) {
				datas += elem.(string)
				datas += "\n"
				//		fmt.Println(datas, "xxxxxxxxx============================================")
			}
			f, err1 := os.OpenFile("/tmp/urlcode.txt", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0664)
			defer f.Close()
			if err1 != nil {
				fmt.Println(err1.Error())
			} else {
				_, err = f.Write([]byte(datas))
				okRequest(res)
			}

		}
	} else {
		fmt.Println(err)
	}
	//var dat map[string]interface{}
	//json.Unmarshal(bytes1, &dat)
	//fmt.Println(bytes1)

	if err != nil {
		tooLarge(res)
		return
	}

	metrics, err := h.Parse(bytes)

	if err != nil {
		log.Println("D! " + err.Error())
		badRequest(res)
		return
	}
	for _, m := range metrics {
		fmt.Println(m.Fields(), m.Name(), "XXXXXXXXXXXXXXXXXXXXX")
		h.acc.AddFields(m.Name(), m.Fields(), m.Tags(), m.Time())
	}
	res.WriteHeader(http.StatusNoContent)
}

func tooLarge(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusRequestEntityTooLarge)
	res.Write([]byte(`{"error":"http: request body too large"}`))
}

func methodNotAllowed(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusMethodNotAllowed)
	res.Write([]byte(`{"error":"http: method not allowed"}`))
}

func internalServerError(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusInternalServerError)
}

func badRequest(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusBadRequest)
	res.Write([]byte(`{"error":"http: bad request"}`))
}

func okRequest(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusBadRequest)
	res.Write([]byte(`{"status":"ok"}`))
}

func (h *HTTPListenerV2) AuthenticateIfSet(handler http.HandlerFunc, res http.ResponseWriter, req *http.Request) {
	if h.BasicUsername != "" && h.BasicPassword != "" {
		reqUsername, reqPassword, ok := req.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(reqUsername), []byte(h.BasicUsername)) != 1 ||
			subtle.ConstantTimeCompare([]byte(reqPassword), []byte(h.BasicPassword)) != 1 {

			http.Error(res, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		handler(res, req)
	} else {
		handler(res, req)
	}
}

func init() {
	inputs.Add("http_listener_v2", func() telegraf.Input {
		return &HTTPListenerV2{
			ServiceAddress: ":8080",
			TimeFunc:       time.Now,
			Path:           "/telegraf",
			Methods:        []string{"POST", "PUT"},
		}
	})
}
