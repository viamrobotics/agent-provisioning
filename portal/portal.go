package portal

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.viam.com/utils"
)

const (
	BindAddr = ":50052"
)

type CaptivePortal struct {
	mu sync.Mutex

	server *http.Server
	visibleSSIDs []string
	knownSSIDs []string
	lastError error

	ssid string
	psk  string

	inputRecieved atomic.Bool
}

type TemplateData struct{
	SSID string

	VisibleSSIDs []string
	KnownSSIDs []string
	LastError string
}

//go:embed templates/*
var templates embed.FS

func NewPortal(SSIDs, savedSSIDs []string, lastError error) *CaptivePortal {
	mux := http.NewServeMux()
	cp := &CaptivePortal{
		server: &http.Server{Addr: BindAddr, Handler: mux},
		visibleSSIDs: SSIDs,
		knownSSIDs: savedSSIDs,
	}
	mux.HandleFunc("/", cp.index)
	mux.HandleFunc("/captive", cp.serveCaptive)
	mux.HandleFunc("/wifilist", cp.getWifiList)
	mux.HandleFunc("/save", cp.saveWifi)
	return cp
}

func (cp *CaptivePortal) Run(ctx context.Context) error {

	go func() {
		for {
			if cp.inputRecieved.Load() {
				utils.SelectContextOrWait(ctx, time.Second * 5)
				break
			}
			if !utils.SelectContextOrWait(ctx, time.Second * 1) {
				break
			}
		}
		err := cp.Stop()
		if err != nil {
			log.Println(err)
		}
		cp.inputRecieved.Store(false)
	}()

	return cp.server.ListenAndServe()
}

func (cp *CaptivePortal) Stop() error {
	return cp.server.Close()
}

func (cp *CaptivePortal) GetSettings() (string, string, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.ssid, cp.psk, cp.lastError
}

func (cp *CaptivePortal) index(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	log.Printf(r.Host, r.URL.Path, r.Body, r.Header, r.Method)

	cp.mu.Lock()
	data := TemplateData{
		SSID: cp.ssid,
		VisibleSSIDs: cp.visibleSSIDs,
		KnownSSIDs: cp.knownSSIDs,
	}
	if cp.lastError != nil {
		data.LastError = cp.lastError.Error()
	}

	cp.mu.Unlock()
	t, err := template.ParseFS(templates, "templates/base.html", "templates/index.html")
	if err != nil {
		panic(err)
	}
	err = t.Execute(w, data)
	if err != nil {
		panic(err)
	}
}


func (cp *CaptivePortal) getWifiList(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	log.Printf(r.Host, r.URL.Path, r.Body, r.Header, r.Method)


	cp.mu.Lock()
	data := TemplateData{
		SSID: cp.ssid,
		VisibleSSIDs: cp.visibleSSIDs,
		KnownSSIDs: cp.knownSSIDs,
	}
	if cp.lastError != nil {
		data.LastError = cp.lastError.Error()
	}
	cp.mu.Unlock()

	t, _ := template.ParseFS(templates, "templates/base.html", "templates/wifiform.html")
	err := t.Execute(w, data)

	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}

func (cp *CaptivePortal) saveWifi(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	log.Printf(r.Host, r.URL.Path, r.Body, r.Header, r.Method)

	if r.Method == "POST" {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		cp.ssid = r.FormValue("ssid")
		cp.psk = r.FormValue("password")
		log.Printf("saving credentials for %s", cp.ssid)
		cp.inputRecieved.Store(true)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}


// Captive-portal magic for phones
type CaptiveJson struct {
	Captive       bool   `json:"captive"`
	UserPortalUrl string `json:"user-portal-url"`
}

var captive CaptiveJson = CaptiveJson{
	Captive:       true,
	UserPortalUrl: "http://192.168.2.2/",
}

func (cp *CaptivePortal) serveCaptive(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	log.Printf(r.Host, r.URL.Path, r.Body, r.Header, r.Method)
	j, err := json.Marshal(captive)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/captive+json")
	w.Write(j)
}
