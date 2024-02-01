package portal

import (
	"embed"
	"errors"
	"html/template"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type CaptivePortal struct {
	logger *zap.SugaredLogger

	mu sync.Mutex
	lastInteraction time.Time
	server *http.Server
	visibleSSIDs []string
	savedSSIDs []string
	lastError error

	ssid string
	psk  string

	inputRecieved atomic.Bool
	workers sync.WaitGroup
}

type TemplateData struct{
	SSID string

	VisibleSSIDs []string
	KnownSSIDs []string
	LastError string
}

//go:embed templates/*
var templates embed.FS

func NewPortal(logger *zap.SugaredLogger, bindAddr string) *CaptivePortal {
	mux := http.NewServeMux()
	cp := &CaptivePortal{logger: logger, server: &http.Server{Addr: bindAddr, Handler: mux}}
	mux.HandleFunc("/", cp.index)
	mux.HandleFunc("/save", cp.saveWifi)
	return cp
}

func (cp *CaptivePortal) Run() {
	cp.workers.Add(1)
	go func() {
		defer cp.workers.Done()
		err := cp.server.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			cp.logger.Error(err)
		}
	}()
}

func (cp *CaptivePortal) Stop() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	err := cp.server.Close()
	cp.ssid = ""
	cp.psk = ""
	cp.inputRecieved.Store(false)
	return err
}

func (cp *CaptivePortal) GetUserInput() (string, string, bool) {
	ok := cp.inputRecieved.Load()
	if ok {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		ssid := cp.ssid
		psk := cp.psk
		cp.ssid = ""
		cp.psk = ""
		cp.inputRecieved.Store(false)
		return ssid, psk, ok
	}
	return "", "", ok
}

func (cp *CaptivePortal) GetLastInteraction() (time.Time) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.lastInteraction
}

func (cp *CaptivePortal) SetData(visibleSSIDs, savedSSIDs []string, lastError error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.visibleSSIDs = visibleSSIDs
	cp.savedSSIDs = savedSSIDs
	cp.lastError = lastError
}

func (cp *CaptivePortal) index(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	cp.mu.Lock()
	cp.lastInteraction = time.Now()
	data := TemplateData{
		SSID: cp.ssid,
		VisibleSSIDs: cp.visibleSSIDs,
		KnownSSIDs: cp.savedSSIDs,
	}
	if cp.lastError != nil {
		data.LastError = cp.lastError.Error()
	}
	cp.mu.Unlock()

	t, err := template.ParseFS(templates, "templates/base.html", "templates/index.html")
	if err != nil {
		cp.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	err = t.Execute(w, data)
	if err != nil {
		cp.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (cp *CaptivePortal) saveWifi(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if r.Method == "POST" {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		cp.ssid = r.FormValue("ssid")
		cp.psk = r.FormValue("password")
		cp.logger.Debugf("saving credentials for %s", cp.ssid)
		cp.inputRecieved.Store(true)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
