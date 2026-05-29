package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"better-gh/internal/auth"
	"better-gh/internal/policy"
	"better-gh/internal/store"
)

//go:embed static
var staticFS embed.FS

type Handler struct {
	store       *store.Store
	adminSecret string
	mux         *http.ServeMux
}

func NewHandler(s *store.Store, adminSecret string) *Handler {
	h := &Handler{store: s, adminSecret: adminSecret}
	h.mux = http.NewServeMux()

	staticSub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticSub))

	h.mux.Handle("GET /api/tokens", h.requireAdmin(http.HandlerFunc(h.listTokens)))
	h.mux.Handle("POST /api/tokens", h.requireAdmin(http.HandlerFunc(h.createToken)))
	h.mux.Handle("GET /api/tokens/{id}", h.requireAdmin(http.HandlerFunc(h.getToken)))
	h.mux.Handle("DELETE /api/tokens/{id}", h.requireAdmin(http.HandlerFunc(h.revokeToken)))

	h.mux.Handle("/", fileServer)

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := auth.ExtractToken(r.Header.Get("Authorization"))
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != h.adminSecret {
			jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) listTokens(w http.ResponseWriter, r *http.Request) {
	tokens := h.store.List()
	type tokenResp struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
		LastUsed  string `json:"last_used,omitempty"`
		Revoked   bool   `json:"revoked"`
	}
	out := make([]tokenResp, len(tokens))
	for i, t := range tokens {
		out[i] = tokenResp{
			ID:        t.ID,
			Name:      t.Name,
			CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z"),
			Revoked:   t.Revoked,
		}
		if !t.LastUsed.IsZero() {
			out[i].LastUsed = t.LastUsed.Format("2006-01-02T15:04:05Z")
		}
	}
	jsonResp(w, http.StatusOK, out)
}

type createReq struct {
	Name   string         `json:"name"`
	Policy createReqPolicy `json:"policy"`
}

type createReqPolicy struct {
	Default string           `json:"default"`
	Org     []createReqRule  `json:"org"`
	Repo    []createReqRule  `json:"repo"`
}

type createReqRule struct {
	Name   string `json:"name"`
	Access string `json:"access"`
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	var mode policy.DefaultMode
	if req.Policy.Default == "" {
		req.Policy.Default = "deny"
	}
	if err := mode.UnmarshalText([]byte(req.Policy.Default)); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid default mode"})
		return
	}

	var orgRules []policy.OrgRule
	for _, o := range req.Policy.Org {
		var a policy.Access
		if err := a.UnmarshalText([]byte(o.Access)); err != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid org access: " + o.Access})
			return
		}
		orgRules = append(orgRules, policy.OrgRule{Name: o.Name, Access: a})
	}

	var repoRules []policy.RepoRule
	for _, r := range req.Policy.Repo {
		var a policy.Access
		if err := a.UnmarshalText([]byte(r.Access)); err != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid repo access: " + r.Access})
			return
		}
		repoRules = append(repoRules, policy.RepoRule{Name: r.Name, Access: a})
	}

	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: mode},
		Org:      orgRules,
		Repo:     repoRules,
	}

	tok, secret, err := h.store.Create(req.Name, pol)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	jsonResp(w, http.StatusCreated, map[string]string{
		"id":     tok.ID,
		"name":   tok.Name,
		"secret": secret,
	})
}

func (h *Handler) getToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tok := h.store.Get(id)
	if tok == nil {
		jsonResp(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	jsonResp(w, http.StatusOK, tok)
}

func (h *Handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !h.store.Revoke(id) {
		jsonResp(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func jsonResp(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
