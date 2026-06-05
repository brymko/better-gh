package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
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
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.adminSecret)) != 1 {
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
	Name   string          `json:"name"`
	Policy createReqPolicy `json:"policy"`
}

type createReqPolicy struct {
	Default  string            `json:"default"`
	Unscoped map[string]string `json:"unscoped,omitempty"`
	Org      []createReqRule   `json:"org"`
	Repo     []createReqRule   `json:"repo"`
}

type createReqRule struct {
	Name        string            `json:"name"`
	Access      string            `json:"access"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
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

	var unscoped map[string]policy.Access
	for cat, acc := range req.Policy.Unscoped {
		var a policy.Access
		if err := a.UnmarshalText([]byte(acc)); err != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid unscoped access for " + cat + ": " + acc})
			return
		}
		if unscoped == nil {
			unscoped = make(map[string]policy.Access)
		}
		unscoped[cat] = a
	}

	var orgRules []policy.OrgRule
	for _, o := range req.Policy.Org {
		var a policy.Access
		if err := a.UnmarshalText([]byte(o.Access)); err != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid org access: " + o.Access})
			return
		}
		perms, err := parsePermissions(o.Permissions)
		if err != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid org permission: " + err.Error()})
			return
		}
		orgRules = append(orgRules, policy.OrgRule{Name: o.Name, Access: a, Permissions: perms})
	}

	var repoRules []policy.RepoRule
	for _, r := range req.Policy.Repo {
		var a policy.Access
		if err := a.UnmarshalText([]byte(r.Access)); err != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid repo access: " + r.Access})
			return
		}
		perms, err := parsePermissions(r.Permissions)
		if err != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid repo permission: " + err.Error()})
			return
		}
		repoRules = append(repoRules, policy.RepoRule{Name: r.Name, Access: a, Permissions: perms})
	}

	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: mode, Unscoped: unscoped},
		Org:      orgRules,
		Repo:     repoRules,
	}
	// Reject a misspelled per-resource key (round-19 D2): an unknown key never matches a request, so
	// a per-resource `none` written under a typo would silently degrade to the rule's base access.
	if err := pol.ValidateResourceKeys(); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	tok, secret, err := h.store.Create(req.Name, pol)
	if err != nil {
		slog.Error("failed to create token", "err", err)
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to create token"})
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
	type tokenDetail struct {
		ID        string        `json:"id"`
		Name      string        `json:"name"`
		Policy    policy.Policy `json:"policy"`
		CreatedAt string        `json:"created_at"`
		LastUsed  string        `json:"last_used,omitempty"`
		Revoked   bool          `json:"revoked"`
	}
	out := tokenDetail{
		ID:        tok.ID,
		Name:      tok.Name,
		Policy:    tok.Policy,
		CreatedAt: tok.CreatedAt.Format("2006-01-02T15:04:05Z"),
		Revoked:   tok.Revoked,
	}
	if !tok.LastUsed.IsZero() {
		out.LastUsed = tok.LastUsed.Format("2006-01-02T15:04:05Z")
	}
	jsonResp(w, http.StatusOK, out)
}

func (h *Handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// ?hard=true removes the entry entirely; otherwise it is marked revoked. Both go
	// through the running server's store so the change takes effect immediately and is
	// not clobbered by the server's own writes.
	if r.URL.Query().Get("hard") == "true" {
		ok, err := h.store.Delete(id)
		if err != nil {
			slog.Error("persisting token deletion failed", "id", id, "err", err)
			jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "could not persist deletion"})
			return
		}
		if !ok {
			jsonResp(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		jsonResp(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}
	ok, err := h.store.Revoke(id)
	if err != nil {
		slog.Error("persisting token revocation failed", "id", id, "err", err)
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "could not persist revocation"})
		return
	}
	if !ok {
		jsonResp(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func parsePermissions(m map[string]string) (map[string]policy.Access, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[string]policy.Access, len(m))
	for resource, acc := range m {
		var a policy.Access
		if err := a.UnmarshalText([]byte(acc)); err != nil {
			return nil, fmt.Errorf("%s=%s: %w", resource, acc, err)
		}
		out[resource] = a
	}
	return out, nil
}

func jsonResp(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
