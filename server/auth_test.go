package server

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestUserAuth_NextFlowUrl(t *testing.T) {
	u := UserAuth{Data: SessionData{NeedOtp: true}}
	assert.Equal(t, url.URL{Path: "/login/otp"}, *u.NextFlowUrl(&url.URL{}))
	assert.Equal(t, url.URL{Path: "/login/otp", RawQuery: url.Values{"redirect": {"/hello"}}.Encode()}, *u.NextFlowUrl(&url.URL{Path: "/hello"}))
	assert.Equal(t, url.URL{Path: "/login/otp", RawQuery: url.Values{"redirect": {"/hello?a=A"}}.Encode()}, *u.NextFlowUrl(&url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}}.Encode()}))
	u.Data.NeedOtp = false
	assert.Nil(t, u.NextFlowUrl(&url.URL{}))
}

func TestUserAuth_IsGuest(t *testing.T) {
	var u UserAuth
	assert.True(t, u.IsGuest())
	u.Data.ID = uuid.New()
	assert.False(t, u.IsGuest())
}

type fakeSessionStore struct {
	m        map[string]any
	saveFunc func(map[string]any) error
}

func (f *fakeSessionStore) Context() context.Context          { return context.Background() }
func (f *fakeSessionStore) SessionID() string                 { return "fakeSessionStore" }
func (f *fakeSessionStore) Set(key string, value interface{}) { f.m[key] = value }

func (f *fakeSessionStore) Get(key string) (a interface{}, ok bool) {
	if a, ok = f.m[key]; false {
	}
	return
}

func (f *fakeSessionStore) Delete(key string) (i interface{}) {
	i = f.m[key]
	delete(f.m, key)
	return
}

func (f *fakeSessionStore) Save() error {
	return f.saveFunc(f.m)
}

func (f *fakeSessionStore) Flush() error {
	return nil
}

func TestUserAuth_SaveSessionData(t *testing.T) {
	f := &fakeSessionStore{m: make(map[string]any)}
	u := UserAuth{Data: SessionData{ID: uuid.UUID{5, 6, 7}, NeedOtp: true}, Session: f}

	// fail to save
	f.saveFunc = func(m map[string]any) error { return fmt.Errorf("failed") }
	assert.Error(t, u.SaveSessionData())

	// try with success
	var m2 map[string]any
	f.saveFunc = func(m map[string]any) error {
		m2 = m
		return nil
	}
	assert.NoError(t, u.SaveSessionData())
	assert.Equal(t, map[string]any{"session-data": SessionData{ID: uuid.UUID{5, 6, 7}, NeedOtp: true}}, m2)
}

func TestRequireAuthentication(t *testing.T) {
}

func TestOptionalAuthentication(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/hello", nil)
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	auth, err := internalAuthenticationHandler(rec, req)
	assert.NoError(t, err)
	assert.True(t, auth.IsGuest())
	auth.Data.ID = uuid.UUID{5, 6, 7}
	assert.NoError(t, auth.SaveSessionData())
}

func Test_internalAuthenticationHandler(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/hello", nil)
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	auth, err := internalAuthenticationHandler(rec, req)
	assert.NoError(t, err)
	assert.True(t, auth.IsGuest())
	auth.Data.ID = uuid.UUID{5, 6, 7}
	assert.NoError(t, auth.SaveSessionData())

	req, err = http.NewRequest(http.MethodGet, "https://example.com/world", nil)
	assert.NoError(t, err)
	req.Header.Set("Cookie", rec.Header().Get("Set-Cookie"))
	rec = httptest.NewRecorder()
	auth, err = internalAuthenticationHandler(rec, req)
	assert.NoError(t, err)
	assert.False(t, auth.IsGuest())
	assert.Equal(t, uuid.UUID{5, 6, 7}, auth.Data.ID)
}

func TestPrepareRedirectUrl(t *testing.T) {
	assert.Equal(t, url.URL{Path: "/hello"}, *PrepareRedirectUrl("/hello", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/world"}, *PrepareRedirectUrl("/world", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello"}}.Encode()}, *PrepareRedirectUrl("/a", &url.URL{Path: "/hello"}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello?a=A"}}.Encode()}, *PrepareRedirectUrl("/a", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}}.Encode()}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello?a=A&b=B"}}.Encode()}, *PrepareRedirectUrl("/a", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}, "b": {"B"}}.Encode()}))
}
