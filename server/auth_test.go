package server

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestUserAuth_NextFlowUrl(t *testing.T) {
	u := UserAuth{NeedOtp: true}
	assert.Equal(t, url.URL{Path: "/login/otp"}, *u.NextFlowUrl(&url.URL{}))
	assert.Equal(t, url.URL{Path: "/login/otp", RawQuery: url.Values{"redirect": {"/hello"}}.Encode()}, *u.NextFlowUrl(&url.URL{Path: "/hello"}))
	assert.Equal(t, url.URL{Path: "/login/otp", RawQuery: url.Values{"redirect": {"/hello?a=A"}}.Encode()}, *u.NextFlowUrl(&url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}}.Encode()}))
	u.NeedOtp = false
	assert.Nil(t, u.NextFlowUrl(&url.URL{}))
}

func TestUserAuth_IsGuest(t *testing.T) {
	var u UserAuth
	assert.True(t, u.IsGuest())
	u.Subject = uuid.NewString()
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

func TestRequireAuthentication(t *testing.T) {
}

func TestOptionalAuthentication(t *testing.T) {
	h := &HttpServer{}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/hello", nil)
	assert.NoError(t, err)
	auth, err := h.internalAuthenticationHandler(nil, req)
	assert.NoError(t, err)
	assert.True(t, auth.IsGuest())
	auth.Subject = "567"
}

func TestPrepareRedirectUrl(t *testing.T) {
	assert.Equal(t, url.URL{Path: "/hello"}, *PrepareRedirectUrl("/hello", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/world"}, *PrepareRedirectUrl("/world", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello"}}.Encode()}, *PrepareRedirectUrl("/a", &url.URL{Path: "/hello"}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello?a=A"}}.Encode()}, *PrepareRedirectUrl("/a", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}}.Encode()}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello?a=A&b=B"}}.Encode()}, *PrepareRedirectUrl("/a", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}, "b": {"B"}}.Encode()}))

	assert.Equal(t, url.URL{Path: "/hello", RawQuery: "z=y"}, *PrepareRedirectUrl("/hello?z=y", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/world", RawQuery: "z=y"}, *PrepareRedirectUrl("/world?z=y", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"z": {"y"}, "redirect": {"/hello"}}.Encode()}, *PrepareRedirectUrl("/a?z=y", &url.URL{Path: "/hello"}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"z": {"y"}, "redirect": {"/hello?a=A"}}.Encode()}, *PrepareRedirectUrl("/a?z=y", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}}.Encode()}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"z": {"y"}, "redirect": {"/hello?a=A&b=B"}}.Encode()}, *PrepareRedirectUrl("/a?z=y", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}, "b": {"B"}}.Encode()}))
}
