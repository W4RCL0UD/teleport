/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"net/http"
	"strings"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/trace"

	"github.com/julienschmidt/httprouter"
)

const (
	SessionCookiePrefix = "__Secure-grv_app_session_"
)

// handleAuth handles authentication for an app
// When a `POST` request comes in, it'll check the request's cookies for one matching the name of the value of
// the `X-Cookie-Name` header. This cookie is set by the proxy and then passed on via the web UI setting the header,
// If these match, it'll create the proper session cookie on the app's subdomain.
func (h *Handler) handleAuth(w http.ResponseWriter, r *http.Request, p httprouter.Params) error {
	httplib.SetNoCacheHeaders(w.Header())

	cookieName := r.Header.Get("X-Cookie-Name")
	if cookieName == "" {
		return trace.BadParameter("X-Cookie-Name header missing")
	}

	if !strings.HasPrefix(cookieName, SessionCookiePrefix) {
		return trace.BadParameter("X-Cookie-Name is malformed")
	}

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		h.log.Warn("Request failed: cookie matching the name in the X-Cookie-Name header not found.")
		return trace.AccessDenied("access denied")
	}

	// Validate that the caller is asking for a session that exists.
	_, err = h.c.AccessPoint.GetAppSession(r.Context(), types.GetAppSessionRequest{
		SessionID: cookie.Value,
	})
	if err != nil {
		h.log.Warn("Request failed: session does not exist.")
		return trace.AccessDenied("access denied")
	}

	// Delete the temporary cookie by setting the expiry time to a minute ago, and the value to nothing
	// Note: we have to set this cookie on the same domain it was set from (the proxy).
	// This prevents reuse.of the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		Domain:   h.c.ProxyPublicAddrs[0].Host(),
		HttpOnly: true,
		Secure:   true,
		Expires:  h.c.Clock.Now().UTC().Add(-1 * time.Minute),
		SameSite: http.SameSiteNoneMode,
	})

	// Set the "Set-Cookie" header on the response.
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    cookie.Value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		// Set Same-Site policy for the session cookie to None in order to
		// support redirects that identity providers do during SSO auth.
		// Otherwise the session cookie won't be sent and the user will
		// get redirected to the application launcher.
		//
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
		SameSite: http.SameSiteNoneMode,
	})
	return nil
}
