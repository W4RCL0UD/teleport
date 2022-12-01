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

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/httplib"
)

// handleAuth handles authentication for an app
// When a `POST` request comes in, it'll check the request's cookies for one matching the name of the value of
// the `X-Cookie-Name` header. This cookie is set by the proxy and then passed on via the web UI setting the header,
// If these match, it'll create the proper session cookie on the app's subdomain.
func (h *Handler) handleAuth(w http.ResponseWriter, r *http.Request, p httprouter.Params) error {
	httplib.SetNoCacheHeaders(w.Header())

	cookieValue := r.Header.Get("X-Cookie-Value")
	if cookieValue == "" {
		return trace.BadParameter("X-Cookie-Value header missing")
	}

	// Validate that the caller is asking for a session that exists.
	_, err := h.c.AccessPoint.GetAppSession(r.Context(), types.GetAppSessionRequest{
		SessionID: cookieValue,
	})
	if err != nil {
		h.log.WithError(err).Warn("Request failed: unable to get app session")
		return trace.AccessDenied("access denied")
	}

	// Set the "Set-Cookie" header on the response.
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    cookieValue,
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
