// Copyright (c) 2019 The Jaeger Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/jaegertracing/jaeger/storage/spanstore"
	"github.com/valyala/fasthttp"
)

func bearerTokenPropagationHandler(logger *zap.Logger, h http.Handler, validationAPI string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authHeaderValue := r.Header.Get("Authorization")
		// If no Authorization header is present, try with X-Forwarded-Access-Token
		if authHeaderValue == "" {
			authHeaderValue = r.Header.Get("X-Forwarded-Access-Token")
		}
		if authHeaderValue == "" {
			authHeaderValue = r.Header.Get("EIToken")
		}
		if authHeaderValue != "" {
			headerValue := strings.Split(authHeaderValue, " ")
			token := ""
			if len(headerValue) == 2 {
				// Make sure we only capture bearer token , not other types like Basic auth.
				if headerValue[0] == "Bearer" {
					token = headerValue[1]
				}
			} else if len(headerValue) == 1 {
				// Tread all value as a token
				token = authHeaderValue
			} else {
				logger.Error("Invalid authorization header value, skipping token propagation")
			}
			if err := tokenVerify(validationAPI, token); err != nil {
				w.Header().Set("status", "403")
				body := "{\"error\":\"Forbidden \",\"message\":\"The url is not allowed to be accessed\"}"
				var data []byte = []byte(body)
				w.Write(data)
				// h.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			h.ServeHTTP(w, r.WithContext(spanstore.ContextWithBearerToken(ctx, token)))
		} else {
			w.Header().Set("status", "401")
			body := "{\"error\":\"Unauthorized \",\"message\":\"The url is not allowed to be accessed\"}"
			var data []byte = []byte(body)
			w.Write(data)
			// h.ServeHTTP(w, r.WithContext(ctx))
		}
	})

}

func tokenVerify(url string, token string) error {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.Header.Add("Authorization", token)
	req.Header.SetMethod(http.MethodPost)
	req.SetRequestURI(url)
	req.Header.Set("Content-Type", "application/json")
	var data []byte = []byte("{\"token\":\"" + token + "\"}")
	req.SetBody(data)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := fasthttp.Do(req, resp); err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return errors.New("response code error:" + strconv.Itoa(resp.StatusCode()))
	}
	return nil
}
