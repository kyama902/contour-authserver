// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/projectcontour/contour-authserver/pkg/config"
)

type OAuth2Proxy struct {
	Log        logr.Logger
	HTTPClient *http.Client
	Config     *config.OAuth2ProxyConfig
}

var _ Checker = &OAuth2Proxy{}

func (o *OAuth2Proxy) Check(ctx context.Context, req *Request) (*Response, error) {
	o.Log.Info("checking request",
		"host", req.Request.Host,
		"path", req.Request.URL.Path,
		"id", req.ID,
	)

	ok, err := o.isAuthenticated(ctx, req)
	if err != nil {
		o.Log.Error(err, "auth validation failed")
		return &Response{}, err
	}

	if ok {
		res := createResponse(http.StatusOK)
		return &res, nil
	}

	res := createResponse(http.StatusTemporaryRedirect)
	res.Response.Header.Add("Location", fmt.Sprintf("%s?rd=%s", o.Config.SignInURL, req.Request.URL.String()))
	return &res, nil
}

func (o *OAuth2Proxy) isAuthenticated(ctx context.Context, req *Request) (bool, error) {
	r, err := http.NewRequest("GET", o.Config.AuthURL, nil)
	if err != nil {
		return false, err
	}
	r = r.WithContext(ctx)

	r.Header.Add("Cookie", req.Request.Header.Get("Cookie"))
	res, err := o.HTTPClient.Do(r)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusAccepted {
		return false, nil
	}
	return true, nil
}
