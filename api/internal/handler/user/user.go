/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package user

import (
	"github.com/apisix/manager-api/internal/core/store"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/shiningrush/droplet"
	"github.com/shiningrush/droplet/wrapper"
	wgin "github.com/shiningrush/droplet/wrapper/gin"

	"github.com/apisix/manager-api/internal/conf"
	"github.com/apisix/manager-api/internal/handler"
	"github.com/apisix/manager-api/internal/utils/consts"
)

type Handler struct {
	authStore *store.GenericStore
}

func NewHandler() (handler.RouteRegister, error) {
	return &Handler{
		authStore: store.GetStore(store.HubKeySystemConfig),
	}, nil
}

func (h *Handler) ApplyRoute(r *gin.Engine) {
	r.POST("/apisix/admin/user/add", wgin.Wraps(h.userAdd,
		wrapper.InputType(reflect.TypeOf(Input{}))))
}

type Session struct {
	Token string `json:"token"`
}

type Input struct {
	// user name
	Token string `json:"token" validate:"required"`

	Username string `json:"username" validate:"required"`
	// password
	Password string `json:"password" validate:"required"`
}

func (h *Handler) userAdd(c droplet.Context) (interface{}, error) {
	input := c.Input().(*Input)
	perToken := input.Token
	if perToken != "abc12345" {
		return nil, consts.ErrPermission
	}

	username := input.Username
	password := input.Password

	_, err := h.authStore.Stg.Get(c.Context(), username)
	if err == nil {
		return nil, consts.ExistUsernamePassword
	}
	h.authStore.Stg.Create(c.Context(), username, password)

	// create JWT for session
	claims := jwt.StandardClaims{
		Subject:   username,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Second * time.Duration(conf.AuthConf.ExpireTime)).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte(conf.AuthConf.Secret))

	// output token
	return &Session{
		Token: signedToken,
	}, nil
}
