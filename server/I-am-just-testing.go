package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-oauth2/oauth2/v4"
)

var _ oauth2.TokenStore = &TestingStruct{}

type TestingStruct struct {
}

func (t TestingStruct) Create(ctx context.Context, info oauth2.TokenInfo) error {
	fmt.Println(info.GetAccessExpiresIn())
	fmt.Println(info.GetRefreshExpiresIn())
	return errors.New("error")
}

func (t TestingStruct) RemoveByCode(ctx context.Context, code string) error {
	//TODO implement me
	panic("implement me")
}

func (t TestingStruct) RemoveByAccess(ctx context.Context, access string) error {
	//TODO implement me
	panic("implement me")
}

func (t TestingStruct) RemoveByRefresh(ctx context.Context, refresh string) error {
	//TODO implement me
	panic("implement me")
}

func (t TestingStruct) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (t TestingStruct) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	//TODO implement me
	panic("implement me")
}

func (t TestingStruct) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	//TODO implement me
	panic("implement me")
}
