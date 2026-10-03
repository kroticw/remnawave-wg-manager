// Package mcpserver exposes the WireGuard client operations as MCP tools.
package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/httpapi"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
)

const restartNote = " Changes rewrite the config profile and restart Xray on the profile's nodes, dropping their connections for a few seconds."

type inboundArgs struct {
	Profile string `json:"profile" jsonschema:"config profile name"`
	Tag     string `json:"tag" jsonschema:"WireGuard inbound tag"`
}

type createArgs struct {
	inboundArgs
	User    string `json:"user" jsonschema:"panel user id, or a new username to create"`
	Address string `json:"address,omitempty" jsonschema:"optional client address; the lowest free one by default"`
}

type clientArgs struct {
	inboundArgs
	Email string `json:"email" jsonschema:"peer email, the panel user id"`
}

type list[T any] struct {
	Items []T `json:"items"`
}

type configOut struct {
	Config string `json:"config"`
}

type done struct {
	OK bool `json:"ok"`
}

func cred(req *mcp.CallToolRequest) (panel.Credentials, error) {
	if req.Extra == nil || req.Extra.Header == nil {
		return panel.Credentials{}, errors.New("missing Authorization header")
	}
	token, ok := strings.CutPrefix(req.Extra.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return panel.Credentials{}, errors.New("missing bearer token")
	}
	return panel.Credentials{Token: token}, nil
}

func boolPtr(b bool) *bool { return &b }

func newServer(svc httpapi.Service) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "remnawave-wg-manager", Version: "v0.1.0"}, nil)

	mcp.AddTool(s, &mcp.Tool{Name: "wg_list_inbounds", Description: "List WireGuard inbounds in all config profiles.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, list[clients.InboundInfo], error) {
			c, err := cred(req)
			if err != nil {
				return nil, list[clients.InboundInfo]{}, err
			}
			items, err := svc.Inbounds(ctx, c)
			return nil, list[clients.InboundInfo]{Items: items}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "wg_list_clients", Description: "List clients (peers) of a WireGuard inbound.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, a inboundArgs) (*mcp.CallToolResult, list[clients.ClientInfo], error) {
			c, err := cred(req)
			if err != nil {
				return nil, list[clients.ClientInfo]{}, err
			}
			items, err := svc.Clients(ctx, c, a.Profile, a.Tag)
			return nil, list[clients.ClientInfo]{Items: items}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "wg_create_client", Description: "Create a WireGuard client bound to a panel user. Does not return the config." + restartNote,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false)}},
		func(ctx context.Context, req *mcp.CallToolRequest, a createArgs) (*mcp.CallToolResult, clients.ClientInfo, error) {
			c, err := cred(req)
			if err != nil {
				return nil, clients.ClientInfo{}, err
			}
			ci, err := svc.Create(ctx, c, a.Profile, a.Tag, a.User, a.Address)
			return nil, ci, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "wg_delete_client", Description: "Delete a WireGuard client." + restartNote,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, a clientArgs) (*mcp.CallToolResult, done, error) {
			c, err := cred(req)
			if err != nil {
				return nil, done{}, err
			}
			err = svc.Delete(ctx, c, a.Profile, a.Tag, a.Email)
			return nil, done{OK: err == nil}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "wg_get_client_config", Description: "Return the client .conf. It contains the client's PRIVATE KEY.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, a clientArgs) (*mcp.CallToolResult, configOut, error) {
			c, err := cred(req)
			if err != nil {
				return nil, configOut{}, err
			}
			conf, err := svc.Config(ctx, c, a.Profile, a.Tag, a.Email)
			return nil, configOut{Config: conf}, err
		})
	return s
}

// Handler serves MCP over Streamable HTTP.
func Handler(svc httpapi.Service) http.Handler {
	s := newServer(svc)
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
}
