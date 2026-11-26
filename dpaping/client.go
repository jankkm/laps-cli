// SPDX-License-Identifier: MIT

package dpaping

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	isdkey "github.com/oiweiwei/go-msrpc/msrpc/gkdi/isdkey/v1"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// RPCClient fetches group keys from a domain controller via MS-GKDI GetKey
// over authenticated, sealed DCE/RPC (NTLM). It connects lazily on first use,
// so a run without encrypted passwords never opens an RPC connection.
type RPCClient struct {
	Server   string // DC hostname
	Username string // "user@domain" or "DOMAIN\\user"
	Password string
	Timeout  time.Duration

	once sync.Once
	err  error
	ctx  context.Context
	conn dcerpc.Conn
	cli  isdkey.ISDKeyClient
}

func (c *RPCClient) connect(ctx context.Context) error {
	c.once.Do(func() {
		c.ctx = gssapi.NewSecurityContext(ctx)
		opts := []dcerpc.Option{
			epm.EndpointMapper(c.ctx, net.JoinHostPort(c.Server, "135"), dcerpc.WithInsecure()),
		}
		if c.Timeout > 0 {
			opts = append(opts, dcerpc.WithTimeout(c.Timeout))
		}
		conn, err := dcerpc.Dial(c.ctx, "ncacn_ip_tcp:"+c.Server, opts...)
		if err != nil {
			c.err = fmt.Errorf("gkdi: connect to %s: %w", c.Server, err)
			return
		}
		cli, err := isdkey.NewISDKeyClient(c.ctx, conn,
			dcerpc.WithSeal(),
			dcerpc.WithMechanism(ssp.NTLM),
			dcerpc.WithCredentials(credential.NewFromPassword(c.Username, c.Password)),
		)
		if err != nil {
			conn.Close(c.ctx)
			c.err = fmt.Errorf("gkdi: bind: %w", err)
			return
		}
		c.conn, c.cli = conn, cli
	})
	return c.err
}

// GetKey implements KeyFetcher.
func (c *RPCClient) GetKey(ctx context.Context, sd []byte, root GUID, l0, l1, l2 int32) ([]byte, error) {
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	resp, err := c.cli.GetKey(c.ctx, &isdkey.GetKeyRequest{
		TargetSDLength: uint32(len(sd)),
		TargetSD:       sd,
		RootKeyID: &dtyp.GUID{
			Data1: binary.LittleEndian.Uint32(root[0:4]),
			Data2: binary.LittleEndian.Uint16(root[4:6]),
			Data3: binary.LittleEndian.Uint16(root[6:8]),
			Data4: append([]byte(nil), root[8:16]...),
		},
		L0KeyID: l0,
		L1KeyID: l1,
		L2KeyID: l2,
	})
	if err != nil {
		return nil, fmt.Errorf("gkdi: GetKey: %w", err)
	}
	return resp.Out, nil
}

// Close closes the RPC connection if one was opened.
func (c *RPCClient) Close() {
	if c.conn != nil {
		c.conn.Close(c.ctx)
	}
}
