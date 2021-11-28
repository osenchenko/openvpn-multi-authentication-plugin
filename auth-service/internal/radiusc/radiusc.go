package radiusc

import (
	"auth-service/internal/globals"
	"context"
	"crypto/rand"
	"strconv"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"layeh.com/radius/rfc2759"
	"layeh.com/radius/vendors/microsoft"
)

type RadiusClient struct {
	config globals.IRadiusServersProvider
	l      globals.AppLogger
}

// var defaultClient *RadiusClient

func NewClient(c globals.IRadiusServersProvider) *RadiusClient {
	return &RadiusClient{config: c, l: c.AppLogger()}
}

// func Client() *RadiusClient {
// 	return defaultClient
// }

func (rc *RadiusClient) Authenticate(u, p, clientIP string, srv globals.RadiusProvider) (*radius.Packet, error) {
	// rcfg := rc.config.RadiusSrv(0)

	packet := radius.New(radius.CodeAccessRequest, []byte(srv.GetSecret()))
	if rc.config.NASID() != "" {
		_ = rfc2865.NASIdentifier_AddString(packet, rc.config.NASID())
	}
	if rc.config.NASIpV4Addr() != nil {
		_ = rfc2865.NASIPAddress_Set(packet, rc.config.NASIpV4Addr())
	}
	if rc.config.NASPort() != 0 {
		_ = rfc2865.NASPort_Set(packet, rfc2865.NASPort(rc.config.NASPort()))
	} else {
		_ = rfc2865.NASPort_Set(packet, 443)
	}
	_ = rfc2865.NASPortType_Set(packet, rfc2865.NASPortType_Value_Virtual)
	_ = rfc2865.CallingStationID_Set(packet, []byte(clientIP))

	err := rfc2865.UserName_SetString(packet, u)
	if err != nil {
		rc.l.Error(err)
		return nil, err
	}

	if srv.GetProto() == "mschapv2" {
		n := 16
		authenticatorChallenge := make([]byte, n)
		peerChallenge := make([]byte, n)
		_, err := rand.Read(authenticatorChallenge)
		if err != nil {
			rc.l.Error(err)
			return nil, err
		}
		_, err = rand.Read(peerChallenge)
		if err != nil {
			rc.l.Error(err)
			return nil, err
		}
		got, err := rfc2759.GenerateNTResponse(authenticatorChallenge, peerChallenge, []byte(u), []byte(p))
		if err != nil {
			rc.l.Error(err)
			return nil, err
		}

		err = microsoft.MSCHAPChallenge_Set(packet, authenticatorChallenge)
		if err != nil {
			rc.l.Error(err)
			return nil, err
		}

		// https://tools.ietf.org/html/rfc2548#2.3.2. MS-CHAP2-Response
		resp := make([]byte, 0, 50)
		resp = append(resp, '1', '0')
		resp = append(resp, peerChallenge...)
		resp = append(resp, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
		resp = append(resp, got...)

		err = microsoft.MSCHAP2Response_Add(packet, resp)
		if err != nil {
			rc.l.Error(err)
			return nil, err
		}

	}

	if srv.GetProto() == "pap" {
		rfc2865.UserPassword_SetString(packet, p)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(srv.GetResponseTimeoutSec())*time.Second)
	defer cancel()
	response, err := radius.Exchange(ctx, packet, srv.GetAddress()+":"+strconv.Itoa(srv.GetPort()))
	if err != nil {
		// rc.l.Debugf("%#v", response)
		rc.l.Error(err)
		return nil, err
	}
	if response.Code != radius.CodeAccessAccept {
		rc.l.Errorf("%d: %s. User: %s, server: %s", response.Code, response.Code.String(), u, srv.GetAddress())
		rc.l.Debugf("%#v", response)
		return nil, globals.ErrAuthenticationFailed
	}
	return response, nil
}

func (rc *RadiusClient) AuthenticateUser(u, p, clientIP string) (bool, *globals.NetworkData, error) {
	authResult := false
	srv, err := rc.config.GetAvailableRadiusAuthServer()
	if err != nil {
		return authResult, nil, err
	}
	pkt, err := rc.Authenticate(u, p, clientIP, srv)
	if err != nil {
		return authResult, nil, err
	}
	authResult = true
	var vs, ns string
	v := rfc2865.FramedIPAddress_Get(pkt)
	if v != nil {
		vs = v.String()
	}
	v2 := rfc2865.FramedIPNetmask_Get(pkt)
	if v2 != nil {
		ns = v2.String()
	}
	ndata := &globals.NetworkData{
		IP:      vs,
		Netmask: ns,
	}
	return authResult, ndata, nil
}

func (rc *RadiusClient) CheckAuthenticateUser(u, p string, serverIdx int) (bool, error) {
	authResult := false
	srv, err := rc.config.RadiusServer(serverIdx)
	if err != nil {
		return authResult, err
	}
	_, err = rc.Authenticate(u, p, "", srv)
	if err != nil {
		return authResult, err
	}
	authResult = true
	return authResult, nil
}
