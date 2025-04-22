package backend

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	MS_BUILDTOKEN = "MIAOKO4|580JxAo049R|GEnERAl|1X571R930|T0kEN"
	DEFAULT_UA    = "MiaoSpeed/1.0"
)

type SSLType int

const (
	SSLTypeNONE SSLType = iota
	SSLTypeSECURE
	SSLTypeSELF_SIGNED
)

type MiaoSpeed struct {
	scfg        *MiaoSpeedSlave
	proxy       string
	buildToken  string
	token       string
	host        string
	port        int
	path        string
	nodes       []map[string]interface{}
	sslType     SSLType
	wsScheme    string
	verifySSL   bool
	SlaveRequest *MSSlaveRequest
	tempInfo    map[string][]interface{}
	lastProgress time.Time
	debug       bool
}

func NewMiaoSpeed(slaveConfig *MiaoSpeedSlave, slaveRequest *MSSlaveRequest, proxyConfig []map[string]interface{}, debug bool) (*MiaoSpeed, error) {
	ms := &MiaoSpeed{
		scfg:       slaveConfig,
		buildToken: slaveConfig.BuildToken,
		token:      slaveConfig.Token,
		nodes:      proxyConfig,
		sslType:    getSSLType(slaveConfig),
		debug:      debug,
		tempInfo: map[string][]interface{}{
			"节点名称": {},
			"类型":    {},
		},
	}

	// 解析地址
	if err := ms.parseAddress(); err != nil {
		return nil, err
	}

	ms.wsScheme, ms.verifySSL = ms.getWSOptions()
	ms.SlaveRequest = slaveRequest

	if len(ms.nodes) > 0 && len(ms.SlaveRequest.Nodes) == 0 {
		ms.initSlaveRequestNodes()
	}

	if err := ms.checkSlaveRequest(); err != nil {
		return nil, err
	}

	return ms, nil
}

func getSSLType(slaveConfig *MiaoSpeedSlave) SSLType {
	if !slaveConfig.TLS {
		return SSLTypeNONE
	}
	if slaveConfig.SkipCertVerify {
		return SSLTypeSELF_SIGNED
	}
	return SSLTypeSECURE
}

func (ms *MiaoSpeed) parseAddress() error {
	addr := ms.scfg.Address
	if addr == "" {
		return errors.New("address is empty")
	}

	i := strings.LastIndex(addr, ":")
	if i == -1 {
		return fmt.Errorf("invalid address format: %s", addr)
	}

	ms.host = addr[:i]
	portStr := addr[i+1:]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}
	ms.port = port

	ms.path = "/" + strings.TrimPrefix(ms.scfg.Path, "/")
	if ms.path == "/" {
		log.Printf("Warning: path is root")
	}

	return nil
}

func (ms *MiaoSpeed) initSlaveRequestNodes() {
	nodes := make([]SlaveRequestNode, len(ms.nodes))
	for i, node := range ms.nodes {
		nodes[i] = SlaveRequestNode{
			ID:   strconv.Itoa(i),
			Node: node,
		}
	}
	ms.SlaveRequest.Nodes = nodes
}

func (ms *MiaoSpeed) checkSlaveRequest() error {
	if len(ms.SlaveRequest.Options.Matrices) == 0 {
		return errors.New("SlaveRequest.Options.Matrices is empty")
	}
	return nil
}
