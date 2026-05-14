package delegation

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
)

type S4UConfig struct {
	TargetSPN        string
	Username         string
	Domain           string
	Password         string
	Hash             string
	TargetUser       string
	DomainController string
	Cache            string
	KeytabPath       string
}

type S4UResult struct {
	TGT         []byte
	TGS         []byte
	SessionKey  []byte
	CcachePath  string
	Username    string
	Impersonate string
}

func PerformS4U2Self(cfg *S4UConfig) (*S4UResult, error) {
	realm := strings.ToUpper(cfg.Domain)

	var krbClient *client.Client
	var err error

	if cfg.KeytabPath != "" {
		kt, ktErr := keytab.Load(cfg.KeytabPath)
		if ktErr != nil {
			return nil, fmt.Errorf("load keytab: %w", ktErr)
		}
		krbClient = client.NewWithKeytab(cfg.Username, realm, kt, nil)
		if loginErr := krbClient.Login(); loginErr != nil {
			return nil, fmt.Errorf("kerberos login: %w", loginErr)
		}
	} else if cfg.Cache != "" {
		ccache, cErr := credentials.LoadCCache(cfg.Cache)
		if cErr != nil {
			return nil, fmt.Errorf("load ccache: %w", cErr)
		}
		krbClient, err = client.NewFromCCache(ccache, nil)
		if err != nil {
			return nil, fmt.Errorf("client from ccache: %w", err)
		}
	} else if cfg.Password != "" {
		krbClient = client.NewWithPassword(cfg.Username, realm, cfg.Password, nil)
		if loginErr := krbClient.Login(); loginErr != nil {
			return nil, fmt.Errorf("kerberos login: %w", loginErr)
		}
	} else if cfg.Hash != "" {
		hashBytes, _ := hex.DecodeString(cfg.Hash)
		kt := keytab.New()
		kt.AddEntry(cfg.Username, realm, string(hashBytes), time.Now(), 18, 0)
		krbClient = client.NewWithKeytab(cfg.Username, realm, kt, nil)
		if loginErr := krbClient.Login(); loginErr != nil {
			return nil, fmt.Errorf("kerberos login: %w", loginErr)
		}
	} else {
		return nil, fmt.Errorf("credentials required: password, hash, keytab, or ccache")
	}

	spn := cfg.TargetSPN
	if !strings.Contains(spn, "/") {
		spn = fmt.Sprintf("cifs/%s", spn)
	}

	tkt, ekey, err := krbClient.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("get service ticket: %w", err)
	}

	_ = ekey

	result := &S4UResult{
		Username:    cfg.Username,
		Impersonate: cfg.TargetUser,
	}

	tgtBytes, err := tkt.Marshal()
	if err == nil {
		result.TGT = tgtBytes
	}

	return result, nil
}

func PerformS4U2Proxy(cfg *S4UConfig) (*S4UResult, error) {
	return PerformS4U2Self(cfg)
}

func requestServiceTicket(krbClient *client.Client, spn string) (*messages.Ticket, error) {
	tkt, _, err := krbClient.GetServiceTicket(spn)
	if err != nil {
		return nil, err
	}
	return &tkt, nil
}

func sendKDCRequest(host string, reqBytes []byte) ([]byte, error) {
	addr := host
	if !strings.Contains(addr, ":") {
		addr = addr + ":88"
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to KDC: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("write message: %w", err)
	}

	if _, err := conn.Read(lenBuf); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 1<<20 {
		return nil, fmt.Errorf("response too large: %d bytes", respLen)
	}
	respBytes := make([]byte, respLen)
	if _, err := conn.Read(respBytes); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return respBytes, nil
}

func parseTGSRep(data []byte) (*messages.TGSRep, error) {
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(data); err != nil {
		return nil, err
	}
	return &tgsRep, nil
}

func parseSPN(spn string) (string, string) {
	parts := strings.SplitN(spn, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "cifs", spn
}

func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func generateRandomNonce() int {
	b := generateRandomBytes(4)
	return int(binary.BigEndian.Uint32(b) & 0x7FFFFFFF)
}

func generateRandomSessionKey() []byte {
	return generateRandomBytes(16)
}

func typesPrincipalName(nameType int, nameString string) interface{} {
	return nil
}
