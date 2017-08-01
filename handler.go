package main

import (
	"github.com/jmcvetta/randutil"
	"github.com/miekg/dns"
	"net"
	"sync"
	"time"
)

const (
	notIPQuery = 0
	_IP4Query  = 4
	_IP6Query  = 6
)

type Question struct {
	qname      string
	qtype      string
	qclass     string
	clientaddr net.IP
}

type LogMsg struct {
	clientIP      string
	clientPort    int
	clientId      uint16
	mode          string
	qname         string
	qtype         string
	qclass        string
	rcode         string
	ecs           bool
	ecsClientAddr string
	hit           string
	upstream      []UpstreamCtx
}

func (q *Question) String() string {
	return q.qname + " " + q.qclass + " " + q.qtype + " " + q.clientaddr.String()
}

type GODNSHandler struct {
	resolver        *Resolver
	cache, negCache Cache
	hosts           Hosts
}

func NewHandler() *GODNSHandler {

	var (
		clientConfig    *dns.ClientConfig
		cacheConfig     CacheSettings
		resolver        *Resolver
		cache, negCache Cache
	)

	resolvConfig := settings.ResolvConfig
	clientConfig, err := dns.ClientConfigFromFile(resolvConfig.ResolvFile)
	if err != nil {
		logger.Warn(":%s is not a valid resolv.conf file\n", resolvConfig.ResolvFile)
		logger.Error(err.Error())
		panic(err)
	}
	clientConfig.Timeout = resolvConfig.Timeout
	resolver = &Resolver{
		clientConfig, map[string]*NsStat{},
		make([]string, 0), sync.RWMutex{},
		time.Now(), make([]randutil.Choice, 0)}
	resolver.Init()

	cacheConfig = settings.Cache
	switch cacheConfig.Backend {
	case "memory":
		cache = &MemoryCache{
			Backend:  make(map[string]Mesg, cacheConfig.Maxcount),
			Expire:   time.Duration(cacheConfig.Expire) * time.Second,
			Maxcount: cacheConfig.Maxcount,
		}
		negCache = &MemoryCache{
			Backend:  make(map[string]Mesg),
			Expire:   time.Duration(cacheConfig.Expire) * time.Second / 2,
			Maxcount: cacheConfig.Maxcount,
		}

	case "memcache":
		cache = NewMemcachedCache(
			settings.Memcache.Servers,
			int32(cacheConfig.Expire))
		negCache = NewMemcachedCache(
			settings.Memcache.Servers,
			int32(cacheConfig.Expire/2))
	case "redis":
		// cache = &MemoryCache{
		// 	Backend:    make(map[string]*dns.Msg),
		//  Expire:   time.Duration(cacheConfig.Expire) * time.Second,
		// 	Serializer: new(JsonSerializer),
		// 	Maxcount:   cacheConfig.Maxcount,
		// }
		panic("Redis cache backend not implement yet")
	default:
		logger.Error("Invalid cache backend %s", cacheConfig.Backend)
		panic("Invalid cache backend")
	}

	L := func(cache Cache, negCache Cache) {
		for {
			time.Sleep(10 * time.Second)
			cache.ClearExpire()
			negCache.ClearExpire()
		}
	}

	go L(cache, negCache)

	var hosts Hosts
	if settings.Hosts.Enable {
		hosts = NewHosts(settings.Hosts, settings.Redis)
	}

	return &GODNSHandler{resolver, cache, negCache, hosts}
}

func (h *GODNSHandler) do(Net string, w dns.ResponseWriter, req *dns.Msg) (lmsg LogMsg) {
	q := req.Question[0]

	var remote net.IP

	if Net == "tcp" {
		remote = w.RemoteAddr().(*net.TCPAddr).IP
		lmsg.clientIP = w.RemoteAddr().(*net.TCPAddr).IP.String()
		lmsg.clientPort = w.RemoteAddr().(*net.TCPAddr).Port
	} else {
		remote = w.RemoteAddr().(*net.UDPAddr).IP
		lmsg.clientIP = w.RemoteAddr().(*net.UDPAddr).IP.String()
		lmsg.clientPort = w.RemoteAddr().(*net.UDPAddr).Port
	}
	Q := Question{UnFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass], remote}

	lmsg.clientId = req.Id
	lmsg.mode = Net
	lmsg.qname = Q.String()
	lmsg.qtype = dns.TypeToString[q.Qtype]
	lmsg.qclass = dns.ClassToString[q.Qclass]

	IPQuery := h.isIPQuery(q)

	// Query hosts
	if settings.Hosts.Enable && IPQuery > 0 {
		if ips, ok := h.hosts.Get(Q.qname, IPQuery); ok {
			m := new(dns.Msg)
			m.SetReply(req)

			switch IPQuery {
			case _IP4Query:
				rr_header := dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    settings.Hosts.TTL,
				}
				for _, ip := range ips {
					a := &dns.A{rr_header, ip}
					m.Answer = append(m.Answer, a)
				}
			case _IP6Query:
				rr_header := dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    settings.Hosts.TTL,
				}
				for _, ip := range ips {
					aaaa := &dns.AAAA{rr_header, ip}
					m.Answer = append(m.Answer, aaaa)
				}
			}

			lmsg.rcode = dns.RcodeToString[m.Rcode]
			w.WriteMsg(m)
			logger.Debug("%s found in hosts file", Q.qname)
			return
		} else {
			logger.Debug("%s didn't found in hosts file", Q.qname)
		}
	}

	extra := make([]dns.RR, 0)

	lmsg.ecs = false
	lmsg.ecsClientAddr = "0"
	ecs := false
	for _, xx := range req.Extra {
		if rr, ok := xx.(*dns.OPT); ok {
			for _, yy := range rr.Option {
				if edns_subnet, ok1 := yy.(*dns.EDNS0_SUBNET); ok1 {
					Q.clientaddr = edns_subnet.Address
					extra = append(extra, rr)
					ecs = true
					lmsg.ecs = true
					lmsg.ecsClientAddr = Q.clientaddr.String()
				}
			}
		} else {
			extra = append(extra, rr)
		}
	}

	// Only query cache when qtype == 'A'|'AAAA' , qclass == 'IN'
	key := KeyGen(Q)
	//logger.Debug("cache key %s", key)

	if IPQuery > 0 {
		mesg, err := h.cache.Get(key)
		if err != nil {
			if mesg, err = h.negCache.Get(key); err != nil {
				logger.Debug("%s didn't hit cache", Q.String())
				lmsg.hit = "MISS"
			} else {
				lmsg.hit = "HIT"
				logger.Debug("%s hit negative cache", Q.String())
				lmsg.rcode = dns.RcodeToString[dns.RcodeServerFailure]
				dns.HandleFailed(w, req)
				return
			}
		} else {
			lmsg.hit = "HIT"
			logger.Debug("%s hit cache", Q.String())
			// we need this copy against concurrent modification of Id
			msg := *mesg

			lmsg.rcode = dns.RcodeToString[msg.Rcode]
			msg.Id = req.Id
			w.WriteMsg(&msg)
			return
		}
	}

	//add client addr to extra, if extra empty.
	if ecs != true {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.Hdr.Class = 4096
		e := new(dns.EDNS0_SUBNET)
		e.Code = dns.EDNS0SUBNET

		if remote.To4() != nil {
			e.Family = 1
			e.SourceNetmask = 32
		} else { //IPV6
			e.Family = 2
			e.SourceNetmask = 128
		}
		e.SourceScope = 0
		e.Address = remote
		o.Option = append(o.Option, e)
		extra = append(extra, o)
	}
	req.Extra = extra

	mesg, upstream, err := h.resolver.Lookup(Net, req)
	lmsg.upstream = upstream

	if err != nil {
		lmsg.rcode = dns.RcodeToString[dns.RcodeServerFailure]
		dns.HandleFailed(w, req)

		// cache the failure, too!
		if err = h.negCache.Set(key, nil); err != nil {
			logger.Warn("Set %s negative cache failed: %v", Q.String(), err)
		}
		return
	}

	if ecs != true {
		mesg.Extra = make([]dns.RR, 0)
	}

	lmsg.rcode = dns.RcodeToString[mesg.Rcode]
	w.WriteMsg(mesg)

	if IPQuery > 0 && (len(mesg.Answer) > 0 || len(mesg.Ns) > 0) {
		err = h.cache.Set(key, mesg)
		if err != nil {
			logger.Warn("Set %s cache failed: %s", Q.String(), err.Error())
		}
		logger.Debug("Insert %s into cache", Q.String())
	}
	return
}

func (h *GODNSHandler) queryLog(lmsg LogMsg) {
	/*
	 * log format:
	 * [client_addr]#[client_port]#[dns_id]
	 * [mode]
	 * [qname]
	 * [qclass]
	 * [qtype]
	 * [rcode]
	 * [ecs_mode] [ecs_client_addr]
	 * [upstream]
	 * [HIT/MISS]
	 */

	upstream := ""
	for _, u := range lmsg.upstream {
		upstream += u.name
		upstream += " "
	}

	/*
		    logger.Info("query: %s(ip)#%d(port)#%d(id) %s(mode)
			%s(qname) %s(qclass) %s(qtype) %s(rcode) %t(ecs)/%s(ecsClientAddr) %s(upstream) %s(hit)",
	*/
	logger.Info("query: %s#%d#%d %s %s %s %s %s %t/%s %s %s",
		lmsg.clientIP, lmsg.clientPort, lmsg.clientId, lmsg.mode,
		lmsg.qname, lmsg.qclass, lmsg.qtype, lmsg.rcode, lmsg.ecs,
		lmsg.ecsClientAddr, upstream, lmsg.hit)
}

func (h *GODNSHandler) DoTCP(w dns.ResponseWriter, req *dns.Msg) {
	lmsg := h.do("tcp", w, req)
	h.queryLog(lmsg)
}

func (h *GODNSHandler) DoUDP(w dns.ResponseWriter, req *dns.Msg) {
	lmsg := h.do("udp", w, req)
	h.queryLog(lmsg)
}

func (h *GODNSHandler) isIPQuery(q dns.Question) int {
	if q.Qclass != dns.ClassINET {
		return notIPQuery
	}

	switch q.Qtype {
	case dns.TypeA, dns.TypeCNAME, dns.TypeNS:
		return _IP4Query
	case dns.TypeAAAA:
		return _IP6Query
	default:
		return notIPQuery
	}
}

func UnFqdn(s string) string {
	if dns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}
