package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jmcvetta/randutil"
	"github.com/miekg/dns"
)

type ResolvError struct {
	qname, net  string
	nameservers []string
}

const (
	NS_MAX_EXCHANGE            int   = 3
	NS_UPDATE_CHOICES_INTERVAL int64 = 10
)

type NsStat struct {
	name    string
	rtt     int64
	failcnt int
	reqcnt  int
	weight  int
}

func (e ResolvError) Error() string {
	errmsg := fmt.Sprintf("%s resolv failed on %s (%s)", e.qname, strings.Join(e.nameservers, "; "), e.net)
	return errmsg
}

type Resolver struct {
	config     *dns.ClientConfig
	nsstat     map[string]*NsStat
	ns         []string
	mu         sync.RWMutex
	lastmodify time.Time
	choices    []randutil.Choice
}

type UpstreamCtx struct {
	name string
	rtt  time.Duration
	resp *dns.Msg
	err  error
}

// Lookup will ask each nameserver in top-to-bottom fashion, starting a new request
// in every second, and return as early as possbile (have an answer).
// It returns an error if no request has succeeded.
func (r *Resolver) Lookup(net string, req *dns.Msg) (message *dns.Msg, upstream []UpstreamCtx, err error) {
	c := &dns.Client{
		Net:          net,
		ReadTimeout:  r.Timeout(),
		WriteTimeout: r.Timeout(),
	}

	if net == "udp" && settings.ResolvConfig.SetEDNS0 {
		req = req.SetEdns0(65535, true)
	}

	qname := req.Question[0].Name

	for i := 0; i < NS_MAX_EXCHANGE; i++ {
		nameserver := r.getNextNameserver()
		nr, rtt, err := c.Exchange(req, nameserver)
		upstream = append(upstream, UpstreamCtx{nameserver, rtt, nr, err})

		r.recordNsStat(nameserver, rtt.Nanoseconds()/1000000, err)

		if err != nil {
			logger.Warn("%s socket error on %s, %s", qname, nameserver, err.Error())
			continue
		}
		// If SERVFAIL happen, should return immediately and try another upstream resolver.
		// However, other Error code like NXDOMAIN is an clear response stating
		// that it has been verified no such domain existas and ask other resolvers
		// would make no sense. See more about #20
		if nr != nil && nr.Rcode != dns.RcodeSuccess {
			logger.Warn("%s failed to get an valid answer on %s", qname, nameserver)
			if nr.Rcode == dns.RcodeServerFailure {
				continue
			}
		} else {
			logger.Debug("%s resolv on %s (%s) ttl: %d", UnFqdn(qname), nameserver, net, rtt)
			return nr, upstream, nil
		}
	}

	return nil, upstream, ResolvError{qname, net, r.ns}
}

func (r *Resolver) getNextNameserver() (nameserver string) {
	r.mu.Lock()

	res, _ := randutil.WeightedChoice(r.choices)

	r.mu.Unlock()

	return res.Item.(string)
}

func (r *Resolver) Timeout() time.Duration {
	return time.Duration(r.config.Timeout) * time.Second
}

func (r *Resolver) Init() {
	// Namservers return the array of nameservers, with port number appended.
	// '#' in the name is treated as port separator, as with dnsmasq.
	for _, server := range r.config.Servers {
		if i := strings.IndexByte(server, '#'); i > 0 {
			server = net.JoinHostPort(server[:i], server[i+1:])
		} else {
			server = net.JoinHostPort(server, r.config.Port)
		}
		r.ns = append(r.ns, server)
	}

	for _, name := range r.ns {
		r.nsstat[name] = &NsStat{name, 0, 0, 0, 1}
		r.choices = append(r.choices, randutil.Choice{1, name})
	}
}

func (r *Resolver) recordNsStat(name string, rtt int64, err error) {
	r.mu.Lock()

	stat := r.nsstat[name]

	stat.reqcnt++
	if err != nil {
		stat.failcnt++
	} else {
		stat.rtt = (stat.rtt + rtt) / 2
	}

	min_weight := 0
	if time.Now().Unix()-r.lastmodify.Unix() >= NS_UPDATE_CHOICES_INTERVAL {
		r.choices = make([]randutil.Choice, 0)
		for n, st := range r.nsstat {
			logger.Debug("%s weight: %d, reqcnt: %d, failcnt: %d, rtt: %d",
				n, st.weight, st.reqcnt, st.failcnt, st.rtt)

			st.weight = -(int(st.rtt) + st.failcnt*10)

			if min_weight > st.weight {
				min_weight = st.weight
			}

			st.failcnt = 0
			st.reqcnt = 0
		}

		for n, st := range r.nsstat {
			st.weight -= min_weight - 1
			r.choices = append(r.choices, randutil.Choice{st.weight, n})
		}

		r.lastmodify = time.Now()
	}

	r.mu.Unlock()
}
