package autoipv6ptr

import (
	"context"
	"strings"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type AutoIPv6PTR struct {
	Next plugin.Handler

	// Presets are static entries which should not be generated
	Presets map[string]string
	TTL uint32

	Suffix string
}

// ServeDNS implements the plugin.Handler interface.
func (v6ptr AutoIPv6PTR) ServeDNS(ctx context.Context, writer dns.ResponseWriter, request *dns.Msg) (int, error) {
	if !(request.Question[0].Qtype == dns.TypePTR || request.Question[0].Qtype == dns.TypeAAAA) {
		return plugin.NextOrFailure(v6ptr.Name(), v6ptr.Next, ctx, writer, request)
	}

	if request.Question[0].Qtype == dns.TypePTR {
		var responsePtrValue string
	
		if ptrValue, found := v6ptr.Presets[request.Question[0].Name]; found {
			responsePtrValue = ptrValue
		} else {
			responsePtrValue = request.Question[0].Name
			responsePtrValue = RemoveIP6DotArpa(responsePtrValue)
			responsePtrValue = RemoveDots(responsePtrValue)
			responsePtrValue = ReverseString(responsePtrValue)
			responsePtrValue += "." + v6ptr.Suffix + "."
		}
	
		message := new(dns.Msg)
		message.SetReply(request)
		hdr := dns.RR_Header{Name: request.Question[0].Name, Ttl: v6ptr.TTL, Class: dns.ClassINET, Rrtype: dns.TypePTR}
		message.Answer = []dns.RR{&dns.PTR{Hdr: hdr, Ptr: responsePtrValue}}
	
		writer.WriteMsg(message)
		return 0, nil
	} else {
		var response string
		var responseIp net.IP
	
		response = request.Question[0].Name
		response = RemoveSuffix(response, v6ptr.Suffix)
		if len(response) != 32 {
			return plugin.NextOrFailure(v6ptr.Name(), v6ptr.Next, ctx, writer, request)
		}
		response = AddColons(response)
		responseIp = net.ParseIP(response);
	
		message := new(dns.Msg)
		message.SetReply(request)
		
		hdr := dns.RR_Header{Name: request.Question[0].Name, Ttl: v6ptr.TTL, Class: dns.ClassINET, Rrtype: dns.TypeAAAA}
		message.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: responseIp}}
	
		writer.WriteMsg(message)
		return 0, nil
	}

}

func AddColons(input string) string {
	return input[0:4] + ":" + input[4:8] + ":" + input[8:12] + ":" + input[12:16] + ":" + input[16:20] + ":" + input[20:24] + ":" + input[24:28] + ":" + input[28:]
}

func RemoveSuffix(input string, suffix string) string {
	return input[:len(input) - len(suffix) - 2]
}

func RemoveIP6DotArpa(input string) string {
    return strings.ReplaceAll(input, ".ip6.arpa.", "")
}

func RemoveDots(input string) string {
    return strings.ReplaceAll(input, ".", "")
}

func ReverseString(input string) string {
	// Copied from https://stackoverflow.com/questions/1752414/how-to-reverse-a-string-in-go
    runes := []rune(input)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

func (a AutoIPv6PTR) Name() string { return "autoipv6ptr" }
