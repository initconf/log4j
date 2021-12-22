module Log4j;

# although we've added embedded domains to Intel framework
# lets still watch here too

export {
		redef Notice::Type += {
			HostileDomainLookup,
		};
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=10
{
        if (query in malware_domains)
        {
                 NOTICE([$note=Log4j::HostileDomainLookup,
                                $conn=c,
                                $msg=fmt("Log4j Hostile domain seen %s=%s [%s]",c$id$orig_h, c$id$resp_h, query ),
                                $identifier=c$uid]);
        }
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
{
    if (ans$query in malware_domains)
    {
@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
        #event Log4j::log4j_new(log4j_domains[ans$query]);
        Broker::publish(Cluster::manager_topic, Log4j::log4j_new, log4j_domains[ans$query]);
@endif
    }

}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
{
    if (ans$query in log4j_domains)
    {
        add log4j_domains[ans$query]$mal_ips[a];

@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
    #event Log4j::log4j_new(log4j_domains[ans$query]);
    Broker::publish(Cluster::manager_topic, Log4j::log4j_new, log4j_domains[ans$query]);
@endif
    }

}

