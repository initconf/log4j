module Log4j;

export {


}

global already_seen_callbackip: set[addr] &create_expire=1 mins &backend=Broker::MEMORY;

event Log4j::build_intel (cid: conn_id, payload: PayloadParts)
{
    if (payload?$host)
    {
		local a_item: Intel::Item = [$indicator=fmt("%s", payload$host),
					$indicator_type = Intel::ADDR,
					$meta = [$source = "log4jScript", $desc="Scanning IP Address"] ];

		Intel::insert(a_item);

		if (cid$orig_h !in already_seen_callbackip)
		{
				NOTICE([$note=CallBackIP, $id=cid, $src=cid$orig_h,
					$msg=fmt("Callback IP [%s] seen from host %s with payload of [%s]", payload$host,  cid$orig_h, payload),
					$identifier=cat(cid), $suppress_for=1 day]);

			add already_seen_callbackip [cid$orig_h];
    	}
    }

    # 4. sensitive_URL
    a_item = [$indicator=fmt("%s", payload$uri), $indicator_type = Intel::URL,
                $meta = [$source = "log4jScript", $desc="URL of log4j callback"] ];

    Intel::insert(a_item);

    if (! is_valid_ip(payload$stem) )
    {
    a_item = [$indicator=fmt("%s", payload$stem), $indicator_type =
            Intel::DOMAIN, $meta = [$source = "log4jScript", $desc="DOMAIN of log4j callback"] ];

    Intel::insert(a_item);

    }

    # 2. Watch callback IP+port
    local a: ip_port = [$ip=payload$host, $p=payload$port_] ;

    if (a !in track_callback)
    {
        track_callback[a]=cid;
        @if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
            Broker::publish(Cluster::manager_topic, Log4j::log4j_new, payload$host, payload$port_, cid);
        @endif
    }

}
