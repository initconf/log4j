module Log4j;

export {

        redef enum Notice::Type += {
            POST,
            Attempt,
	    CallBackIP,
            CallBack,
            } ;

    global log4j_postBody = /jndi:ldap|\{\$.*\}|jndi/;

	  const ip_regex = /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)|(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)|(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)|([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}(:[0-9]+)?/;
    }


global already_seen_callbackip: set[addr] &create_expire=1 mins &backend=Broker::MEMORY;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=3
    {
            if ( method == "POST"
                    &&  log4j_postBody in unescaped_URI)

            {
                NOTICE([$note=Log4j::POST, $conn=c, $src=c$id$orig_h,
                $msg=fmt("Malicious POST %s seen from host %s",
                unescaped_URI,c$id$orig_h), $identifier=cat(c$id$orig_h),
                $suppress_for=1 day]);
            }

    }

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
{

    if ( log4j_postBody !in value)
        return ;

    #if ( (name == "USER-AGENT" || name == "REFERRER" || name == "COOKIE") && log4j_postBody in value )
    #{
    #print fmt ("%s - %s", name, value);
        NOTICE([$note=Attempt, $conn=c, $src=c$id$orig_h,
                $msg=fmt("Malicious %s %s seen from host %s", name, value, c$id$orig_h)]);
                #$identifier=cat(c$id$orig_h), $suppress_for=1 day]);

        event Log4j::parse_payload(c$id, value);
    #}
}

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

event new_connection(c: connection)
    {
        local resp=c$id$resp_h;
        local dport = c$id$resp_p;

        local a:ip_port=[$ip=resp, $p=dport];

        if (a in track_callback)
        {
                NOTICE([$note=CallBack, $conn=c, $src=resp, $msg=fmt("Possible Successful Callback seen [%s:%s] : attack connection %s", resp,
                        dport, track_callback[a]),$identifier=cat(c$id$orig_h),
                        $suppress_for=30 mins]);
        }
    }

event zeek_done()
{
    for (i in track_callback) 
        print fmt ("track-callback: %s - %s", i, track_callback[i]);
}
