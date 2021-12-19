module Log4j;

export {

        redef enum Notice::Type += {
            POST,
            UserAgent,
	        CallBackIP,
            CallBack,
            } ;

    global log4j_postBody = /jndi:ldap|\{\$.*\}/;

	  const ip_regex = /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)|(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)|(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)|([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}(:[0-9]+)?/;

    }

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

    if ( (name == "USER-AGENT" || name == "REFERRER" || name == "COOKIE") && log4j_postBody in value )
    {
        NOTICE([$note=UserAgent, $conn=c, $src=c$id$orig_h,
                $msg=fmt("Malicious user agent %s seen from host %s", value, c$id$orig_h)]);
                #$identifier=cat(c$id$orig_h), $suppress_for=1 day]);

        event Log4j::parse_payload(c$id, value);
    }
}

event Log4j::build_intel (cid: conn_id, payload: PayloadParts)
{
    if (payload?$host)
    {
    local a_item: Intel::Item = [$indicator=fmt("%s", payload$host),
                $indicator_type = Intel::ADDR,
                $meta = [$source = "log4jScript", $desc="Scanning IP Address"] ];

    Intel::insert(a_item);

    NOTICE([$note=CallBackIP, $id=cid, $src=payload$host,
                $msg=fmt("Callback IP [%s] seen from host %s with payload of [%s]", payload$host,  cid$orig_h, payload),
                $identifier=cat(payload$host), $suppress_for=1 day]);
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
        print fmt ("%s - %s", i, track_callback[i]);
}
