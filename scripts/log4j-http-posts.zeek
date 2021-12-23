module Log4j;

export {
		redef enum Notice::Type += {
				POST,
				Attempt,
		} ;
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

    #print fmt ("%s  %s",name, value);
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



event new_connection(c: connection)
    {
        local resp=c$id$resp_h;
        local dport = c$id$resp_p;

	if (resp in Site::local_nets)
		return; 

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
