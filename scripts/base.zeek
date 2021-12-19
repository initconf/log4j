module Log4j;

#redef exit_only_after_terminate=T;

export {
    type ip_port: record {
        ip: addr;
        p:  port;
        };

    global track_callback: table[ip_port] of  conn_id  ; # &backend=Broker::MEMORY;

    }


# Borrowed shamelessly from corelight's heuristic

# If split doesn't return the expected number of indices, return the default "-"
function safe_split1_w_default(s: string, p: pattern, idx: count, missing: string &default="-"): string
    {
    local tmp = split_string1(s, p);
    if ( |tmp| > idx )
        return tmp[idx];
    else
        return missing;
    }

# I've modified this to use addr, port instead of strings

type PayloadParts: record {
    uri: string;
    uri_path: string ;
    stem: string;
    host: addr;
    port_: port;
    };

global Log4j::parse_payload: event (cid: conn_id, s: string);
global Log4j::build_intel:   event (cid: conn_id, p: PayloadParts);


# borrowed shamelessly from corelights package
# and modified significantly to handle implicit 80/tcp
# as well as domain names in callback URLs! 

event Log4j::parse_payload(cid: conn_id, s: string)
    {
    local tmp = split_string(s, /\/\//);
    local last: string = "-";
    if ( |tmp| > 0 )
        last = tmp[(|tmp| - 1)];
    local uri  = safe_split1_w_default(last, /\}/, 0);
    local stem = safe_split1_w_default(uri, /\//, 0);

    #local domain_regex = /\/\/[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}\/?/;
    local domain_regex = /[A-Za-z0-9]+([\-\.]{1}[A-Za-z0-9]+)*\.[a-zA-Z]{2,6}\/?[A-Za-z0-9]+/; 

    local path=safe_split1_w_default(uri,/\//,1);

    if (/:/ in stem)
        local port_ = to_port(fmt ("%s/tcp",safe_split1_w_default(stem, /\:/, 1)));
    else
            port_=80/tcp;

    local host : addr = 0.0.0.0 ;
    if ( domain_regex in stem)
    {
        # this is a dns situation
        local ph = split_string(stem,/:|\//)[0];
        when ( local h = lookup_hostname(ph) )
        {
            # issue if host is multi homed ie has both IPv4 and IPv6
            if (|h| > 0)
                for (i in h)
                {
                    local a = PayloadParts($uri=uri, $uri_path=path, $stem=stem, $host=i , $port_=port_);
                    event Log4j::build_intel( cid,a);
                }
        }
    }
    else
        host = to_addr(safe_split1_w_default(stem, /\:/, 0));

        if (host != 0.0.0.0)  
        { 
        local b = PayloadParts($uri=uri, $uri_path=path, $stem=stem, $host=host , $port_=port_);
        event Log4j::build_intel( cid,b);
        }
    }


### end borrowed shamelessly from corelight

function extract_host(url: string): string
{
        local host = "" ;
        local domain_regex: pattern = /\/\/[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}\/?/ ;
        local domain = find_all(url, domain_regex);

        for (d in domain)
        {
                host = gsub(d,/\/|\.$/,"");
                break ;
        }

        return host ;
}
