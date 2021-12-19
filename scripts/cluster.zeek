module Log4j;

export {
    global Log4j::log4j_new :event (ip: addr, p: port, cid: conn_id);
    global Log4j::log4j_add :event (ip: addr, p: port, cid: conn_id);
}

@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )

event Log4j::log4j_add (ip: addr, p: port, cid: conn_id)
{
        local a: ip_port =[$ip=ip,$p=p];
        if ( a !in Log4j::track_callback)
        {
                track_callback[a] = cid;
        }
}

@endif



### manager basically distributes the record to all workers.

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

event Log4j::log4j_new (ip: addr, p: port, cid: conn_id)
{
        Broker::publish(Cluster::worker_topic, Log4j::log4j_add, ip, p, cid);
}

@endif
