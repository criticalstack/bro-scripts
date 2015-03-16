# Liam Randall ( @Hectaman ).  Critical Stack, LLC.
# Script will log files to an inbound, outbound, or internal state.
#
# Logging files in this way is not necessarily as straighforward as one might wish
# a the files framework allows for 0 or more transmitters or recievers.
# This is reflected in the Files::Info record as tx_hosts and rx_hosts are both a 
# set of addresses.

event bro_init()
{

# Remove the default files.log
Log::remove_default_filter(Files::LOG);


Log::add_filter(Files::LOG, [
        $name = "files-directions",
        $path_func(id: Log::ID, path: string, rec: Files::Info) = 
	{
        # What if there are no parents; they are optional
        if (!rec?$tx_hosts || !rec?$rx_hosts)
            return "files_internal";
        # There are parents but one is missing.. *sniff*
        if (|rec$tx_hosts| == 0 || |rec$rx_hosts| == 0)
            return "files_internal";

        # ok, ignore the edge case, grab the first tx & rx and log it
        # NOTE: there could be more than one tx or rx here
        for (tx in rec$tx_hosts)
         for (rx in rec$rx_hosts)
         {
            local transmitter = Site::is_local_addr(tx);
            local reciever = Site::is_local_addr(rx);
            if(transmitter && reciever)
                return "files_internal";
            if (transmitter)
                return "files_outbound";
            else
                return "files_inbound";
         }
	}
    ]);
}
