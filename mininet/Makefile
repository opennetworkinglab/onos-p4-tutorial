topo:
	$(info ************ STARTING MININET TOPOLOGY ************)
	sudo -E ./topo.py --onos-ip ${OCI}

netcfg:
	$(info ************ PUSHING NETCFG TO ONOS ************)
	onos-netcfg ${OCI} netcfg.json

clean:
	sudo mn -c
