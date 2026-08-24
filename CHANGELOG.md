v0.1.0:
- hostname resolution
- mac address resolution
- mac address lookup
- http/https open checks
- icmp ping check
- added version to window title

v0.2.0:
- consistent gui padding
- filter out empty IPs
- dont open terminal on windows
- shows current ip address
- when there's a scrollbar, it goes to the side, not overlaying the table
- on windows mac addresses are now manually requested via ARP
- show current subnet mask

TODO:

v0.3.0:

TODO:
- dynamically adjust to network mask
- markers for each device, gateway, current device, etc
- TTL checks too
- change between network interfaces
- start using os syscalls
- unify local ip and subnet mask to a single source of truth
- move some blocking calls into async .await/spawn blockinghow 