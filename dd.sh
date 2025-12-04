enen#!/bin/bash


PORT="${1:-23100}"

DOH=()
DOH+=("https://185.222.222.222/dns-query")
DOH+=("https://94.140.14.15/dns-query")
DOH+=("https://doh.pub/dns-query")
DOH+=("https://freedns.controld.com/p3")
DOH+=("https://helios.plan9-dns.com/dns-query")
DOH+=("https://dns11.quad9.net:443/dns-query")
DOH+=("https://wikimedia-dns.org/dns-query")
DOH+=("https://adblock.dns.mullvad.net/dns-query")
DOH+=("https://dns.brahma.world/dns-query")
DOH+=("https://doh.tiarap.org/dns-query")
DOH+=("https://77.88.8.2/dns-query")
DOH+=("https://sky.rethinkdns.com/dns-query")
DOH+=("https://jp.tiar.app/dns-query")
DOH+=("https://dns.njal.la/dns-query")
DOH+=("https://public.dns.iij.jp/dns-query")
DOH+=("https://dns0.eu/dns-query")
DOH+=("https://130.59.31.248/dns-query")
DOH+=("https://per.adfilter.net/dns-query")
DOH+=("https://dns.bebasid.com/unfiltered")
DOH+=("https://family.dns.mullvad.net/dns-query")
DOH+=("https://dns1.dnscrypt.ca/dns-query")
DOH+=("https://doh.opendns.com/dns-query")
DOH+=("https://doh.libredns.gr/ads")
DOH+=("https://pluton.plan9-dns.com/dns-query")
DOH+=("https://anycast.dns.nextdns.io/dns-query")
DOH+=("https://dns.twnic.tw/dns-query")
DOH+=("https://doh.cleanbrowsing.org/doh/adult-filter/")


[ -f "/usr/bin/gost" ] || {
  which wget >/dev/null 2>&1
  [ "$?" -eq 0 ] || exit 1
  wget -qO- "https://github.com/ginuerzh/gost/releases/download/v2.12.0/gost_2.12.0_linux_amd64.tar.gz" |tar -C /usr/bin -zxv gost && chmod -R 777 /usr/bin/gost || exit 1
}

i=0;
for doh in "${DOH[@]}"; do
  port=$((PORT+i))
  echo "${port} --> ${doh}"
  /usr/bin/gost -L="socks5://:${port}?dns=${doh}" >/dev/null 2>&1 &
  i=$((i+1))
done

