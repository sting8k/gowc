# GoWC
A fast & accurate tool to clean **wildcards** from **[Massdns](https://github.com/blechschmidt/massdns) output file**.  
This is **not** a wrapper. A wrapper will have massdns's parameters fixed inside, what is not my style. Massdns should be used in flexible way.  
Generally, algorithm is based on [puredns](https://github.com/d3mondev/puredns), but there are few changes to make the algorithm more accurate and faster. 

GoWC, first it will ask for NS of target domain (Ex. ns1.<target>.com, ns2.<target>.com). Then, belong with Google & CloudFlare DNS, these NS will be used to clean wildcards faster and more accurate. Why? Because sometimes, ns1 (of target) could accept wildcard subdomains, but ns2 doesn't that lead to **False Positive**. This tool will solve all these problems.

## Build

```
go get github.com/sting8k/gowc
go build
```

Or use the [pre-built binary](https://github.com/sting8k/gowc/releases/tag/1.0)

## Usage

```
./gowc -h

 ██████╗  ██████╗ ██╗    ██╗ ██████╗
██╔════╝ ██╔═══██╗██║    ██║██╔════╝
██║  ███╗██║   ██║██║ █╗ ██║██║     
██║   ██║██║   ██║██║███╗██║██║     
╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗
 ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝
                           GoWC v1.0
Usage of GoWC:
  -d string
        Domain of target
  -m string
        Massdns output file
  -o string
        Output file (default "output.txt")
  -t int
        Threads (default 10)
  -i    Output with ips from massdns
```


For normal output:
```
./gowc -d <target.com> -m <massdnsOutput> -t 10 -o <output>
```

For output with ips of domains:
```
./gowc -d <target.com> -m <massdnsOutput> -t 10 -o <output> -i
```

# Example
```
./gowc -d netflix.com -m massdns_tmp1.txt -t 20 -o /tmp/tested.txt -i

 ██████╗  ██████╗ ██╗    ██╗ ██████╗
██╔════╝ ██╔═══██╗██║    ██║██╔════╝
██║  ███╗██║   ██║██║ █╗ ██║██║     
██║   ██║██║   ██║██║███╗██║██║     
╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗
 ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝
                           GoWC v1.0
Nameserver list: ["8.8.8.8:53" "8.8.4.4:53" "1.1.1.1:53" "1.0.0.1:53" "ns1.netflix.com" "ns2.netflix.com" "ns-1372.awsdns-43.org" "ns-1984.awsdns-56.co.uk" "ns-659.awsdns-18.net" "ns-81.awsdns-10.com"]
Processing MassDns cache file ...
638 subdomains to be checked!
Invoke threads to clean Wildcards ...
All threads done!
Saving output to file: /tmp/tested.txt
Done!
```

Output:
```
...
dnm.prod.us-east-1.prodaa.netflix.com [54.84.140.216, 52.21.185.7, 54.164.77.130]
dubencovskaja.www.www.www.www.assets.obiwan.netflix.com [obiwan-wc.geo.netflix.com]
edgecenter.netflix.com [internal-primerui-prod-elb-444824057.us-east-1.elb.amazonaws.com]
edx.netflix.com [internal-etmarsapi-release-frontend-110816309.us-west-2.elb.amazonaws.com]
foodvaccine.www.www.www.cms.obiwan.netflix.com [obiwan-wc.geo.netflix.com]
ftl.netflix.com [45.57.40.1, 45.57.41.1]
help.netflix.com [help.geo.netflix.com]
...
```


