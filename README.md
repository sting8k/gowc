# GoWC
A fast & accurate tool to clean **wildcards** from **[Massdns](https://github.com/blechschmidt/massdns) output file**.  
This is **not** a wrapper. A wrapper will have massdns's parameters fixed inside, what is not my style. Massdns should be used in flexible way.  
Generally, algorithm is based on [puredns](https://github.com/d3mondev/puredns), but there are few changes to make the algorithm more accurate and faster. 

GoWC, first it will ask for NS of target domain (Ex. ns1.<target>.com, ns2.<target>.com). Then, belong with Google & CloudFlare DNS, these NS will be used to clean wildcards faster and more accurate. Why? Because sometimes, ns1 (of target) could accept wildcard subdomains, but ns2 doesn't that lead to **False Positive**. This tool will solve all these problems.

## Build

```
git clone https://github.com/sting8k/gowc
go build
```

Or use the [pre-built binary](https://github.com/sting8k/gowc/releases)

## Usage

```
./gowc -h

 ██████╗  ██████╗ ██╗    ██╗ ██████╗
██╔════╝ ██╔═══██╗██║    ██║██╔════╝
██║  ███╗██║   ██║██║ █╗ ██║██║     
██║   ██║██║   ██║██║███╗██║██║     
╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗
 ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝
                           GoWC v1.2
Usage:
  cmd [OPTIONS]

Application Options:
  -m=            Massdns output file
  -d=            Domain of target
  -s, --timeout= Timeout in seconds (default: 10)
  -q, --qps=     Queries per second (default: 10000)
  -r, --retries= Max retries each failed query (default: 1)
  -o=            Output file
  -i, --ip       Output with ips from massdns

Help Options:
  -h, --help     Show this help message

```


For normal output:
```
./gowc -d <target.com> -m <massdnsOutput> -o <output>
```

For output with ips of domains:
```
./gowc -d <target.com> -m <massdnsOutput> -o <output> -i
```

# Example

Cleaned `~190k` subdomains in just `~2.12s`

```
./gowc -d vk.com -m vk.com_massdns.txt -o output.txt -i

 ██████╗  ██████╗ ██╗    ██╗ ██████╗
██╔════╝ ██╔═══██╗██║    ██║██╔════╝
██║  ███╗██║   ██║██║ █╗ ██║██║     
██║   ██║██║   ██║██║███╗██║██║     
╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗
 ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝
                           GoWC v1.1
[+] Nameserver list: ["ns1.vkontakte.ru" "ns2.vkontakte.ru" "ns3.vkontakte.ru" "ns4.vkontakte.ru" "8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1"]
[+] Processing MassDns cache file ...
[+] 190468 subdomains to be checked
[+] Sending 2020 queries ...
[i] Cleaning wildcards ...
[i] Saving output to file: test/testvk31.txt
[!] Found 1052 valid subdomains in 2.125442671s

```

Output:
```
...
papi.vk.com [87.240.139.156]
post.vk.com [87.240.182.130]
ps.vk.com [pu.vk.com]
pu.vk.com [87.240.129.180, 87.240.137.139, 87.240.190.85, 87.240.190.74, 87.240.129.188]
queue.vk.com [87.240.129.131, 87.240.129.186, 93.186.225.201, 93.186.225.198, 87.240.129.129]
queuev4.vk.com [87.240.129.186, 93.186.225.201, 93.186.225.198, 87.240.129.129, 87.240.129.131]
reply.vk.com [95.142.194.149]
rim.vk.com [87.240.129.186]
security.vk.com [95.142.199.216]
smtp.vk.com [87.240.169.121]
storage2.vk.com [87.240.139.151]
streaming.vk.com [87.240.129.187, 87.240.190.64]
team.vk.com [185.29.130.131]
...
```


