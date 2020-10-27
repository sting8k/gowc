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
./gowc -d vk.com -m vk.com_massdns.txt -t 20 -o output.txt -i

 ██████╗  ██████╗ ██╗    ██╗ ██████╗
██╔════╝ ██╔═══██╗██║    ██║██╔════╝
██║  ███╗██║   ██║██║ █╗ ██║██║     
██║   ██║██║   ██║██║███╗██║██║     
╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗
 ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝
                           GoWC v1.1
[+] Nameserver list: ["8.8.8.8:53" "8.8.4.4:53" "1.1.1.1:53" "1.0.0.1:53" "ns1.vkontakte.ru" "ns3.vkontakte.ru" "ns2.vkontakte.ru" "ns4.vkontakte.ru"]
[i] Processing MassDns cache file ...
[+] 190471 subdomains to be checked!
[i] Invoke threads to clean Wildcards ...
[i] Saving output to file: output.txt
[!] Found 1146 valid subdomains in 7.215540611s

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


