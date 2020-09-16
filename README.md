## GoWC
A fast & accurate tool to clean *Wildcards* from *massdns output file*.
This is not a wrapper. A wrapper will have massdns's parameters fixed inside, what is not recommended. Massdns should be used in flexible way.
Generally, it is based on [puredns](https://github.com/d3mondev/puredns), but there are few changes to make the algorithm better and faster.

## Build

```
go get gitlab.com/prawps/gowc
go build main.go
```

Or use the [pre-built binary](https://gitlab.com/prawps/gowc/uploads/18ef15aff8bc3ac0b2bfed7c0f0539d5/goWC)

## Usage

For normal output:
```
gowc -d <target.com> -m <massdnsOutput> -t 20 -o <output>
```

For output with ips of domains:
```
gowc -d <target.com> -m <massdnsOutput> -t 20 -o <output> -i
```




