## GoWC
A fast & accurate tool to clean *Wildcard from massdns output file.
This is not a wrapper. A wrapper will have massdns's parameters fixed inside, what is not recommended. Massdns should be used in flexible way.
Generally, it is based on [puredns](https://github.com/d3mondev/puredns), but there are few changes to make the algorithm better and faster.

## Build

```
go get gitlab.com/prawps/gowc
go build main.go
```

Or use the pre-built binary 

## Usage

For normal output:
```
gowc -d <target.com> -m <massdnsOutput> -t 20 -o <output>
```

For output with ips of domains:
```
gowc -d <target.com> -m <massdnsOutput> -t 20 -o <output> -i
```




