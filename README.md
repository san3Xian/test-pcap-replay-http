# pcap HTTP Analyzer

This project reads a pcap file and summarizes HTTP requests found inside. It decodes Snappy-compressed request bodies when applicable and reports basic statistics.

## Usage

```
go run ./cmd/pcapreplay -f packet1.pcap
```

The program prints the total number of HTTP requests and information about each request including source/destination, method, URL, timestamp, decoded length, and content-length.

---

# pcap HTTP 分析工具

该项目用于读取 pcap 文件，并从中提取所有 HTTP 请求。对于使用 Snappy 编码的请求体会自动解码，最后汇总输出请求数量及相关统计信息。

## 使用方法

```
go run ./cmd/pcapreplay -f packet1.pcap
```

程序会打印总共识别到的 HTTP 请求数，以及每个请求的源/目的地址、方法、URL、时间戳、解码后长度和 `Content-Length` 值。
