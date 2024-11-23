# Advanced Multi-Protocol Proxy Scraper

A high-performance, asynchronous proxy scraper and checker tool that supports multiple protocols (HTTP, SOCKS4, SOCKS5) with advanced features for proxy validation and anonymity checking.

## Features

- **Multi-Protocol Support**: HTTP, SOCKS4, and SOCKS5 proxies
- **Asynchronous Processing**: High-performance proxy scraping and checking
- **Advanced Validation**:
  - Connection testing
  - Anonymity level detection
  - Response time measurement
  - SSL verification
- **Flexible Output**:
  - Multiple export formats (TXT, JSON, CSV)
  - Protocol-specific organization
  - Detailed statistics
- **Robust Error Handling**:
  - Retry mechanisms
  - Timeout management
  - Graceful shutdown
- **Progress Tracking**:
  - Real-time progress bars
  - Detailed logging
  - Performance statistics

## Installation

1. Clone the repository:
```bash
git clone https://github.com/taygun08/elite-proxy-checker.git
cd proxy_scraper
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python proxy_scraper.py
```

Advanced usage with options:
```bash
python proxy_scraper.py --threads 100 --timeout 10 --protocols http,socks4 --anonymity-level elite
```

### Command Line Options

```
Required Arguments:
  --threads INT           Number of concurrent connections (default: 50)
  --timeout FLOAT        Timeout in seconds for each request (default: 10)
  --protocols STR        Comma-separated list of protocols (default: http,socks4,socks5)

Optional Arguments:
  --output STR           Output directory for results (default: output/)
  --max-ms INT          Maximum response time in milliseconds (default: 10000)
  --delay FLOAT         Delay between proxy checks in seconds (default: 0)
  --anonymity-level STR  Required anonymity level (transparent, anonymous, elite)
  --verify-ssl          Verify SSL certificates (default: True)
  --export-format STR    Export format for results (txt, json, csv) (default: txt)

Output Control:
  --verbose             Show detailed output
  --quiet              Show minimal output
  --raw                Output only IP:PORT format
```

### Examples

1. Check HTTP proxies with SSL verification:
```bash
python proxy_scraper.py --verify-ssl --protocols http
```

2. Find elite proxies with fast response time:
```bash
python proxy_scraper.py --anonymity-level elite --max-ms 1000
```

3. Export results in JSON format:
```bash
python proxy_scraper.py --export-format json --protocols http,socks4
```

## Configuration


### User Agents
Customize user agents in `config/user_agents.txt`.
Customize proxy sources in `config/proxy_sources.txt`

## Output Structure

```
output/
├── http/
│   └── http_20231215_123456.txt
├── socks4/
│   └── socks4_20231215_123456.txt
├── socks5/
│   └── socks5_20231215_123456.txt
└── summary_20231215_123456.txt
```

## Dependencies

- Python 3.8+
- aiohttp
- aiohttp-socks
- rich
- geoip2
- And more in requirements.txt

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [ProxyScrape](https://proxyscrape.com/) for providing proxy APIs
- [aiohttp](https://docs.aiohttp.org/) for async HTTP client/server framework
- [rich](https://rich.readthedocs.io/) for beautiful terminal formatting
