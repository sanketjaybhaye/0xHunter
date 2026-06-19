// ============================================================
// 0xHunter — GitHub Hacker Resources Library
// Curated repos for bug bounty, pentesting & CTF
// ============================================================

const ghResources = {
  recon: {
    label: '🔍 Reconnaissance & OSINT',
    color: '#58a6ff',
    items: [
      { name: 'subfinder', stars: '10.5k', desc: 'Fast passive subdomain enumeration tool using 40+ sources', url: 'https://github.com/projectdiscovery/subfinder', tags: ['subdomain', 'passive', 'go'], cmd: 'subfinder -d target.com -o subs.txt' },
      { name: 'amass', stars: '12.1k', desc: 'In-depth attack surface mapping and asset discovery by OWASP', url: 'https://github.com/owasp-amass/amass', tags: ['subdomain', 'active', 'osint'], cmd: 'amass enum -passive -d target.com -o amass_out.txt' },
      { name: 'theHarvester', stars: '11.4k', desc: 'OSINT tool for emails, names, subdomains, IPs from public sources', url: 'https://github.com/laramies/theHarvester', tags: ['osint', 'email', 'python'], cmd: 'theHarvester -d target.com -b all' },
      { name: 'Shodan CLI', stars: '2.1k', desc: 'CLI for Shodan — search exposed services, banners, CVEs', url: 'https://github.com/achillean/shodan-python', tags: ['shodan', 'iot', 'osint'], cmd: 'shodan search "org:target" --fields ip_str,port,transport' },
      { name: 'recon-ng', stars: '3.8k', desc: 'Full-featured reconnaissance framework with module system', url: 'https://github.com/lanmaster53/recon-ng', tags: ['framework', 'osint', 'modules'], cmd: 'recon-ng -w target_workspace' },
      { name: 'dnsx', stars: '2.1k', desc: 'Fast and multi-purpose DNS toolkit, bulk resolution, brute force', url: 'https://github.com/projectdiscovery/dnsx', tags: ['dns', 'brute', 'go'], cmd: 'dnsx -l subs.txt -a -resp -o dns_results.txt' },
      { name: 'puredns', stars: '1.8k', desc: 'Fast domain resolver and subdomain bruteforcing with wildcard detection', url: 'https://github.com/d3mondev/puredns', tags: ['dns', 'bruteforce', 'wildcard'], cmd: 'puredns bruteforce wordlist.txt target.com' },
      { name: 'massdns', stars: '4.1k', desc: 'High-performance DNS stub resolver for bulk lookups (millions/sec)', url: 'https://github.com/blechschmidt/massdns', tags: ['dns', 'fast', 'bulk'], cmd: 'massdns -r resolvers.txt -t A -o S -w results.txt subs.txt' },
      { name: 'chaos-client', stars: '630', desc: "Client for ProjectDiscovery's Chaos dataset — free subdomain datasets", url: 'https://github.com/projectdiscovery/chaos-client', tags: ['subdomain', 'dataset', 'passive'], cmd: 'chaos -d target.com -o chaos_subs.txt' },
      { name: 'github-search', stars: '1.1k', desc: 'Python tool for GitHub dorking — find exposed secrets and code', url: 'https://github.com/gwen001/github-search', tags: ['github', 'dork', 'secrets'], cmd: 'python github_search.py -q "target.com password" -t code' },
      { name: 'GitDorker', stars: '1.9k', desc: 'Uses GitHub Search API to find exposed secrets & sensitive files', url: 'https://github.com/obheda12/GitDorker', tags: ['github', 'secrets', 'dork'], cmd: 'python3 GitDorker.py -tf tokens.txt -q target.com' },
      { name: 'trufflehog', stars: '17.2k', desc: 'Find credentials in git history, S3, GitHub, Slack and 800+ sources', url: 'https://github.com/trufflesecurity/trufflehog', tags: ['secrets', 'git', 'scanning'], cmd: 'trufflehog github --org=targetorg' },
      { name: 'urlhunter', stars: '430', desc: 'Recon tool for archived URLs from shortener services', url: 'https://github.com/utkusen/urlhunter', tags: ['urls', 'archive', 'osint'], cmd: 'urlhunter -keywords keywords.txt -date 2023-01-01' },
      { name: 'uncover', stars: '2.3k', desc: 'Quickly discover exposed hosts using Shodan, Fofa, Censys, Quake APIs', url: 'https://github.com/projectdiscovery/uncover', tags: ['shodan', 'censys', 'fofa'], cmd: 'uncover -q "org:target" -e shodan,censys,fofa' },
      { name: 'reconftw', stars: '5.9k', desc: 'Automated recon framework combining 50+ tools in one pipeline', url: 'https://github.com/six2dez/reconftw', tags: ['automation', 'framework', 'all-in-one'], cmd: 'reconftw.sh -d target.com -a' },
      { name: 'Arjun', stars: '3.7k', desc: 'HTTP parameter discovery suite — find hidden API params', url: 'https://github.com/s0md3v/Arjun', tags: ['parameters', 'api', 'fuzzing'], cmd: 'arjun -u https://api.target.com/endpoint' },
      { name: 'paramspider', stars: '3.2k', desc: 'Mining URLs from dark corners of web archives for fuzzing', url: 'https://github.com/devanshbatham/ParamSpider', tags: ['params', 'wayback', 'urls'], cmd: 'python3 paramspider.py -d target.com' },
      { name: 'waymore', stars: '1.5k', desc: 'Find much more from the Wayback Machine (archived JS, endpoints)', url: 'https://github.com/xnl-h4ck3r/waymore', tags: ['wayback', 'archive', 'urls'], cmd: 'waymore -i target.com -mode U' },
      { name: 'findomain', stars: '3.6k', desc: 'Blazing fast subdomain monitoring and extraction tool written in Rust', url: 'https://github.com/Findomain/Findomain', tags: ['subdomain', 'rust', 'recon'], cmd: 'findomain -t target.com -u resolved_subs.txt' },
      { name: 'subjs', stars: '1.1k', desc: 'Fetch all JavaScript files from a list of URLs or domains', url: 'https://github.com/lc/subjs', tags: ['js', 'recon', 'go'], cmd: 'cat domains.txt | subjs -c 10' },
      { name: 'gowitness', stars: '2.8k', desc: 'Web screenshot utility using Chrome Headless', url: 'https://github.com/sensepost/gowitness', tags: ['screenshot', 'recon', 'go'], cmd: 'gowitness single https://target.com' },
      { name: 'httprobe', stars: '2.5k', desc: 'Take a list of domains and probe for working HTTP and HTTPS servers', url: 'https://github.com/tomnomnom/httprobe', tags: ['probe', 'http', 'go'], cmd: 'cat domains.txt | httprobe' },
      { name: 'anew', stars: '2.9k', desc: 'A tool for easily adding unique lines to a file', url: 'https://github.com/tomnomnom/anew', tags: ['utility', 'text', 'go'], cmd: 'cat new_subs.txt | anew old_subs.txt' }
    ]
  },
  scanning: {
    label: '🌐 Web Scanning & Fuzzing',
    color: '#f59e0b',
    items: [
      { name: 'nuclei', stars: '22.3k', desc: 'Fast, customizable vulnerability scanner based on YAML templates', url: 'https://github.com/projectdiscovery/nuclei', tags: ['scanner', 'templates', 'go'], cmd: 'nuclei -u https://target.com -t . -severity critical,high' },
      { name: 'httpx', stars: '8.1k', desc: 'Fast multi-purpose HTTP probe — status codes, tech, headers, CDN', url: 'https://github.com/projectdiscovery/httpx', tags: ['http', 'probe', 'go'], cmd: 'httpx -l subs.txt -status-code -tech-detect -o alive.txt' },
      { name: 'ffuf', stars: '13.1k', desc: 'Wicked fast web fuzzer written in Go (directory, param, vhost)', url: 'https://github.com/ffuf/ffuf', tags: ['fuzzing', 'directory', 'go'], cmd: 'ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302' },
      { name: 'feroxbuster', stars: '6.0k', desc: 'Fast, simple, recursive content discovery tool (Rust)', url: 'https://github.com/epi052/feroxbuster', tags: ['fuzzing', 'directory', 'rust'], cmd: 'feroxbuster -u https://target.com -w wordlist.txt --depth 3' },
      { name: 'gobuster', stars: '9.7k', desc: 'Directory/file & DNS/vhost brute forcing tool', url: 'https://github.com/OJ/gobuster', tags: ['directory', 'dns', 'brute'], cmd: 'gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt' },
      { name: 'dirsearch', stars: '12.3k', desc: 'Web path scanner with multi-thread support and smart wordlists', url: 'https://github.com/maurosoria/dirsearch', tags: ['directory', 'python', 'scanner'], cmd: 'dirsearch -u https://target.com -e php,html,js,txt' },
      { name: 'wfuzz', stars: '5.7k', desc: 'Web fuzzer to find resources, hidden content and vulnerabilities', url: 'https://github.com/xmendez/wfuzz', tags: ['fuzzing', 'python', 'web'], cmd: 'wfuzz -c -z file,wordlist.txt --hc 404 https://target.com/FUZZ' },
      { name: 'naabu', stars: '4.6k', desc: 'Fast port scanner from ProjectDiscovery with host discovery', url: 'https://github.com/projectdiscovery/naabu', tags: ['portscan', 'go', 'fast'], cmd: 'naabu -host target.com -top-ports 1000 -o ports.txt' },
      { name: 'masscan', stars: '23.5k', desc: 'Mass IP port scanner — scan the entire internet in 5 minutes', url: 'https://github.com/robertdavidgraham/masscan', tags: ['portscan', 'fast', 'c'], cmd: 'masscan -p 80,443,8080,8443 10.0.0.0/8 --rate=10000' },
      { name: 'katana', stars: '11.5k', desc: 'Next-generation crawling and spidering framework (JS-aware)', url: 'https://github.com/projectdiscovery/katana', tags: ['crawler', 'spider', 'js'], cmd: 'katana -u https://target.com -js-crawl -d 3 -o crawl.txt' },
      { name: 'gospider', stars: '2.6k', desc: 'Fast web spider — sitemap, robots, wayback, linkfinder', url: 'https://github.com/jaeles-project/gospider', tags: ['spider', 'go', 'crawler'], cmd: 'gospider -s https://target.com -c 10 -d 2 -o output/' },
      { name: 'hakrawler', stars: '4.0k', desc: 'Fast web crawler for gathering URLs and JS file locations', url: 'https://github.com/hakluke/hakrawler', tags: ['crawler', 'urls', 'go'], cmd: 'cat subs.txt | hakrawler -subs -u' },
      { name: 'dalfox', stars: '3.9k', desc: 'Fast XSS scanning and parameter analysis tool (Go)', url: 'https://github.com/hahwul/dalfox', tags: ['xss', 'scanner', 'go'], cmd: 'dalfox url https://target.com/search?q=FUZZ' },
      { name: 'XSStrike', stars: '13.9k', desc: 'Advanced XSS detection suite with DOM analysis and fuzzer', url: 'https://github.com/s0md3v/XSStrike', tags: ['xss', 'python', 'dom'], cmd: 'python3 xsstrike.py -u "https://target.com/page?id=1"' },
      { name: 'wpscan', stars: '8.4k', desc: 'WordPress security scanner — find vulnerabilities, active plugins, themes', url: 'https://github.com/wpscan/wpscan', tags: ['wordpress', 'scanner', 'exploit'], cmd: 'wpscan --url https://target.com --enumerate vp,vt' },
      { name: 'aquatone', stars: '3.6k', desc: 'Tool for visual inspection of websites across a large number of hosts', url: 'https://github.com/michenriksen/aquatone', tags: ['screenshot', 'visual', 'recon'], cmd: 'cat subs.txt | aquatone' },
      { name: 'wapiti', stars: '1.2k', desc: 'Web application vulnerability scanner (LFI, SQLi, XSS, etc.)', url: 'https://github.com/wapiti-scanner/wapiti', tags: ['scanner', 'vulnerability', 'python'], cmd: 'wapiti -u https://target.com' }
    ]
  },
  exploitation: {
    label: '💀 Exploitation & Injection',
    color: '#f85149',
    items: [
      { name: 'sqlmap', stars: '32.5k', desc: 'Automatic SQL injection and database takeover tool', url: 'https://github.com/sqlmapproject/sqlmap', tags: ['sqli', 'python', 'auto'], cmd: 'sqlmap -u "https://target.com/page?id=1" --dbs --batch' },
      { name: 'commix', stars: '4.6k', desc: 'Automated OS command injection exploitation tool', url: 'https://github.com/commixproject/commix', tags: ['cmdi', 'python', 'rce'], cmd: 'commix --url="https://target.com/ping.php?ip=INJECT_HERE"' },
      { name: 'tplmap', stars: '3.4k', desc: 'Server-Side Template Injection (SSTI) detection and exploitation', url: 'https://github.com/epinna/tplmap', tags: ['ssti', 'python', 'template'], cmd: 'python tplmap.py -u "https://target.com/page?name=*"' },
      { name: 'SSRFmap', stars: '2.5k', desc: 'Automatic SSRF fuzzer and exploitation tool', url: 'https://github.com/swisskyrepo/SSRFmap', tags: ['ssrf', 'python', 'auto'], cmd: 'python3 ssrfmap.py -r req.txt -p url' },
      { name: 'Ghauri', stars: '1.7k', desc: 'Advanced SQL injection detection and exploitation tool (sqlmap alternative)', url: 'https://github.com/r0oth3x49/ghauri', tags: ['sqli', 'python', 'advanced'], cmd: 'ghauri -u "https://target.com/page?id=1" --dbs' },
      { name: 'NoSQLMap', stars: '2.7k', desc: 'Automated MongoDB/NoSQL exploitation and injection tool', url: 'https://github.com/codingo/NoSQLMap', tags: ['nosql', 'mongodb', 'injection'], cmd: 'python nosqlmap.py' },
      { name: 'ysoserial', stars: '7.7k', desc: 'Generate payloads for Java deserialization vulnerabilities', url: 'https://github.com/frohoff/ysoserial', tags: ['java', 'deserialization', 'rce'], cmd: 'java -jar ysoserial.jar CommonsCollections6 "id" | base64' },
      { name: 'interactsh', stars: '3.7k', desc: 'Open-source OOB interaction server (like Burp Collaborator)', url: 'https://github.com/projectdiscovery/interactsh', tags: ['oob', 'dns', 'http'], cmd: 'interactsh-client -v' },
      { name: 'cariddi', stars: '1.1k', desc: 'Crawls and checks endpoints for secrets, errors, and injection points', url: 'https://github.com/edoardottt/cariddi', tags: ['crawler', 'secrets', 'injection'], cmd: 'echo target.com | cariddi -s -e -rua' },
      { name: 'CORScanner', stars: '2.0k', desc: 'CORS misconfiguration scanner — detects dangerous patterns', url: 'https://github.com/chenjj/CORScanner', tags: ['cors', 'python', 'scanner'], cmd: 'python cors_scan.py -u https://target.com' },
      { name: 'AutoSSRF', stars: '380', desc: 'Smart context-aware SSRF detection in multiple protocols', url: 'https://github.com/Th0h0/autossrf', tags: ['ssrf', 'auto', 'scanner'], cmd: 'python3 autossrf.py -u target.com' },
      { name: 'metasploit-framework', stars: '34.0k', desc: 'Exploitation framework for modular execution of public exploits and payloads', url: 'https://github.com/rapid7/metasploit-framework', tags: ['exploitation', 'framework', 'red-team'], cmd: 'msfconsole' },
      { name: 'beef', stars: '9.0k', desc: 'Web browser penetration testing platform focusing on clients', url: 'https://github.com/beefproject/beef', tags: ['beef', 'browser', 'framework'], cmd: './beef' },
      { name: 'exploitdb', stars: '4.9k', desc: 'Offline exploit database command line search utility', url: 'https://github.com/offensive-security/exploitdb', tags: ['exploit', 'cli', 'search'], cmd: 'searchsploit "Apache 2.4.41"' }
    ]
  },
  burp: {
    label: '🔧 Burp Suite Extensions',
    color: '#bc8cff',
    items: [
      { name: 'Autorize', stars: '3.7k', desc: 'Automatic authorization enforcement testing Burp extension', url: 'https://github.com/PortSwigger/autorize', tags: ['burp', 'authz', 'idor'], cmd: '# Install from BApp Store: Autorize' },
      { name: 'BurpSuite-Asset-Discovery', stars: '430', desc: 'Passive asset discovery during browsing from Burp', url: 'https://github.com/redhuntlabs/BurpSuite-Asset-Discovery', tags: ['burp', 'recon', 'passive'], cmd: '# BApp Store: Asset Discovery' },
      { name: 'param-miner', stars: '4.0k', desc: 'Find hidden web cache poisoning & parameter pollution issues', url: 'https://github.com/PortSwigger/param-miner', tags: ['burp', 'cache', 'params'], cmd: '# BApp Store: Param Miner → Right-click → Guess headers' },
      { name: 'turbo-intruder', stars: '3.2k', desc: 'Burp extension for complex, extremely fast HTTP requests (race conditions)', url: 'https://github.com/PortSwigger/turbo-intruder', tags: ['burp', 'race', 'fast'], cmd: '# BApp Store: Turbo Intruder' },
      { name: 'active-scan-plus-plus', stars: '1.5k', desc: 'Extends Burp active scanner with SSTI, blind code injection checks', url: 'https://github.com/PortSwigger/active-scan-plus-plus', tags: ['burp', 'scanner', 'ssti'], cmd: '# BApp Store: Active Scan++' },
      { name: 'JWT Editor', stars: '1.2k', desc: 'Burp extension for JWT editing, signing, and CVE attacks', url: 'https://github.com/PortSwigger/jwt-editor', tags: ['burp', 'jwt', 'auth'], cmd: '# BApp Store: JWT Editor' },
      { name: 'Hackvertor', stars: '1.5k', desc: 'Burp tag-based encoding/decoding of HTTP messages on the fly', url: 'https://github.com/PortSwigger/hackvertor', tags: ['burp', 'encode', 'decode'], cmd: '# BApp Store: Hackvertor' },
      { name: 'GadgetProbe', stars: '680', desc: 'Probe Java serialization libs over Burp Collaborator', url: 'https://github.com/BishopFox/GadgetProbe', tags: ['burp', 'java', 'deserialization'], cmd: '# BApp Store: GadgetProbe' },
      { name: 'InQL', stars: '1.7k', desc: 'GraphQL security testing scanner and Burp integration', url: 'https://github.com/doyensec/inql', tags: ['burp', 'graphql', 'api'], cmd: '# BApp Store: InQL Scanner' },
      { name: 'Backslash-Powered-Scanner', stars: '1.1k', desc: 'Detects server-side injection via novel backslash-powered fuzzing', url: 'https://github.com/PortSwigger/backslash-powered-scanner', tags: ['burp', 'scanner', 'injection'], cmd: '# BApp Store: Backslash Powered Scanner' },
      { name: 'Bypass WAF', stars: '620', desc: 'Burp extension to add custom headers to bypass WAF configurations', url: 'https://github.com/codewatchorg/BypassWAF', tags: ['burp', 'waf', 'bypass'], cmd: '# Install from BApp Store: Bypass WAF' },
      { name: 'Copy as Python-Requests', stars: '920', desc: 'Copy selected request(s) to clipboard as Python code using requests library', url: 'https://github.com/Nick-Vines/BRP-Copy-as-Python-Requests', tags: ['burp', 'python', 'utility'], cmd: '# Install from BApp Store: Copy as Python-Requests' }
    ]
  },
  wordlists: {
    label: '📚 Wordlists & Payloads',
    color: '#3fb950',
    items: [
      { name: 'SecLists', stars: '61.2k', desc: "The #1 collection of multiple types of lists for security assessments", url: 'https://github.com/danielmiessler/SecLists', tags: ['wordlists', 'payloads', 'all-in-one'], cmd: 'git clone --depth 1 https://github.com/danielmiessler/SecLists' },
      { name: 'PayloadsAllTheThings', stars: '63.2k', desc: 'Useful payloads and bypasses for every web vulnerability type', url: 'https://github.com/swisskyrepo/PayloadsAllTheThings', tags: ['payloads', 'bypass', 'cheatsheet'], cmd: '# Browse at https://swisskyrepo.github.io/PayloadsAllTheThings/' },
      { name: 'BBScan', stars: '3.9k', desc: 'Rapid batch web info leakage scanner with huge built-in wordlist', url: 'https://github.com/lijiejie/BBScan', tags: ['scanner', 'wordlist', 'info'], cmd: 'python BBScan.py --host target.com' },
      { name: 'fuzz.txt', stars: '3.2k', desc: 'Wordlist specifically designed for web application fuzzing & bug bounty', url: 'https://github.com/Bo0oM/fuzz.txt', tags: ['wordlist', 'fuzzing', 'paths'], cmd: 'ffuf -u https://target.com/FUZZ -w fuzz.txt -mc 200' },
      { name: 'assetnote-wordlists', stars: '5.6k', desc: 'Automated wordlists for fuzzing — updated API paths, JS keywords', url: 'https://github.com/assetnote/wordlists', tags: ['wordlist', 'api', 'js'], cmd: 'curl -s https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024.txt | ffuf ...' },
      { name: 'IntruderPayloads', stars: '3.5k', desc: 'Collection of Burp Intruder payloads organized by category', url: 'https://github.com/1N3/IntruderPayloads', tags: ['burp', 'intruder', 'payloads'], cmd: '# Load in Burp Intruder from payloads/ directory' },
      { name: 'XSS-Payload-List', stars: '3.8k', desc: 'Cross-Site Scripting payload list (every bypass and encoding)', url: 'https://github.com/payloadbox/xss-payload-list', tags: ['xss', 'payloads', 'bypass'], cmd: 'cat xss-payload-list.txt | dalfox pipe -o results.txt' },
      { name: 'sql-injection-payload-list', stars: '4.0k', desc: 'SQL injection payload list for every DB and bypass method', url: 'https://github.com/payloadbox/sql-injection-payload-list', tags: ['sqli', 'payloads', 'bypass'], cmd: '# Use with ffuf, sqlmap, or Burp Intruder' },
      { name: 'leaky-paths', stars: '2.0k', desc: 'Collection of paths that may leak sensitive information when accessible', url: 'https://github.com/ayoubfathi/leaky-paths', tags: ['wordlist', 'paths', 'leaks'], cmd: 'ffuf -u https://target.com/FUZZ -w leaky-paths.txt -mc 200' },
      { name: 'trickest-wordlists', stars: '3.5k', desc: 'Real-world search queries, usernames, passwords, subdomains, and cloud bucket names', url: 'https://github.com/trickest/wordlists', tags: ['wordlists', 'inventory', 'automated'], cmd: 'git clone https://github.com/trickest/wordlists' }
    ]
  },
  jwt_oauth: {
    label: '🔑 Auth, JWT & OAuth Testing',
    color: '#f59e0b',
    items: [
      { name: 'jwt_tool', stars: '5.4k', desc: 'Toolkit for testing, tweaking, and cracking JWTs. Supports all alg attacks', url: 'https://github.com/ticarpi/jwt_tool', tags: ['jwt', 'python', 'auth'], cmd: 'python3 jwt_tool.py <token> -T' },
      { name: 'jwtear', stars: '320', desc: 'JWT manipulation and forging tool — none alg, HS256 crack, kid injection', url: 'https://github.com/KINGSABRI/jwtear', tags: ['jwt', 'ruby', 'exploit'], cmd: 'jwtear manipulate --token <token> --alg none' },
      { name: 'oauthscan', stars: '1.0k', desc: 'Tool for scanning and testing OAuth 2.0 implementations', url: 'https://github.com/AvalZ/oauthscan', tags: ['oauth', 'python', 'scanner'], cmd: 'python3 oauthscan.py --target https://target.com' },
      { name: 'OAuth-2.0-attacks', stars: '2.3k', desc: 'Complete guide and test cases for OAuth 2.0 vulnerability research', url: 'https://github.com/Puskar-Roy/OAuth-2.0-Security-Checklist', tags: ['oauth', 'checklist', 'guide'], cmd: '# Reference guide — see wiki for test cases' },
      { name: 'Caido', stars: '2.6k', desc: 'Modern web security auditing tool — Burp alternative with replay, match/replace', url: 'https://github.com/caido/caido', tags: ['proxy', 'burp-alt', 'modern'], cmd: 'caido' },
      { name: 'keyhacks', stars: '5.0k', desc: 'Shows quick ways to check if API keys are valid & exploit them', url: 'https://github.com/streaak/keyhacks', tags: ['api-keys', 'secrets', 'validation'], cmd: '# Reference: find API key type → run corresponding curl command' },
      { name: 'authanalyzer', stars: '1.2k', desc: 'Burp extension to analyze authorization issues across different users', url: 'https://github.com/simioni87/authanalyzer', tags: ['burp', 'authz', 'idor'], cmd: '# Install from BApp Store: Auth Analyzer' }
    ]
  },
  cloud: {
    label: '☁️ Cloud & AWS Security',
    color: '#60a5fa',
    items: [
      { name: 'ScoutSuite', stars: '6.6k', desc: 'Multi-cloud security auditing tool — AWS, Azure, GCP', url: 'https://github.com/nccgroup/ScoutSuite', tags: ['cloud', 'aws', 'audit'], cmd: 'scout aws --profile default' },
      { name: 'cloudsplaining', stars: '2.0k', desc: 'AWS IAM security assessment that identifies policy violations', url: 'https://github.com/salesforce/cloudsplaining', tags: ['aws', 'iam', 'audit'], cmd: 'cloudsplaining scan --input-file iam.json' },
      { name: 'Pacu', stars: '4.6k', desc: 'AWS exploitation framework — 45+ modules for attacking AWS environments', url: 'https://github.com/RhinoSecurityLabs/pacu', tags: ['aws', 'exploit', 'framework'], cmd: 'python3 pacu.py' },
      { name: 'S3Scanner', stars: '2.7k', desc: 'Scan for open S3 buckets and dump contents', url: 'https://github.com/sa7mon/S3Scanner', tags: ['s3', 'aws', 'buckets'], cmd: 'python3 s3scanner.py --bucket target-bucket' },
      { name: 'cloud_enum', stars: '2.8k', desc: 'Multi-cloud OSINT — enumerate public S3, Azure Blobs, GCS Buckets', url: 'https://github.com/initstring/cloud_enum', tags: ['cloud', 'enum', 'osint'], cmd: 'python3 cloud_enum.py -k target -m s3,azure,gcp' },
      { name: 'GrayhatWarfare', stars: '780', desc: 'Public buckets and Azure blobs search using grayhatwarfare.com CLI', url: 'https://github.com/nightswatch-al/ghw-cli', tags: ['s3', 'azure', 'buckets'], cmd: 'ghw search target' },
      { name: 'gcpwn', stars: '900', desc: 'GCP privilege escalation and lateral movement toolkit', url: 'https://github.com/NetSPI/gcpwn', tags: ['gcp', 'privesc', 'cloud'], cmd: 'python3 gcpwn.py --profile default' },
      { name: 'azurehound', stars: '1.8k', desc: 'BloodHound data collector for Microsoft Azure environments', url: 'https://github.com/BloodHoundAD/AzureHound', tags: ['azure', 'graph', 'enum'], cmd: 'azurehound -u user@domain.com list all' },
      { name: 'aws-nuke', stars: '6.0k', desc: 'Remove all resources from an AWS account (red team cleanup)', url: 'https://github.com/rebuy-de/aws-nuke', tags: ['aws', 'cleanup', 'red-team'], cmd: 'aws-nuke -c config.yml --no-dry-run' },
      { name: 'prowler', stars: '10.5k', desc: 'AWS, Azure, GCP security assessment, auditing, hardening and compliance', url: 'https://github.com/prowler-cloud/prowler', tags: ['aws', 'cloud', 'audit'], cmd: 'prowler aws' }
    ]
  },
  mobile: {
    label: '📱 Mobile Security',
    color: '#34d399',
    items: [
      { name: 'MobSF', stars: '18.4k', desc: 'All-in-one mobile security testing framework (Android + iOS)', url: 'https://github.com/MobSF/Mobile-Security-Framework-MobSF', tags: ['android', 'ios', 'sast'], cmd: 'docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest' },
      { name: 'frida', stars: '17.2k', desc: 'Dynamic instrumentation toolkit for Android/iOS (hook functions, bypass SSL)', url: 'https://github.com/frida/frida', tags: ['android', 'ios', 'dynamic'], cmd: 'frida -U -f com.target.app -l script.js --no-pause' },
      { name: 'objection', stars: '7.0k', desc: 'Frida-based runtime mobile exploration toolkit (SSL pinning bypass)', url: 'https://github.com/sensepost/objection', tags: ['android', 'ios', 'frida'], cmd: 'objection -g com.target.app explore' },
      { name: 'apktool', stars: '21.5k', desc: 'Reverse engineering Android APK files — decompile, modify, recompile', url: 'https://github.com/iBotPeaches/Apktool', tags: ['android', 'apk', 'reverse'], cmd: 'apktool d app.apk -o output/' },
      { name: 'jadx', stars: '41.0k', desc: 'Dex to Java decompiler — reverse Android APKs to readable Java', url: 'https://github.com/skylot/jadx', tags: ['android', 'java', 'decompile'], cmd: 'jadx -d output/ app.apk' },
      { name: 'drozer', stars: '3.6k', desc: 'Android security assessment framework — test attack surface on device', url: 'https://github.com/WithSecureLabs/drozer', tags: ['android', 'ipa', 'security'], cmd: 'dz> run app.package.list -f target' },
      { name: 'apkleaks', stars: '3.5k', desc: 'Scan APK files for URLs, endpoints, and secrets in DEX code', url: 'https://github.com/dwisiswant0/apkleaks', tags: ['android', 'secrets', 'urls'], cmd: 'apkleaks -f app.apk' },
      { name: 'house', stars: '1.4k', desc: 'Runtime mobile application analysis toolkit using Frida', url: 'https://github.com/nccgroup/house', tags: ['ios', 'android', 'frida'], cmd: 'python3 app.py' },
      { name: 'Grapefruit', stars: '1.9k', desc: 'Runtime iOS app analysis tool using Frida and a local web interface', url: 'https://github.com/ChiChou/Grapefruit', tags: ['ios', 'frida', 'runtime'], cmd: 'npm install -g grapefruit && grapefruit' }
    ]
  },
  api: {
    label: '🔌 API Security Testing',
    color: '#a78bfa',
    items: [
      { name: 'kiterunner', stars: '1.9k', desc: 'Blazing fast API endpoint discovery using request routing patterns', url: 'https://github.com/assetnote/kiterunner', tags: ['api', 'discovery', 'fast'], cmd: 'kr scan https://target.com/api -w routes-small.kite' },
      { name: 'Astra', stars: '2.5k', desc: 'Automated REST API security testing — OWASP API Top 10', url: 'https://github.com/flipkart-incubator/Astra', tags: ['api', 'rest', 'owasp'], cmd: 'python3 run.py' },
      { name: 'graphql-cop', stars: '870', desc: 'Security audit tool for GraphQL APIs — 10 common vulnerabilities', url: 'https://github.com/dolevf/graphql-cop', tags: ['graphql', 'scanner', 'audit'], cmd: 'python3 graphql-cop.py -t https://target.com/graphql' },
      { name: 'clairvoyance', stars: '1.2k', desc: 'Recover GraphQL schema even when introspection is disabled', url: 'https://github.com/nikitastupin/clairvoyance', tags: ['graphql', 'enum', 'schema'], cmd: 'python3 -m clairvoyance -o schema.json https://target.com/api/graphql' },
      { name: 'postman-to-openapi', stars: '660', desc: 'Convert Postman collections to OpenAPI spec for security analysis', url: 'https://github.com/joolfe/postman-to-openapi', tags: ['api', 'postman', 'openapi'], cmd: 'p2o ./postman_collection.json -f ./api_spec.yml' },
      { name: 'APIFuzzer', stars: '1.3k', desc: 'HTTP API fuzzer reads OpenAPI spec and fuzzes all endpoints', url: 'https://github.com/KissPeter/APIFuzzer', tags: ['api', 'fuzzer', 'openapi'], cmd: 'APIFuzzer -s openapi.json -u https://target.com' },
      { name: 'mitmproxy2swagger', stars: '3.7k', desc: 'Autoconvert mitmproxy traffic captures into OpenAPI 3.0 specs', url: 'https://github.com/alufers/mitmproxy2swagger', tags: ['api', 'spec', 'mitmproxy'], cmd: 'mitmproxy2swagger -i flow.yml -o spec.yml -p https://target.com' },
      { name: 'GraphQLmap', stars: '820', desc: 'Scripting engine to interact with a GraphQL endpoint for exploitation', url: 'https://github.com/swisskyrepo/GraphQLmap', tags: ['graphql', 'exploitation', 'injection'], cmd: 'graphqlmap -u https://target.com/graphql' }
    ]
  },
  privilege: {
    label: '⬆️ Privilege Escalation & Post-Exploitation',
    color: '#f85149',
    items: [
      { name: 'linPEAS', stars: '16.2k', desc: 'Linux Privilege Escalation Awesome Script — auto enum for local privesc', url: 'https://github.com/peass-ng/PEASS-ng', tags: ['linux', 'privesc', 'enum'], cmd: 'curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh' },
      { name: 'winPEAS', stars: '16.2k', desc: 'Windows Privilege Escalation Awesome Script', url: 'https://github.com/peass-ng/PEASS-ng', tags: ['windows', 'privesc', 'enum'], cmd: 'winpeas.exe quiet' },
      { name: 'GTFOBins', stars: '11.0k', desc: 'Curated list of Unix binaries to bypass security restrictions and privesc', url: 'https://github.com/GTFOBins/GTFOBins.github.io', tags: ['gtfobins', 'bypass', 'privesc'], cmd: '# Browse: https://gtfobins.github.io/' },
      { name: 'LOLBAS', stars: '7.5k', desc: 'Living Off The Land Binaries, Scripts and Libraries (Windows)', url: 'https://github.com/LOLBAS-Project/LOLBAS', tags: ['windows', 'lolbin', 'bypass'], cmd: '# Browse: https://lolbas-project.github.io/' },
      { name: 'BloodHound', stars: '9.9k', desc: 'Attack paths in Active Directory using graph theory', url: 'https://github.com/SpecterOps/BloodHound', tags: ['ad', 'graph', 'privesc'], cmd: 'SharpHound.exe -c All' },
      { name: 'BeRoot', stars: '2.2k', desc: 'Privilege escalation tool for Windows, Linux, and macOS', url: 'https://github.com/AlessandroZ/BeRoot', tags: ['privesc', 'windows', 'linux'], cmd: 'python beroot.py' },
      { name: 'PrintSpoofer', stars: '3.6k', desc: 'Abuse SeImpersonatePrivilege on Windows 10 and Server 2016/2019', url: 'https://github.com/itm4n/PrintSpoofer', tags: ['windows', 'privesc', 'impersonate'], cmd: 'PrintSpoofer.exe -c cmd' }
    ]
  },
  network: {
    label: '🌐 Network & Infrastructure',
    color: '#60a5fa',
    items: [
      { name: 'nmap', stars: '10.6k', desc: 'Legendary network mapper — port scan, version detect, NSE scripts', url: 'https://github.com/nmap/nmap', tags: ['portscan', 'network', 'nse'], cmd: 'nmap -sV -sC -p- --min-rate 5000 -oN scan.txt target.com' },
      { name: 'rustscan', stars: '14.8k', desc: 'Blazing fast port scanner (Rust) — finds all ports then passes to Nmap', url: 'https://github.com/RustScan/RustScan', tags: ['portscan', 'rust', 'fast'], cmd: 'rustscan -a target.com --ulimit 5000 -- -sV -sC' },
      { name: 'nikto', stars: '8.2k', desc: 'Web server scanner — outdated software, misconfigs, dangerous files', url: 'https://github.com/sullo/nikto', tags: ['web', 'scanner', 'perl'], cmd: 'nikto -h https://target.com -ssl -output nikto.html -Format html' },
      { name: 'testssl.sh', stars: '8.5k', desc: 'Testing TLS/SSL ciphers, protocols, and crypto vulnerabilities', url: 'https://github.com/drwetter/testssl.sh', tags: ['ssl', 'tls', 'crypto'], cmd: 'testssl.sh --severity HIGH --full https://target.com' },
      { name: 'responder', stars: '5.5k', desc: 'LLMNR/NBT-NS/MDNS poisoner for credential capture on LAN', url: 'https://github.com/lgandx/Responder', tags: ['llmnr', 'ntlm', 'credential'], cmd: 'python3 Responder.py -I eth0 -wrd' },
      { name: 'bettercap', stars: '13.0k', desc: 'The Swiss Army knife for wifi, BLE, IPv4 and IPv6 networks reconnaissance and attacking', url: 'https://github.com/bettercap/bettercap', tags: ['network', 'wifi', 'mitm'], cmd: 'bettercap -iface eth0' }
    ]
  },
  writeups: {
    label: '📖 Write-ups, Methodology & Learning',
    color: '#d29922',
    items: [
      { name: 'Bug-Bounty-Resources', stars: '4.8k', desc: 'Compilation of bug bounty writeups, tools, and resources by B3nac', url: 'https://github.com/B3nac/Android-Reports-and-Resources', tags: ['resources', 'learning', 'mobile'], cmd: '# Browse the repo for categorized learning' },
      { name: 'HowToHunt', stars: '5.5k', desc: 'Collection of methodologies for hunting specific vulnerability types', url: 'https://github.com/KathanP19/HowToHunt', tags: ['methodology', 'guide', 'howto'], cmd: '# Reference guide for specific vulnerability hunting' },
      { name: 'AllAboutBugBounty', stars: '5.9k', desc: 'Everything you need to know about bug bounty programs', url: 'https://github.com/daffainfo/AllAboutBugBounty', tags: ['bugbounty', 'guide', 'checklist'], cmd: '# Reference by daffainfo — organized by vulnerability type' },
      { name: 'Bug-Bounty-Wordlists', stars: '2.1k', desc: 'Collection of wordlists specifically curated for bug bounty hunting', url: 'https://github.com/YaS5in3/Bug-Bounty-Wordlists', tags: ['wordlist', 'bugbounty', 'fuzzing'], cmd: 'ffuf -u https://target.com/FUZZ -w bb-wordlist.txt' },
      { name: 'hacker-roadmap', stars: '13.7k', desc: 'Guide for amateurs pen testers and ethical hackers', url: 'https://github.com/sundowndev/hacker-roadmap', tags: ['roadmap', 'learning', 'guide'], cmd: '# Learning roadmap — see visual at repo' },
      { name: 'awesome-bugbounty-tools', stars: '4.9k', desc: 'Curated list of various bug bounty tools and resources', url: 'https://github.com/vavkamil/awesome-bugbounty-tools', tags: ['tools', 'resources', 'curated'], cmd: '# Reference list organized by category' },
      { name: 'Web-Security-Learning', stars: '1.9k', desc: 'Collection of web security learning resources, CTFs, and writeups', url: 'https://github.com/qazbnm456/awesome-web-hacking', tags: ['learning', 'ctf', 'web'], cmd: '# Read and bookmark relevant sections' },
      { name: 'nahamsec-resources', stars: '8.9k', desc: 'NahamSec\'s bug bounty resources, roadmap and learning links', url: 'https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters', tags: ['bugbounty', 'beginner', 'resources'], cmd: '# Follow the roadmap in README' },
      { name: 'bugbounty-cheatsheet', stars: '4.8k', desc: 'Web application attack cheatsheets for bug bounty hunting', url: 'https://github.com/EdOverflow/bugbounty-cheatsheet', tags: ['cheatsheet', 'web', 'attacks'], cmd: '# Browse by vulnerability type' },
      { name: 'hackerone-reports', stars: '2.2k', desc: 'Collection of public HackerOne bug bounty reports for learning', url: 'https://github.com/reddelexc/hackerone-reports', tags: ['writeups', 'h1', 'reports'], cmd: '# Study real-world reports organized by vulnerability' },
      { name: 'pentesterland-writeups', stars: '2.5k', desc: 'Curated list of public bug bounty writeups sorted by vulnerability type', url: 'https://github.com/pentesterland/Writeups', tags: ['writeups', 'bugbounty', 'learning'], cmd: '# Study public write-ups categorized by type' }
    ]
  },
  subdomain_takeover: {
    label: '🏳️ Subdomain Takeover',
    color: '#fb923c',
    items: [
      { name: 'subjack', stars: '3.2k', desc: 'Subdomain takeover tool written in Go — checks for dangling CNAMEs', url: 'https://github.com/haccer/subjack', tags: ['takeover', 'subdomain', 'go'], cmd: 'subjack -w subs.txt -t 100 -o takeover.txt -ssl' },
      { name: 'subzy', stars: '1.6k', desc: 'Fast subdomain takeover tool checking 50+ vulnerable services', url: 'https://github.com/PentestPad/subzy', tags: ['takeover', 'go', 'fast'], cmd: 'subzy run --targets subs.txt' },
      { name: 'nuclei-takeover', stars: '600', desc: 'Nuclei takeover templates for 50+ services', url: 'https://github.com/projectdiscovery/nuclei-templates/tree/main/takeovers', tags: ['nuclei', 'takeover', 'templates'], cmd: 'nuclei -l subs.txt -t takeovers/' },
      { name: 'can-i-take-over-xyz', stars: '5.1k', desc: 'Comprehensive list of services susceptible to subdomain takeover', url: 'https://github.com/EdOverflow/can-i-take-over-xyz', tags: ['takeover', 'reference', 'services'], cmd: '# Reference list of vulnerable services' },
      { name: 'dnsrecon', stars: '3.6k', desc: 'DNS Security Assessment tool', url: 'https://github.com/darkoperator/dnsrecon', tags: ['dns', 'recon', 'python'], cmd: 'dnsrecon -d target.com' }
    ]
  },
  secretsTools: {
    label: '🕵️ Secret & Credential Discovery',
    color: '#f472b6',
    items: [
      { name: 'trufflehog', stars: '17.2k', desc: 'Find credentials in git history, S3, GitHub, Slack, 800+ sources', url: 'https://github.com/trufflesecurity/trufflehog', tags: ['secrets', 'git', 'scanning'], cmd: 'trufflehog github --org=targetorg --only-verified' },
      { name: 'gitleaks', stars: '18.5k', desc: 'Detect hardcoded secrets in git repos, CI/CD pipelines', url: 'https://github.com/gitleaks/gitleaks', tags: ['secrets', 'git', 'ci'], cmd: 'gitleaks detect --source . -v' },
      { name: 'gitrob', stars: '5.9k', desc: 'Reconnaissance for GitHub orgs — find sensitive files in public repos', url: 'https://github.com/michenriksen/gitrob', tags: ['github', 'secrets', 'osint'], cmd: 'gitrob --github-access-token TOKEN targetorg' },
      { name: 'secretfinder', stars: '2.1k', desc: 'Find sensitive data in JS files — API keys, tokens, endpoints', url: 'https://github.com/m4ll0k/SecretFinder', tags: ['js', 'secrets', 'api-keys'], cmd: 'python3 SecretFinder.py -i https://target.com/main.js -o cli' },
      { name: 'JSluice', stars: '1.1k', desc: 'Extract URLs, paths, secrets from JS files using AST analysis', url: 'https://github.com/BishopFox/jsluice', tags: ['js', 'urls', 'ast'], cmd: 'jsluice urls --input-format=file main.js' },
      { name: 'LinkFinder', stars: '3.5k', desc: 'Python script to find endpoints in JavaScript files', url: 'https://github.com/GerbenJavado/LinkFinder', tags: ['js', 'endpoints', 'python'], cmd: 'python3 linkfinder.py -i https://target.com -d -o cli' },
      { name: 'dumpsterDiver', stars: '1.6k', desc: 'Tool to search for hardcoded secrets in various file types (JS, JSON, YAML, etc.)', url: 'https://github.com/nrich/dumpsterDiver', tags: ['secrets', 'scanning', 'entropy'], cmd: 'python3 dumpsterDiver.py -p /path/to/project' }
    ]
  },
  cheatsheets: {
    label: '📋 Cheatsheets & References',
    color: '#94a3b8',
    items: [
      { name: 'OWASP Testing Guide', stars: '7.5k', desc: 'Official OWASP Web Security Testing Guide v4.2 — complete methodology', url: 'https://github.com/OWASP/wstg', tags: ['owasp', 'guide', 'methodology'], cmd: '# Browse at https://owasp.org/www-project-web-security-testing-guide/' },
      { name: 'HackTricks', stars: '9.7k', desc: 'Comprehensive hacking tricks and techniques for pentest & CTF', url: 'https://github.com/carlospolop/hacktricks', tags: ['tricks', 'pentest', 'ctf'], cmd: '# Browse at https://book.hacktricks.xyz/' },
      { name: 'ippsec-notes', stars: '1.4k', desc: 'IppSec\'s HTB notes and methodology (top bug hunter / CTF player)', url: 'https://github.com/ippsec', tags: ['notes', 'htb', 'ctf'], cmd: '# Study IppSec YouTube videos and notes' },
      { name: 'pentest-everything', stars: '1.9k', desc: 'Massive collection of pentest knowledge organized by topic', url: 'https://github.com/vvinn/pentest-everything', tags: ['pentest', 'reference', 'all-in-one'], cmd: '# Reference — browse by vulnerability category' },
      { name: 'awesome-hacking', stars: '13.1k', desc: 'Curated list of hacking resources and awesome learning materials', url: 'https://github.com/carpedm20/awesome-hacking', tags: ['learning', 'resources', 'curated'], cmd: '# Browse curated list by topic' },
      { name: 'BugBountyHunting', stars: '3.1k', desc: 'Collection of resources, tools, and tips for bug bounty hunting', url: 'https://github.com/gwendallecoguic/awesome-bugbounty', tags: ['bugbounty', 'resources', 'tips'], cmd: '# Browse organized list of resources' },
      { name: 'Reverse Shell Generator', stars: '4.9k', desc: 'Interactive Reverse Shell Generator with multiple languages and listeners', url: 'https://github.com/0x03mad/revshells', tags: ['cheatsheet', 'payloads', 'reverse-shell'], cmd: '# Use web app or curl config' },
      { name: 'PortSwigger XSS Cheatsheet', stars: '2.1k', desc: 'Cross-site scripting (XSS) cheat sheet by PortSwigger', url: 'https://portswigger.net/web-security/cross-site-scripting/cheat-sheet', tags: ['xss', 'cheatsheet', 'portswigger'], cmd: '# Reference for XSS vectors and bypasses' }
    ]
  }
};

// ── RENDER GITHUB RESOURCES ───────────────────────────────────
let ghSearch = '';
let ghCategoryFilter = '';
let ghSortBy = 'default';

function renderGithubResources() {
  const el = document.getElementById('gh-resources-list');
  if (!el) return;
  const q = ghSearch.toLowerCase();
  const catFilter = ghCategoryFilter;
  let totalShown = 0;
  let html = '';

  let allCats = JSON.parse(JSON.stringify(ghResources)); 
  if (window.S && S.customGhResources) {
    S.customGhResources.forEach(cr => {
      let cKey = cr.cat || 'custom';
      if (!allCats[cKey]) {
        allCats[cKey] = { label: '🛠️ ' + cKey.toUpperCase(), color: '#a3a3a3', items: [] };
      }
      allCats[cKey].items.push(cr);
    });
  }

  let favs = (window.S && S.favoriteGhResources) ? S.favoriteGhResources : [];

  // Render Dynamic Category Filter Pills
  const filterBar = document.getElementById('gh-filter-bar');
  if (filterBar) {
    let totalAll = 0;
    Object.keys(allCats).forEach(k => {
      totalAll += allCats[k].items.length;
    });

    let filterHtml = `<button class="gh-cat-btn ${ghCategoryFilter === '' ? 'active' : ''}" onclick="ghCategoryFilter=''; renderGithubResources()">All Categories <span class="pill-count">${totalAll}</span></button>`;
    
    for (const [k, cat] of Object.entries(allCats)) {
      const count = cat.items.length;
      if (count > 0) {
        filterHtml += `<button class="gh-cat-btn ${ghCategoryFilter === k ? 'active' : ''}" onclick="ghCategoryFilter='${esc(k)}'; renderGithubResources()">${esc(cat.label)} <span class="pill-count">${count}</span></button>`;
      }
    }
    filterBar.innerHTML = filterHtml;
  }

  for (const [catKey, cat] of Object.entries(allCats)) {
    if (catFilter && catFilter !== catKey) continue;
    let items = cat.items;
    if (q) {
      items = items.filter(r =>
        r.name.toLowerCase().includes(q) ||
        (r.desc||'').toLowerCase().includes(q) ||
        (r.tags||[]).some(t => t.toLowerCase().includes(q))
      );
    }
    if (!items.length) continue;

    // Sorting
    if (ghSortBy === 'stars_desc') {
      items.sort((a, b) => {
        const parseStars = s => {
          if (!s) return 0;
          let str = String(s).toLowerCase();
          let multi = str.includes('k') ? 1000 : (str.includes('m') ? 1000000 : 1);
          return parseFloat(str.replace(/[^0-9.]/g, '')) * multi;
        };
        return parseStars(b.stars) - parseStars(a.stars);
      });
    } else if (ghSortBy === 'alpha_asc') {
      items.sort((a, b) => a.name.localeCompare(b.name));
    }
    
    // Bubble favorites to top
    items.sort((a, b) => {
      let aFav = favs.includes(a.name) ? 1 : 0;
      let bFav = favs.includes(b.name) ? 1 : 0;
      return bFav - aFav; 
    });

    totalShown += items.length;
    html += `
      <div class="gh-category" id="ghcat-${catKey}">
        <div class="gh-cat-head" style="border-left: 3px solid ${cat.color}">
          <span class="gh-cat-label" style="color:${cat.color}">${cat.label}</span>
          <span class="gh-cat-count">${items.length} tools</span>
        </div>
        <div class="gh-grid">
          ${items.map(r => {
            const isFav = favs.includes(r.name);
            const isCustom = r.isCustom;
            let installCmd = 'git clone ' + r.url;
            if (r.tags && r.tags.includes('go') && r.url.includes('github.com')) {
              installCmd = 'go install ' + r.url.replace('https://', '') + '@latest';
            }
            return `
            <div class="gh-card" style="${isFav ? 'border:1px solid var(--yellow);box-shadow:0 4px 12px rgba(234,179,8,0.1);' : ''}">
              <div class="gh-card-head">
                <div>
                  <a href="${r.url}" target="_blank" class="gh-card-name">${esc(r.name)}</a>
                  <span class="gh-stars">⭐ ${r.stars || 'Custom'}</span>
                </div>
                <div style="display:flex;gap:6px">
                  <button class="copy-btn" style="${isFav ? 'color:var(--yellow);border-color:var(--yellow);' : ''}" onclick="toggleFavoriteGhResource('${esc(r.name).replace(/'/g, "\\'")}')" title="Favorite">⭐</button>
                  ${isCustom ? `<button class="copy-btn" style="color:var(--red);border-color:var(--red);" onclick="deleteCustomGhResource(${r.id})" title="Delete Custom Resource">🗑️</button>` : ''}
                  <a href="${r.url}" target="_blank" class="copy-btn" title="Open GitHub">⎋ GitHub</a>
                </div>
              </div>
              <div class="gh-card-desc">${esc(r.desc)}</div>
              <div style="display:flex; gap: 8px; margin-bottom: 8px;">
                <div class="gh-card-cmd" style="flex:1; margin-bottom:0;" onclick="navigator.clipboard.writeText(this.innerText).then(()=>toast('Command copied!'))" title="Copy Run Command">${esc(r.cmd)}</div>
                <button class="copy-btn" style="padding: 0 10px; height: auto;" data-cmd="${esc(installCmd).replace(/"/g, '&quot;')}" onclick="navigator.clipboard.writeText(this.getAttribute('data-cmd')).then(()=>toast('Install command copied!'))" title="Copy Install Cmd">⬇️ Install</button>
              </div>
              <div class="gh-card-tags">${(r.tags||[]).map(t => `<span class="tag-chip" onclick="ghSearch='${t}';document.getElementById('gh-search').value='${t}';renderGithubResources()">${esc(t)}</span>`).join('')}</div>
            </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  if (!totalShown) {
    el.innerHTML = `<div class="empty-state"><div class="es-icon">🔍</div><div class="es-title">No resources match</div><div class="es-sub">Try a different search term or clear filters</div></div>`;
    return;
  }
  el.innerHTML = html;
  document.getElementById('gh-total-count').textContent = totalShown + ' tools';
}

function saveCustomGhResource() {
  const name = document.getElementById('gh-name').value.trim();
  const url = document.getElementById('gh-url').value.trim();
  const catSelect = document.getElementById('gh-cat-select').value;
  const cat = catSelect === '__custom__' ? (document.getElementById('gh-cat-custom').value.trim() || 'custom') : catSelect;
  const desc = document.getElementById('gh-desc').value.trim();
  const tagsStr = document.getElementById('gh-tags').value.trim();
  const cmd = document.getElementById('gh-cmd').value.trim();
  const starsStr = document.getElementById('modal-add-gh').dataset.fetchedStars || 'Custom';
  
  if (!name || !url) { toast('Name and URL are required'); return; }
  
  let tags = tagsStr ? tagsStr.split(',').map(t => t.trim()).filter(Boolean) : [];
  
  if (!window.S) return;
  if (!S.customGhResources) S.customGhResources = [];
  
  S.customGhResources.unshift({
    id: Date.now(),
    name,
    url,
    cat,
    desc,
    tags,
    cmd,
    stars: starsStr,
    isCustom: true
  });
  
  delete document.getElementById('modal-add-gh').dataset.fetchedStars;
  
  // Clear inputs
  document.getElementById('gh-name').value = '';
  document.getElementById('gh-url').value = '';
  document.getElementById('gh-cat-select').value = 'recon';
  document.getElementById('gh-cat-custom').value = '';
  document.getElementById('gh-cat-custom-wrap').style.display = 'none';
  document.getElementById('gh-desc').value = '';
  document.getElementById('gh-tags').value = '';
  document.getElementById('gh-cmd').value = '';
  
  save(); 
  closeModal('modal-add-gh'); 
  renderGithubResources(); 
  toast('Custom resource saved!');
}

function deleteCustomGhResource(id) {
  if (confirm('Delete custom GitHub resource?')) {
    S.customGhResources = S.customGhResources.filter(r => r.id !== id);
    save();
    renderGithubResources();
  }
}

function toggleFavoriteGhResource(name) {
  if (!S.favoriteGhResources) S.favoriteGhResources = [];
  if (S.favoriteGhResources.includes(name)) {
    S.favoriteGhResources = S.favoriteGhResources.filter(n => n !== name);
    toast('Removed from favorites');
  } else {
    S.favoriteGhResources.push(name);
    toast('Added to favorites');
  }
  save();
  renderGithubResources();
}

async function autoFillGhResource() {
  const urlInput = document.getElementById('gh-url').value.trim();
  if (!urlInput || !urlInput.includes('github.com/')) {
    toast('Please enter a valid GitHub repository URL');
    return;
  }
  
  const match = urlInput.match(/github\.com\/([^\/]+\/[^\/]+)/);
  if (!match) {
    toast('Invalid GitHub URL format');
    return;
  }
  
  const repoPath = match[1].replace(/\.git$/, '');
  const btn = event.target;
  const originalText = btn.innerText;
  btn.innerText = '⏳ Syncing...';
  btn.disabled = true;
  
  try {
    const res = await fetch(`https://api.github.com/repos/${repoPath}`);
    if (!res.ok) throw new Error('Repo not found or rate limited');
    const data = await res.json();
    
    document.getElementById('gh-name').value = data.name || '';
    document.getElementById('gh-desc').value = data.description || '';
    
    let stars = data.stargazers_count || 0;
    let starsStr = stars > 999 ? (stars/1000).toFixed(1) + 'k' : stars.toString();
    document.getElementById('modal-add-gh').dataset.fetchedStars = starsStr;
    
    let tags = [];
    if (data.language) tags.push(data.language.toLowerCase());
    if (data.topics && data.topics.length) {
      tags = tags.concat(data.topics.slice(0, 4));
    }
    document.getElementById('gh-tags').value = tags.join(', ');
    
    // Intelligent Category Assignment
    let textToAnalyze = (data.description + ' ' + tags.join(' ')).toLowerCase();
    let bestCat = '';
    const catMap = {
      recon: ['recon', 'osint', 'subdomain', 'enum', 'discovery'],
      scanning: ['scan', 'fuzz', 'crawl', 'spider', 'directory'],
      exploitation: ['exploit', 'sqli', 'xss', 'ssrf', 'rce', 'inject'],
      wordlists: ['wordlist', 'payload', 'dictionary', 'seclists'],
      cloud: ['cloud', 'aws', 'gcp', 'azure', 's3', 'bucket'],
      secretsTools: ['secret', 'credential', 'token', 'key', 'leak'],
      burp: ['burp', 'proxy', 'bapp'],
      api: ['api', 'graphql', 'rest', 'openapi', 'swagger'],
      privilege: ['privesc', 'privilege', 'escalation', 'bloodhound'],
      network: ['nmap', 'portscan', 'network', 'tls', 'ssl']
    };
    
    for (const [cat, keywords] of Object.entries(catMap)) {
      if (keywords.some(k => textToAnalyze.includes(k))) {
        bestCat = cat;
        break; // Stop at first match
      }
    }
    
    if (bestCat) {
      document.getElementById('gh-cat').value = bestCat;
    }
    
    toast('Repo data fetched & categorized successfully!');
  } catch (err) {
    toast('Failed to fetch repo: ' + err.message);
  } finally {
    btn.innerText = originalText;
    btn.disabled = false;
  }
}

function exportGhToolkit() {
  const exportData = {
    customGhResources: (window.S && S.customGhResources) ? S.customGhResources : [],
    favoriteGhResources: (window.S && S.favoriteGhResources) ? S.favoriteGhResources : []
  };
  
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
  const dlAnchorElem = document.createElement('a');
  dlAnchorElem.setAttribute("href", dataStr);
  dlAnchorElem.setAttribute("download", "0xHunter_Toolkit.json");
  dlAnchorElem.click();
  toast('Toolkit exported successfully!');
}

function importGhToolkit(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const data = JSON.parse(e.target.result);
      if (!window.S) return;
      
      if (data.customGhResources && Array.isArray(data.customGhResources)) {
        if (!S.customGhResources) S.customGhResources = [];
        data.customGhResources.forEach(importedItem => {
          if (!S.customGhResources.find(r => r.url === importedItem.url)) {
            importedItem.id = Date.now() + Math.random();
            S.customGhResources.push(importedItem);
          }
        });
      }
      
      if (data.favoriteGhResources && Array.isArray(data.favoriteGhResources)) {
        if (!S.favoriteGhResources) S.favoriteGhResources = [];
        data.favoriteGhResources.forEach(fav => {
          if (!S.favoriteGhResources.includes(fav)) {
            S.favoriteGhResources.push(fav);
          }
        });
      }
      
      save();
      renderGithubResources();
      toast('Toolkit imported successfully!');
    } catch (err) {
      toast('Invalid toolkit JSON file');
    }
  };
  reader.readAsText(file);
  event.target.value = ''; 
}
