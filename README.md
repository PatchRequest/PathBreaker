# Pathbreaker

**Pathbreaker** is a powerful path traversal tool designed for security researchers and penetration testers. It supports advanced evasion techniques and offers flexible filtering options for HTTP codes and response patterns.

## Usage    
```bash
./pathbreaker -url="http://localhost:8000/image?filename=PATHBREAKER&testing=wwww"
./pathbreaker -url="http://localhost:8000/image?filename=PATHBREAKER&testing=wwww" -proxy="http://127.0.0.1:8080" -whitelist="200" -blacklist="404,500" -whiteregex=".*Success.*" -blackregex=".*Error.*" -targetFile="etc/passwd"
```
This command will attempt to traverse the target file /etc/passwd while routing requests through a proxy, applying the specified whitelist/blacklist codes, and filtering responses using regular expressions.

## Features

- **HTTP Proxy Support**: Route requests through a proxy.
- **HTTP Code Whitelist/Blacklist**: Fine-tune the response codes to accept or reject.
- **Regex Filtering**: Use regex to whitelist or blacklist response content.
- **Targeted File Extraction**: Attempt to extract specific files from the target using path traversal techniques.

## Techniques

Pathbreaker utilizes various advanced techniques to bypass security measures:

- **Nesting Slash Scans**: Bypass filters using nested slashes (e.g., `....//`).
- **Flip-Flop Slashes**: Alternate between forward and backward slashes (e.g., `/\../`).
- **URL Encoding**: Encode payloads to avoid detection.
- **16-bit Encoding**: Obfuscate payloads with 16-bit Unicode.
- **Double URL Encoding**: Apply multiple URL encodings to evade filters.
- **Null Terminator Injection**: Use null terminators (`%00`) to terminate strings prematurely.
- **Pre-pended Payloads**: Insert payloads at the beginning of paths to evade input filters.

## Installation

```bash
git clone https://github.com/PatchRequest/Pathbreaker.git
cd Pathbreaker
go build -o pathbreaker
```


## Flags
-url: The target URL to scan.
-proxy: (Optional) The HTTP proxy to route requests through (e.g., http://localhost:8080).
-whitelist: (Optional) Comma-separated list of HTTP status codes to whitelist. Defaults to 200.
-blacklist: (Optional) Comma-separated list of HTTP status codes to blacklist. Defaults to 404,500.
-whiteregex: (Optional) Regular expression to whitelist response content.
-blackregex: (Optional) Regular expression to blacklist response content.
-targetFile: The file to attempt to extract via path traversal. Defaults to etc/passwd.

## Contributing
Feel free to fork this repository, submit issues, or contribute by making pull requests. All contributions are welcome!

