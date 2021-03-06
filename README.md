
# spf_packer

This tool was created in response to exceeding the recommended number of DNS lookups defined by rfc7208.
By resolving the various entries ahead of time, it's possible to reduce the number of DNS calls below
that threshold and host the full set of allowed IP addresses at the SPF owners domain.


# Configuration

`spf_packer` takes the following arguments

## Command line arguments
| Name | Data type | Description |
| ---| --- | --- |
| `dryrun` | flag | Run without making changes to the DNS backend. |
| `verbose` | flag | Increase verbosity of actions performed by spf_packer. |
| `help` | flag | Command line help. |
| `config` | argument | The filename of the YAML configuration file used by spf_packer. |

`spf_packer` reads the YAML configuration file either from the same directory as the executable or
as provided with `--config` argument.

## YAML configuration example

```
---
version: spf1
domain: domain.example
spfmaxchars: 500
policy: "~all"
rawtxt: "include:anotherdomain.example"
ipv4:
  - 127.0.0.1/8
ipv6:
  - "::1"
includes:
  - domain1.example
  - domain2.example
  - subdomain.domain3.example
a:
  - mailhost.example
mx:
  - domain.example
redirect: []
```
## Options
| Name | Data type | Description |
| ---| --- | --- |
| `version` | string | The spf version string, `spf1` is the current version as of writing. |
| `domain` | string | The name of the domain to be used when generating include directives. (normally the owners domain) |
| `spfmaxchars` | integer | The maximum number of characters an SPF TXT record may contain before another is created. |
| `rawtxt` | string | Insert raw text into the SPF TXT record before any name resolution is performed. |
| `policy` | string | The SPF policy to be used when generating the SPF TXT records. |
| `ipv4` | list of strings | IPv4 addresses in CIDR notation to be included. |
| `ipv6` | list of strings | IPv6 addresses in CIDR notation to be included. |
| `includes` | list of strings | 3rd party domains to be queried for SPF TXT records. |
| `a` | list of strings | Address records to be resolved. |
| `mx` | list of strings | Mail Exchange records to be resolved. |
| `redirect` | N/A| Unsupported. |

# License

MIT License
