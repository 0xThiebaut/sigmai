# Sigma Importer
Sigma Importer (a.k.a. `sigmai`) is a project designed to do the opposite of [Sigma](https://github.com/Neo23x0/sigma).
The objective of `sigmai` is to convert specific data sources into the Sigma generic and open signature format.

## Installation
If you have [Go](https://golang.org/) installed, you can get the newest version of `sigmai` through:

```bash
go get github.com/0xThiebaut/sigmai
```

Alternatively, you can download the [release binaries](https://github.com/0xThiebaut/sigmai/releases) which are updated less frequently.

## Usage
For the generic usage's help section, `sigmai` is equipped with the `--help` flag (shorthand `-h`).

```bash
sigmai --help
```

> ```
> Usage of ./sigmai:
>       --directory-path string       Directory: Path to save rules
>   -h, --help                        Display this help section
>   -i, --interval string             Continuous importing interval
>       --json                        Output JSON instead of pretty print
>       --level-set string            Set level on all rules [low, medium, high, critical]
>       --misp-buffer int             MISP: Size of the event buffer (default 500)
>       --misp-events ints            MISP: Only events with matching IDs
>       --misp-ids-exclude            MISP: Only IDS-disabled attributes
>       --misp-ids-ignore             MISP: All attributes regardless of their IDS flag
>       --misp-insecure               MISP: Allow insecure connections when using SSL
>       --misp-key string             MISP: User API key
>       --misp-keywords stringArray   MISP: All events containing any of the keywords
>       --misp-levels stringArray     MISP: Only events with matching threat levels [1-4]
>       --misp-period strings         MISP: Only events within time-frame (4d, 3w, ...)
>       --misp-published              MISP: Only published events
>       --misp-published-exclude      MISP: Only unpublished events
>       --misp-tags stringArray       MISP: Only events with matching tags
>       --misp-url string             MISP: Instance API base URL
>       --misp-warning-include        MISP: Include attributes listed on warning-list
>       --misp-workers int            MISP: Number of concurrent workers (default 20)
>   -q, --quiet                       Only output error information
>   -s, --source string               Source backend [misp]
>       --status-set string           Set status on all rules [experimental, testing, stable]
>       --tags-add stringArray        Add tags on all rules
>       --tags-clear                  Clear tags from all rules
>       --tags-rm stringArray         Remove tags from all rules
>       --tags-set stringArray        Set tags on all rules
>   -t, --target string               Target backend [stdout, directory] (default "stdout")
>   -v, --verbose                     Show debug information
> ```

### Sources
A source is the origin from which data will be fetched in order to generate Sigma rules.
Currently, [MISP](https://github.com/MISP/MISP) is the only implemented source.

A source can be defined through the `--source` flag (shorthand `-s`).
Currently, the only acceptable value for this flag is `misp`.

#### MISP
Importing events from MISP can be done by specifying `misp` as source.
When using MISP, The following flags are required:

| Flag            | Description                                                                       |
|-----------------|-----------------------------------------------------------------------------------|
| `--misp-url`    | The URL at which the MISP instance API can be queried (i.e. `https://localhost`). |
| `--misp-key`    | A User API key authorized to query the MISP instance.                             |

##### Use Cases
A sample `sigmai` command would be as follows:

```bash
sigmai -t stdout -s misp --misp-url https://localhost --misp-key CAFEBABE== --misp-levels 1,2
```

The above command sends the Sigma rules to the `stdout` target (`-t`; more on that later).
The Sigma rules are to be generated from the `misp` source (`-s`).
In MISP, we'll solely generate Sigma rules for event's with a level (`--misp-levels`) of high (`1`) or medium (`2`).
For the eligible events, only attributes flagged for IDS (decent enough for detection) will be used.
Furthermore, any attribute on a [warning list](https://github.com/MISP/misp-warninglists) (a.k.a. subject to false positives) won't be included.

As an example, this is how a generated multi-document Sigma rule would look like if imported from MISP:

```yaml
action: global
title: 'OSINT: Emissary Panda – A potential new malicious tool'
id: 5b0562d3-8460-4482-93c4-05a3ac12042b
status: experimental
description: See MISP event 60870
author: dcso.de
level: medium
tags:
- APT
- tlp:white
- iep:traffic-light-protocol="WHITE"
- DCSO:tie="ALL"
- DCSO:sharing="PUBLIC"
- osint:source-type="blog-post"
---
logsource:
  product: windows
detection:
  condition:
  - event60870
  - all of event60870attr2049468mapping*
  - event60870object33488
  - event60870object33489
  - event60870object33490 and all of event60870object33490attr2049523mapping*
  - event60870object33491 and all of event60870object33491attr2049526mapping*
  event60870:
    DestinationIp:
    - 159.65.80.157
    - 103.59.144.183
  event60870attr2049468mappingFilename:
  - Image|endswith: '%APPDATA%\systemconfig\sys.bin.url'
  - ParentImage|endswith: '%APPDATA%\systemconfig\sys.bin.url'
  - CommandLine|contains: '%APPDATA%\systemconfig\sys.bin.url'
  - ParentCommandLine|contains: '%APPDATA%\systemconfig\sys.bin.url'
  - ProcessName: '%APPDATA%\systemconfig\sys.bin.url'
  - ParentProcessName: '%APPDATA%\systemconfig\sys.bin.url'
  event60870object33488:
    Hashes|contains:
    - c69d60b82252b6e7eaaeb710d5e1ebe5
    - 4c0211c91b4b9f99e52f4d385e6e3960b321a3b0
    - 4d65d371a789aabe1beadcc10b38da1f998cd3ec87d4cc1cfbf0af014b783822
    - 768:NHO6X9W62QIPe1HhDIRmnTEDtcvyvfSl0zeM:NHOymWBDLYg0zB
  event60870object33489:
    Hashes|contains: 93b972951685b4ae284583dbc3959725
  event60870object33490:
    Hashes|contains: 2b2bb4c132d808572f180fe4db3a0a3143a37fdece667f8e78778ee1e9717606
  event60870object33490attr2049523mappingFilename:
  - Image|endswith: sys.bin.url
  - ParentImage|endswith: sys.bin.url
  - CommandLine|contains: sys.bin.url
  - ParentCommandLine|contains: sys.bin.url
  - ProcessName: sys.bin.url
  - ParentProcessName: sys.bin.url
  event60870object33491:
    Hashes|contains: 3e718f39dfb2f6b8fba366fefa8b7c127db1e6795f3caad2d4a9f3753eea0adc
  event60870object33491attr2049526mappingFilename:
  - Image|endswith: sys.bin.url
  - ParentImage|endswith: sys.bin.url
  - CommandLine|contains: sys.bin.url
  - ParentCommandLine|contains: sys.bin.url
  - ProcessName: sys.bin.url
  - ParentProcessName: sys.bin.url
---
// Many more log-sources (firewall, proxy, webserver, ...) are trimmed for readability...
```

###### Specific Events
Alternatively, you might wish to import a specific set of events.
To do so, you might use the `--misp-events` flag as follows:

```bash
sigmai -t stdout -s misp --misp-url https://localhost --misp-key CAFEBABE== --misp-events 123,456,789
```

The above command will import the events with IDs `123`, `456` and `789`.

###### Searching Events
You can also import events whose description contains one of the specified case-sensitive sub-string.
To do so, you would need to use the `--misp-keywords` flag as follows:

```bash
sigmai -t stdout -s misp --misp-url https://localhost --misp-key CAFEBABE== --misp-keywords emotet,zloader
```

The above command will import all events whose description contains either the `emotet` or `zloader` substring.

### Targets
A target is a way to select where to send the generated Sigma rules.

Defining the target can be done using the `--target` flag (shorthand `-t`).
Currently, both `stdout` and `directory` are implemented.

#### Stdout
This target outputs the generated Sigma rules to the [standard output](https://en.wikipedia.org/wiki/Stdout).
It can be selected by using `stdout` as the `--target` flag's value.

Do note that all other logging is send to the  [standard error](https://en.wikipedia.org/wiki/Standard_streams#Standard_error_(stderr)), which enables you to split logging and generated Sigma rules.

#### Directory
This target output's the generated Sigma rules into a directory, which defaults to the current one.
It can be selected by using `directory` as the `--target` flag's value.

Additionally, one may change the path using the `--directory-path` flag.

### Modifiers
The `sigmai` tool comes with some additional modifiers to ensure the generated rules meet your existing standard.

#### Tags
More specifically, one can modify the imported rule's tags by using the beneath flags.

| Flag            | Description                                                                               |
|-----------------|-------------------------------------------------------------------------------------------|
| `--tags-add`    | A flag with a comma-separated list of tags to be added to the current ones.               |
| `--tags-rm`     | A flag with a comma-separated list of tags to be removed if present in the current ones.  |
| `--tags-set`    | A flag with a comma-separated list of tags to overwrite the current ones.                 |
| `--tags-clear`  | A flag clearing all tags, resulting in tag-less rules.                                    |

#### Level
You can also override the rules by defining a common level using the `--level-set` flag.

#### Status
As for levels, `sigmai` enables you to override the status of all rules by using the `--status-set` flag.

### Continuous Importing
It is possible to run `sigmai` continuously a bit like a cron job would.
The `--interval` flag (shorthand `-i`) defines an interval at which an import should be done.

This flag can be combined with source's period-filters such as MISP's `--misp-period` flag.
As an example, the beneath command will import the last 15 minutes of MISP events as Sigma rules every 10 minutes.

```bash
sigmai -t directory --directory-path ~/rules -i 10m -s misp --misp-url https://localhost --misp-key CAFEBABE== --misp-period 15m
``` 

## Tips & Tricks

### Filter Your Queries
The `sigmai`-generated queries will hopefully cover more cases (log-sources, platforms, ...) than you actually need.
Did you know that when compiling the Sigma rules with `sigmac`, you can [filter rules](https://github.com/Neo23x0/sigma#usage) to match your use-cases through the `--filter` flag (shorthand `-f`)?

## Acknowledgements
Development of this project has been supported by [NVISO Labs](https://www.nviso.eu/en/research). Interested in this project? You might [fit with us](https://www.nviso.eu/en/jobs)!

Many thanks to [Florian Roth](https://twitter.com/Cyb3rOps) for his valuable feedback and without whom we wouldn't have [Sigma](https://github.com/Neo23x0/sigma) in the first place.

## License
&copy; Maxime Thiebaut, 2020 &mdash; [Licensed under the EUPL](./LICENSE.txt).
