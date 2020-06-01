# Sigma Importer
Sigma Importer (a.k.a. `sigmai`) is a project designed to do the opposite of [Sigma](https://github.com/Neo23x0/sigma).
The objective of `sigmai` is to convert specific data sources into the Sigma generic and open signature format.

## Installation
This project is written in Go.
The easiest way to install `sigmai` is to [get the release binaries](https://github.com/0xThiebaut/sigmai/releases).
Alternatively, one can [install the project from source](https://golang.org/cmd/go/) as would be done for any Go project. 

## Usage
For the generic usage's help section, `sigmai` is equipped with the `--help` flag (shorthand `-h`).

```bash
./sigmai --help
```

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

A sample `sigmai` command would be as follow:

```bash
./sigmai -t stdout -s misp --misp-url https://localhost --misp-key CAFEBABE== --misp-levels 1,2
```

The above command sends the Sigma rules to the `stdout` target (`-t`; more on that later).
The Sigma rules are to be generated from the `misp` source (`-s`).
In MISP, we'll solely generate Sigma rules for event's with a level (`--misp-levels`) of high (`1`) or medium (`2`).
For the eligible events, only attributes flagged for IDS (decent enough for detection) will be used.
Furthermore, any attribute on a [warning list](https://github.com/MISP/misp-warninglists) (a.k.a. subject to false positives) won't be included.

### Targets
A target is a way to select where to send the generated Sigma rules.

Defining the target can be done using the `--target` flag (shorthand `-t`).
Currently, both `stdout` and `directory` are implemented.

#### Stdout
This target outputs the generated Sigma rules to the [standard output](https://en.wikipedia.org/wiki/Stdout).
It can be selected by using `stdout` as the `--target` flag's value.

#### Directory
This target output's the generated Sigma rules into a directory, which defaults to the current one.
It can be selected by using `directory` as the `--target` flag's value.

Additionally, one may change the path using the `--directory-path` flag.

### Modifiers
The `sigmai` tool comes with some additional modifiers to ensure the generated rules meet your existing standard.
More specifically, one can modify the imported rule's tags by using the beneath flags.

| Flag            | Description                                                                               |
|-----------------|-------------------------------------------------------------------------------------------|
| `--tags-add`    | A flag with a comma-separated list of tags to be added to the current ones.               |
| `--tags-rm`     | A flag with a comma-separated list of tags to be removed if present in the current ones.  |
| `--tags-set`    | A flag with a comma-separated list of tags to overwrite the current ones.                 |
| `--tags-clear`  | A flag clearing all tags, resulting in tag-less rules.                                    |


### Continuous Importing
It is possible to run `sigmai` continuously a bit like a cron job would.
The `--interval` flag (shorthand `-i`) defines an interval at which an import should be done.

This flag can be combined with source's period-filters such as MISP's `--misp-period` flag.
As an example, the beneath command will import the last 15 minutes of MISP events as Sigma rules every 10 minutes.

```bash
./sigmai -t directory --directory-path ~/rules -i 10m -s misp --misp-url https://localhost --misp-key CAFEBABE== --misp-period 15m
``` 

## Acknowledgements
Development of this project has been supported by [NVISO Labs](https://www.nviso.eu/en/research). Interested in this project? You might [fit with us](https://www.nviso.eu/en/jobs)!

## License
&copy; Maxime Thiebaut, 2020 &mdash; [Licensed under the EUPL](./LICENSE.txt).
