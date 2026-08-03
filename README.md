![](./.github/banner.png)

<p align="center">
      A tool to create, enroll, attach, describe, list, find, extract, remove, and flush shadow credentials (msDS-KeyCredentialLink entries, their RSA key material, and device IDs) on Active Directory accounts over LDAP.
      <br>
      <a href="https://github.com/TheManticoreProject/manticore-keycredentials/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/manticore-keycredentials/actions/workflows/release.yaml/badge.svg"></a>
      <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TheManticoreProject/manticore-keycredentials">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/manticore-keycredentials">
      <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
      <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
      <br>
</p>

## Features

- [x] Create a certificate locally, saving its private key and certificate without touching Active Directory (`create`)
- [x] Create a certificate and attach it to one or more target objects as a key credential (`enroll`)
- [x] Attach an existing certificate, from a PFX or a PEM, to one or more target objects (`attach`)
- [x] Decode and display the key credentials of an object — key id, hash and its integrity, usage, source, device id, timestamps (`describe`)
- [x] List the raw key credential values across one or more objects, or the whole domain (`list`)
- [x] Find which objects a given certificate, private key or public key is set on (`find`)
- [x] Extract the public key of each certificate set on an object, to PEM or DER (`extract`)
- [x] Remove a specified certificate from one or more objects, matched by public key (`remove`)
- [x] Flush the whole `msDS-KeyCredentialLink` attribute of an object (`flush`)
- [x] Authenticate with a password (`-p`), a NT hash (`-H`), or an AES key (`--aes-key`), over LDAP or LDAPS (`-L`), with Kerberos (`-k`) or NTLM
- [ ] Authenticate with a keytab

## Installation

To get this tool you can either download the latest release from the [GitHub release page](https://github.com/TheManticoreProject/manticore-keycredentials/releases) or install it with the following `go` command:

```bash
go install github.com/TheManticoreProject/manticore-keycredentials@latest
```

## Usage

The first positional argument of the program is the mode. Running the tool with
no mode prints the list of available modes:

```
$ ./manticore-keycredentials
manticore-keycredentials - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: manticore-keycredentials <attach|create|describe|enroll|extract|find|flush|list|remove>

   attach    Attach an existing certificate to one or more target objects.
   create    Create a new certificate and save it locally (private key and certificate).
   describe  Display information about the KeyCredentialLink values of a target object.
   enroll    Create and attach a new certificate to one or more target objects.
   extract   Extract the public key of a certificate set on a target object.
   find      Find the objects configured with a given certificate or public key.
   flush     Flush the msDS-KeyCredentialLink attribute of a target object.
   list      List the raw msDS-KeyCredentialLink values of one or more target objects.
   remove    Remove a single specified certificate from one or more target objects.
```

Every mode that talks to the directory shares the same `Configuration`,
`LDAP Connection Settings`, `Authentication` and `Secret` groups. Exactly one of
the `Secret` options (`-p`, `-H`, `--aes-key`, `--ticket-ccache`,
`--ticket-kirbi`, or `--no-pass`) has to be given:

```
$ ./manticore-keycredentials describe -h
manticore-keycredentials - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: manticore-keycredentials describe --distinguished-name <string> [--domain <string>] [--username <string>] [--debug] [--dc-ip <string>] [--dc-host <string>] [--ldap-port <tcp port>] [--use-ldaps] [--use-kerberos] [--dns-name-server <string>] [--no-pass] [--password <string>] [--hashes <string>] [--aes-key <string>] [--ticket-ccache <string>] [--ticket-kirbi <string>]

  -D, --distinguished-name <string> Distinguished name of the target account.

  Authentication:
    -d, --domain <string>   Active Directory domain to authenticate to. (default: "")
    -u, --username <string> User to authenticate as. (default: "")

  Configuration:
    --debug         Debug mode. (default: false)

  LDAP Connection Settings:
    -dc, --dc-ip <string>       IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter. (default: "")
    --dc-host <string>          FQDN of the domain controller, used to build the Kerberos SPN when connecting by IP with -k. (default: "")
    -lp, --ldap-port <tcp port> Port number to connect to LDAP server. (default: 389)
    -L, --use-ldaps             Use LDAPS instead of LDAP. (default: false)
    -k, --use-kerberos          Use Kerberos instead of NTLM. (default: false)
    --dns-name-server <string>  DNS name server to use. (default: "")

  Secret:
    --no-pass                 Don't ask for password (useful for -k). (default: false)
    -p, --password <string>   Password to authenticate with. (default: "")
    -H, --hashes <string>     NT/LM hashes, format is LMhash:NThash. (default: "")
    --aes-key <string>        AES key to use for Kerberos Authentication (128 or 256 bits). (default: "")
    --ticket-ccache <string>  Path to a Kerberos credential cache (ccache) holding a TGT for pass-the-ticket (implies -k). (default: "")
    --ticket-kirbi <string>   Path to a .kirbi file holding a TGT for pass-the-ticket (implies -k). (default: "")
```

Omitting `-lp/--ldap-port` selects `389` for LDAP and `636` when `-L/--use-ldaps`
is set. An `--aes-key`, `--ticket-ccache` or `--ticket-kirbi` implies Kerberos, so
`-k` does not have to be given with any of them.

To pass the ticket, point `--ticket-ccache` at a Kerberos credential cache (FILE
format) or `--ticket-kirbi` at a `.kirbi` (DER `KRB-CRED`) file holding a TGT. The
principal is read from the ticket, so `-u/--username` is not required:

```
$ ./manticore-keycredentials list -L -dc 192.168.1.10 --dc-host dc1.corp.local -d CORP.local --ticket-ccache ./operator.ccache
```

With Kerberos (`-k`), the service ticket is requested for `ldap/<host>`, and Active
Directory only registers that SPN under the DC's FQDN. When connecting to the DC by
IP, give the FQDN with `--dc-host` so the SPN is correct while the connection and
the KDC exchanges still use the IP:

```
$ ./manticore-keycredentials list -L -k -dc 192.168.1.10 --dc-host dc1.corp.local -d CORP.local -u operator -p 'Passw0rd!'
```

### Certificates: create, enroll, attach

Three modes deal in certificates, split by where the key comes from:

- `create` generates one and writes its private key, certificate and a PFX to disk.
  It does **not** contact Active Directory.
- `enroll` generates one *and* attaches it to the target objects as a key
  credential, so it takes the LDAP, authentication, target and safety flags and a
  `KeyCredential` group for the fields of the credential. Each object gets its own
  certificate, whose subject is that object's `sAMAccountName`, and its own exported
  key.
- `attach` takes a certificate the caller already holds — a PFX (`--pfx`, with
  `--pfx-password`) or a PEM (`--pem`) — and attaches that same certificate to every
  target. Only the public key is needed, so a certificate, a private key or a public
  key are all usable PEM inputs.

```
$ ./manticore-keycredentials enroll -h
...
  Export certificate:
    --export-pem    Export the certificate in PEM format. (default: false)
    --export-pfx    Export the certificate in PFX format. (default: false)

  KeyCredential:
    --identifier <string>      Identifier of the KeyCredential. A fresh one is generated per object when omitted. (default: "")
    --creation-time <string>   Creation time of the KeyCredential. (default: "")
    --last-logon-time <string> Last logon time of the KeyCredential. (default: "")
    --not-before-time <string> Not before time of the certificate. (default: "")
    --not-after-time <string>  Not after time of the certificate. (default: "")
    --key-size <int>           Key size of the certificate. (default: 2048)
    --device-id <string>       Device ID of the KeyCredential. A fresh one is generated per object when omitted. (default: "")
```

Because `create` no longer touches the directory, the Active Directory flags it
used to accept are rejected with a pointer to `enroll`, rather than being silently
ignored:

```
$ ./manticore-keycredentials create -D 'CN=PC01,CN=Computers,DC=MANTICORE,DC=local' -dc 192.168.1.10 -u operator -p 'Passw0rd!'
[error] create no longer writes to Active Directory, it generates a certificate locally; the flag(s) -D, -dc, -u, -p belong to 'enroll', which creates and attaches a credential to a target object
```

### Targets and safety

`enroll`, `attach`, `list` and `remove` act on one or more objects, selected with
the same three flags (there is no repeatable flag, so a set of objects is named by
a filter or a file rather than by repeating `-D`):

- `-D, --distinguished-name` — a single object by its distinguished name.
- `-f, --filter` — every object matching an LDAP filter, e.g. `-f '(objectClass=computer)'`.
- `-tf, --targets-file` — every distinguished name listed in a file, one per line, `#` for comments.

Exactly one selector is required, except for `list`, which lists every object
holding a `msDS-KeyCredentialLink` when none is given.

The write modes (`enroll`, `attach`, `remove`) guard bulk changes:

- `--dry-run` resolves the targets and prints what would happen without writing.
- Acting on more than one object prompts for confirmation; `-y, --yes` skips the
  prompt for unattended use. A closed or non-interactive stdin counts as "no", so
  an unattended run cannot mass-modify by default.

A run reports success or failure per object and, if any object could not be
written, returns an error naming how many of how many failed.

### Finding where a certificate is planted

`find` works the other way round from the read modes: instead of naming an object
and showing its key credentials, it takes a key and reports which objects have it
set. A key credential stores only the public key, so a certificate, a private key
and a public key are all usable inputs — the public key is derived from whichever is
given:

```
$ ./manticore-keycredentials find --pem ./keys/target.cert.pem -d MANTICORE.local -u operator -p 'Passw0rd!' -dc 192.168.1.10
$ ./manticore-keycredentials find --pfx ./keys/target.pfx --pfx-password 'hunter2' -d MANTICORE.local -u operator -p 'Passw0rd!' -dc 192.168.1.10
```

The whole domain is searched by default; pass `-D` to check a single object. This is
the reverse lookup that answers "where else is this credential planted?", and it
pairs with [FindReusedKeyCredentials](https://github.com/TheManticoreProject/FindReusedKeyCredentials),
which finds keys shared between objects without needing the key up front.

## Output format

Results are printed using the shared TheManticoreProject convention: the `logger`
package, `[>] <Title> (<count>):` headers with the count in yellow, `├──`/`└──`
item trees, and inline ANSI escapes. `logger.Print` carries results, `logger.Info`
progress and write outcomes, and `logger.Debug` the extra detail enabled by
`--debug`.

`describe` decodes each value and renders its fields:

```
[>] KeyCredentialLink values of CN=PC01,CN=Computers,DC=MANTICORE,DC=local (1):
  └── [1] KeyID: CHY/ihRKUiKiqhAqE63DUKrKfxF/wwPpUnG5AbCMcMQ=
      ├── Version: KeyCredentialLink_v2
      ├── KeyHash: 71907a10...f1bf (valid)
      ├── KeySize: 2048 bits
      ├── Usage: New Generation Credential (NGC)
      ├── Source: Active Directory (AD)
      ├── DeviceId: 5e1476b0-9e15-5329-7816-0ee2b3c917ef
      ├── CreationTime (UTC): 2026-08-03 09:14:22
      └── LastLogonTime (UTC): 2026-08-03 09:14:22
```

`list` prints the raw attribute values, nesting each object's values under it so a
whole domain can be reviewed in one pass:

```
[>] Objects with a msDS-KeyCredentialLink (2):
  ├── CN=PC01,CN=Computers,DC=MANTICORE,DC=local
  │   └── B:828:00020000200001...:CN=PC01,CN=Computers,DC=MANTICORE,DC=local
  └── CN=PC02,CN=Computers,DC=MANTICORE,DC=local
      ├── B:828:0002000020000A...:CN=PC02,CN=Computers,DC=MANTICORE,DC=local
      └── B:828:0002000020000B...:CN=PC02,CN=Computers,DC=MANTICORE,DC=local
```

`find` reports the objects a key is set on, with the matched entry nested under
each:

```
[>] Objects with this key credential (2):
  ├── CN=PC01,CN=Computers,DC=MANTICORE,DC=local
  │   ├── DeviceId: 8f4c1d2e-9a3b-4c5d-8e7f-1a2b3c4d5e6f
  │   └── CreationTime (UTC): 2026-08-03 09:14:22
  └── CN=SRV02,CN=Computers,DC=MANTICORE,DC=local
      ├── DeviceId: 2b7e9f01-4c8a-4d3e-9f1b-6a5c4d3e2f10
      └── CreationTime (UTC): 2026-08-03 09:15:07
```

## Migration

The mode and flag layout was reworked. If you used an earlier build, the mapping is:

### Modes

| Was | Now | What changed |
|---|---|---|
| `add --value-to-add <b64>` | `enroll` | Renamed. `enroll` generates a certificate and attaches it; the raw pre-built `--value-to-add` input was removed. |
| `associate` | *(removed)* | Folded into `enroll`, which now targets one or more objects with `-f`/`-tf`. |
| `info` | `describe` | Renamed, and it now decodes each value instead of printing raw base64. |
| `create` (wrote to AD) | `create` (local only) | `create` now only writes a certificate to disk. Use `enroll` to attach one to an object; the AD flags on `create` are refused with a pointer to `enroll`. |
| `find` (showed one object) | `find` (reverse lookup) | `find` now takes a certificate or key (`--pfx`/`--pem`) and reports which objects hold it. To display one object's credentials, use `describe`. |
| `extract` (stub) | `extract` | Now exports the public key of each stored certificate to PEM (`--export-pem`, default) or DER (`--export-der`). The directory stores no private key or certificate, so only the public key can be recovered. |
| `remove --value-to-remove <b64>` | `remove --pfx`/`--pem` | Now identifies the credential by its certificate's public key instead of an exact attribute string. |

### Flags

| Was | Now |
|---|---|
| `-u`, `--user` | `-u`, `--username` |
| `--dc-ip` | `-dc`, `--dc-ip` |
| `--ldap-port` | `-lp`, `--ldap-port` (now range-checked as a TCP port) |
| `--use-ldaps` | `-L`, `--use-ldaps` |
| — | `-k`, `--use-kerberos` (new; `--aes-key` implies it) |
| — | `--dc-host` (new; FQDN for the Kerberos SPN when connecting by IP) |
| — | `--ticket-ccache` / `--ticket-kirbi` (new; pass-the-ticket from a ccache or .kirbi, both imply `-k`) |
| `--aes-key` (was refused) | `--aes-key` (now used for Kerberos authentication) |
| `attach --private-key`/`--public-key`/`--pfx-certificate` | `attach --pem`/`--pfx` |
| single `-D` on `enroll`/`attach`/`list`/`remove` | `-D` / `-f, --filter` / `-tf, --targets-file` |
| — | `--dry-run` and `-y, --yes` on `enroll`/`attach`/`remove` |

## Demonstration

<!-- TODO: Add a demonstration -->

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits
  - [Remi GASCOU (Podalirius)](https://github.com/p0dalirius) for the creation of the [manticore-keycredentials](https://github.com/TheManticoreProject/manticore-keycredentials) project.
