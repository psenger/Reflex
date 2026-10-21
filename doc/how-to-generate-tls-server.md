# How to generate the TLS server credentials

Reflex refuses every connection until both ends hold certificates from the same private CA, and the server also needs a token for every client it will accept. This guide covers minting those files with `ib-certgen`, checking them, distributing them, and the operations `ib-certgen` does not do for you: adding a client later, rotating the server certificate, and revoking a client.

Every command below was run against the release binaries in this workspace. Output shown is real.

## What gets minted

One run of `ib-certgen` produces a complete, self-contained trust domain:

```mermaid
flowchart TB
    CA["ca.pem and ca.key<br/>CN=Reflex CA<br/>self-signed root"]
    S["server.pem and server.key<br/>CN=server<br/>EKU serverAuth<br/>SAN localhost, 127.0.0.1 plus --server-name"]
    A["laptop-a.pem and laptop-a.key<br/>CN=laptop-a<br/>EKU clientAuth"]
    B["laptop-b.pem and laptop-b.key<br/>CN=laptop-b<br/>EKU clientAuth"]
    T["tokens.txt<br/>laptop-a hex<br/>laptop-b hex"]
    TA["laptop-a.token"]
    TB["laptop-b.token"]
    CA -- signs --> S
    CA -- signs --> A
    CA -- signs --> B
    T -. same value .-> TA
    T -. same value .-> TB
```

The CA signs three kinds of leaf. The server pins `ca.pem` to verify clients, and every client pins the same `ca.pem` to verify the server. Nothing else is trusted: no system store, no public CA, no OCSP, no CRL.

| Property        | Value                                                             |
|-----------------|-------------------------------------------------------------------|
| Key algorithm   | ECDSA P-256 with SHA-256, for the CA and every leaf               |
| Key encoding    | PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`)                        |
| Validity        | 1975-01-01 to 4096-01-01, so clock skew and expiry never bite     |
| Chain length    | One step. Leaves are signed directly by the root.                 |
| Token           | 32 random bytes, written as 64 hex characters                     |
| File modes      | `0600` for every `.key`, `.token` and `tokens.txt`. `0644` for `.pem` |

## Prerequisites

- A release build. `ib-certgen` is built with the rest of the workspace.
- `openssl` on your path if you want to inspect the output or add certificates later. It is not needed to run Reflex.

```bash
cargo build --release
./target/release/ib-certgen --help
```

```text
Mint a CA, server certificate, and per-client certificates and tokens for Reflex

Usage: ib-certgen [OPTIONS] --client <CLIENTS>

Options:
      --out <OUT>                   Directory to write into. Created if missing [default: certs]
      --server-name <SERVER_NAMES>  Hostnames or IPs the server certificate is valid for. `localhost` and `127.0.0.1` are always included
      --client <CLIENTS>            Client ids to issue a certificate and token for. Repeat for each client
  -h, --help                        Print help
```

## Step 1: decide the server names

The client verifies the server certificate against a name. By default that name is the host part of the address it dials, so a client started with `ib-client 10.0.0.5:9001 ...` expects the certificate to be valid for `10.0.0.5`. The `--server-name` flag on `ib-client` overrides this, which is useful when clients dial through a port forward or a load balancer.

Collect every hostname and IP address any client will ever use to reach the server, and pass each one as `--server-name`. `localhost` and `127.0.0.1` are always included so local testing works without flags.

Rules:

- IP addresses become `IP Address` entries in the SAN. Hostnames become `DNS` entries. Pass them exactly as clients will dial them.
- There is no wildcard support in `ib-certgen`. List each name.
- Adding a name later means reissuing the server certificate. See [Rotate the server certificate](#rotate-the-server-certificate).

## Step 2: decide the client ids

Each `--client` value becomes a client id. The id must be non-empty and contain no whitespace. It is also used as a filename, so stick to letters, digits, `-` and `_`.

The id is the identity the server tracks sequence numbers under. It is what appears in the first column of the server's output. Choose something stable, like the machine's role or hostname.

## Step 3: run ib-certgen

A local test with one client:

```bash
./target/release/ib-certgen --out certs --client laptop-a
```

A deployment where the server is reached at `10.0.0.5` and `relay.example.internal`, with two clients:

```bash
./target/release/ib-certgen --out certs \
  --server-name 10.0.0.5 --server-name relay.example.internal \
  --client laptop-a --client laptop-b
```

```text
[certgen] wrote CA, server certificate and 2 client credential set(s) to certs
```

List every client in a single run. The reason is in [Rerunning ib-certgen](#rerunning-ib-certgen).

## Step 4: check what you got

```bash
ls -l certs
```

```text
-rw-------  ca.key
-rw-r--r--  ca.pem
-rw-------  laptop-a.key
-rw-r--r--  laptop-a.pem
-rw-------  laptop-a.token
-rw-------  laptop-b.key
-rw-r--r--  laptop-b.pem
-rw-------  laptop-b.token
-rw-------  server.key
-rw-r--r--  server.pem
-rw-------  tokens.txt
```

| File             | Purpose                                                                     |
|------------------|-----------------------------------------------------------------------------|
| `ca.pem`         | The root certificate. Both binaries take it as `--ca`.                      |
| `ca.key`         | The root private key. Used only to issue more certificates. Not used by Reflex at runtime. |
| `server.pem`     | Server leaf certificate. `ib-server --cert`.                                |
| `server.key`     | Server private key. `ib-server --key`.                                      |
| `<id>.pem`       | Client leaf certificate. `ib-client --cert`.                                |
| `<id>.key`       | Client private key. `ib-client --key`.                                      |
| `<id>.token`     | The client's copy of its token. `ib-client --token`.                        |
| `tokens.txt`     | Every client's token, one `client_id token` line each. `ib-server --tokens`. |

The CA:

```bash
openssl x509 -in certs/ca.pem -noout -subject -issuer -dates -ext basicConstraints,keyUsage
```

```text
subject=CN=Reflex CA
issuer=CN=Reflex CA
notBefore=Jan  1 00:00:00 1975 GMT
notAfter=Jan  1 00:00:00 4096 GMT
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
X509v3 Basic Constraints: critical
    CA:TRUE
```

The server certificate, showing the names it is valid for:

```bash
openssl x509 -in certs/server.pem -noout -subject -issuer -ext subjectAltName,extendedKeyUsage
```

```text
subject=CN=server
issuer=CN=Reflex CA
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1, IP Address:10.0.0.5, DNS:relay.example.internal
X509v3 Extended Key Usage:
    TLS Web Server Authentication
```

A client certificate has no SAN. Its identity comes from the token handshake, not the certificate:

```bash
openssl x509 -in certs/laptop-a.pem -noout -subject -issuer -ext extendedKeyUsage
```

```text
subject=CN=laptop-a
issuer=CN=Reflex CA
X509v3 Extended Key Usage:
    TLS Web Client Authentication
```

Confirm every leaf chains to the CA:

```bash
openssl verify -CAfile certs/ca.pem certs/server.pem certs/laptop-a.pem
```

```text
certs/server.pem: OK
certs/laptop-a.pem: OK
```

The token file:

```bash
cat certs/tokens.txt
```

```text
laptop-a 4f1c...dad2d196
laptop-b 9a07...3895d095
```

Blank lines and lines starting with `#` are ignored by `ib-server`. A duplicate id or a line without exactly two fields is a startup error.

## Step 5: distribute the files

Each host gets only what it needs. The CA private key goes nowhere that runs Reflex.

| File                                             | Server host | Client `laptop-a` | Client `laptop-b` | Offline store |
|--------------------------------------------------|-------------|-------------------|-------------------|---------------|
| `ca.pem`                                         | yes         | yes               | yes               | yes           |
| `ca.key`                                         | no          | no                | no                | yes           |
| `server.pem`, `server.key`                       | yes         | no                | no                | optional      |
| `tokens.txt`                                     | yes         | no                | no                | optional      |
| `laptop-a.pem`, `laptop-a.key`, `laptop-a.token` | no          | yes               | no                | optional      |
| `laptop-b.pem`, `laptop-b.key`, `laptop-b.token` | no          | no                | yes               | optional      |

Copy with something that preserves modes:

```bash
scp -p certs/ca.pem certs/server.pem certs/server.key certs/tokens.txt relay:/etc/reflex/
scp -p certs/ca.pem certs/laptop-a.pem certs/laptop-a.key certs/laptop-a.token laptop-a:/etc/reflex/
```

Then move `ca.key` somewhere offline and delete the local copy. Whoever holds `ca.key` can mint a credential the server will accept.

The workspace `.gitignore` already excludes `certs/`, `*.key`, `*.token` and `tokens.txt`.

## Step 6: start both ends

Server:

```bash
./target/release/ib-server 0.0.0.0:9001 \
  --cert /etc/reflex/server.pem --key /etc/reflex/server.key \
  --ca /etc/reflex/ca.pem --tokens /etc/reflex/tokens.txt
```

```text
[server] listening on 0.0.0.0:9001 (2 client tokens loaded)
```

Client, dialling a name that is in the server certificate's SAN:

```bash
./target/release/ib-client 10.0.0.5:9001 laptop-a \
  --cert /etc/reflex/laptop-a.pem --key /etc/reflex/laptop-a.key \
  --ca /etc/reflex/ca.pem --token /etc/reflex/laptop-a.token
```

```text
[client] id 'laptop-a' -> 10.0.0.5:9001
[client] connected
[client] authenticated (server has seq 0)
```

If the client dials an address that is not in the SAN, for instance through an SSH tunnel on `127.0.0.1:9001` to a server whose certificate only names `10.0.0.5`, pass `--server-name 10.0.0.5` so verification uses a name the certificate carries. `127.0.0.1` is always in the SAN, so this particular case works without the flag; the flag matters for any other forwarded address.

## Rerunning ib-certgen

Every run creates a new CA. There is no flag to reuse an existing `ca.key`.

Running `ib-certgen --out certs --client laptop-a` into a directory that already holds credentials does this:

| File                                  | Result                                                                 |
|---------------------------------------|------------------------------------------------------------------------|
| `ca.pem`, `ca.key`                    | Replaced with a new CA                                                 |
| `server.pem`, `server.key`            | Replaced, signed by the new CA                                         |
| `laptop-a.*`                          | Replaced, signed by the new CA, new token                              |
| `tokens.txt`                          | Replaced. Only contains `laptop-a`.                                    |
| `laptop-b.pem`, `.key`, `.token`      | Left on disk untouched. Signed by the old CA, token no longer on file. |

Nothing warns you. The stale `laptop-b` files look valid but fail at the TLS handshake with `BadSignature` on the server, and the token would be rejected even if the certificate passed.

Consequences:

- Treat a run of `ib-certgen` as "rebuild the whole trust domain". Pass every client, every time, and redistribute every file afterwards.
- To add one client, or reissue one certificate, without touching the others, use the openssl recipes below with the existing `ca.key`.
- Use a fresh `--out` directory rather than overwriting, so the old set survives until the new one is deployed.

## Add a client without rotating the CA

`ib-certgen` cannot do this. The recipe below uses the existing `ca.key` and produces files the binaries accept. It was tested end to end: a client issued this way authenticated and delivered events alongside clients from `ib-certgen`.

```bash
cd certs
id=laptop-c

# P-256 key, converted to PKCS#8 to match what ib-certgen writes
openssl ecparam -name prime256v1 -genkey -noout | openssl pkey -out "$id.key"
chmod 600 "$id.key"

# Certificate signing request. The CN is informational.
openssl req -new -key "$id.key" -subj "/CN=$id" -out "$id.csr"

# Sign with the CA. Set the validity you want; rustls rejects expired certificates.
printf 'extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n' > client.ext
openssl x509 -req -in "$id.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 825 -extfile client.ext -out "$id.pem"

# Token: 32 random bytes as hex, one copy for the client, one line for the server
tok=$(openssl rand -hex 32)
printf '%s' "$tok" > "$id.token"
chmod 600 "$id.token"
printf '%s %s\n' "$id" "$tok" >> tokens.txt

rm "$id.csr" client.ext
openssl verify -CAfile ca.pem "$id.pem"
```

Then copy `ca.pem`, `laptop-c.pem`, `laptop-c.key` and `laptop-c.token` to the new client, copy the updated `tokens.txt` to the server, and restart `ib-server`. Tokens are read once at startup.

`-CAcreateserial` writes a `ca.srl` file next to `ca.pem`. It is harmless and can stay or go.

## Rotate the server certificate

Use this to add a server name, or to replace a key you believe is compromised, without reissuing any client. Tested: existing clients connected to the rotated server without change.

```bash
cd certs

openssl ecparam -name prime256v1 -genkey -noout | openssl pkey -out server.key.new
chmod 600 server.key.new
openssl req -new -key server.key.new -subj "/CN=server" -out server.csr

# List every name clients dial. Keep localhost and 127.0.0.1 for local testing.
cat > server.ext <<'EXT'
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.0.0.5,DNS:relay.example.internal,DNS:relay2.example.internal
EXT

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 825 -extfile server.ext -out server.pem.new

openssl x509 -in server.pem.new -noout -ext subjectAltName
mv server.key.new server.key
mv server.pem.new server.pem
rm server.csr server.ext
```

Copy `server.pem` and `server.key` to the server host and restart `ib-server`. Clients reconnect with backoff and verify the new certificate against the same `ca.pem`.

## Revoke a client

There is no CRL. Two options:

1. **Remove the token.** Delete the client's line from `tokens.txt` and restart `ib-server`. The client's certificate still passes the TLS handshake, but the server then rejects it with `rejected unknown client`. This is the normal path.
2. **Reissue the CA.** Run `ib-certgen` again with every remaining client and redeploy everything. Use this if `ca.key` itself may have leaked.

## Troubleshooting

Each row was reproduced against the real binaries. The client exits with code 2 on anything it classifies as an authentication failure. Token rejections are the exception: the server simply closes the connection, so the client sees a disconnect and keeps retrying. Check the server's stderr for those.

| Symptom on the client                                                                                                  | Server stderr                                           | Cause                                                                 | Fix                                                                                              |
|------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|-----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `authentication failed, not retrying: TLS handshake: invalid peer certificate: BadSignature`, exit 2                   | `TLS handshake: received fatal alert: BadCertificate`   | The client's `--ca` is not the CA that signed the server certificate  | Copy the current `ca.pem` to the client                                                          |
| `authentication failed, not retrying: received fatal alert: DecryptError`, exit 2                                      | `TLS handshake: invalid peer certificate: BadSignature` | The client's certificate was signed by a different CA than the server's `--ca`. Usually a stale file from an earlier `ib-certgen` run. | Reissue the client against the current CA, or redeploy the whole set |
| `invalid peer certificate: certificate not valid for name "X"; certificate is only valid for ...`, exit 2              | `received fatal alert: BadCertificate`                  | The name the client dials, or `--server-name`, is not in the SAN      | Dial a listed name, pass `--server-name` with one, or rotate the server certificate with the extra name |
| `keys may not be consistent: KeyMismatch`, exit 1, before connecting                                                   | nothing, no connection made                             | `--cert` and `--key` are from different pairs                         | Use the matching `.pem` and `.key`                                                               |
| `disconnected (0 unacked ...); retrying in ...` in a loop                                                              | `rejected client 'X': token proof failed`               | `--token` does not match the server's line for that id                | Copy the current `.token`, or the current `tokens.txt` to the server, then restart the server    |
| `disconnected ...; retrying` in a loop                                                                                 | `rejected unknown client 'X'`                           | Id is not in `tokens.txt`                                             | Add the line and restart the server, or start the client with the right id                       |
| `ib-server` exits with `keys may not be consistent: KeyMismatch`                                                       |                                                         | `--cert` and `--key` are from different pairs                         | Use `server.pem` with `server.key`                                                               |
| `ib-server` exits with `no certificates in <path>`                                                                     |                                                         | A `.key` file was passed as `--cert` or `--ca`                        | Pass the `.pem`                                                                                  |
| `ib-server` exits with `<path>:<line>: expected client_id token`                                                       |                                                         | A line in `tokens.txt` does not have exactly two fields               | Fix the line. Comments start with `#`.                                                           |
| Anything that is not `ib-client` connects and is dropped                                                               | `TLS handshake: peer sent no certificates`              | The peer did not present a client certificate                         | Expected. The server requires mutual TLS.                                                        |

A quick external check that the server is up and demanding a client certificate, without any Reflex client:

```bash
echo | openssl s_client -connect 10.0.0.5:9001 -CAfile certs/ca.pem 2>&1 | grep -E 'Verification|alert'
```

```text
Verification: OK
... tlsv13 alert certificate required ...
```

`Verification: OK` means the server certificate chains to your CA and the name matches. The alert is the server refusing a peer with no certificate, which is correct.

## Security notes

- **`ca.key` is the whole trust domain.** Anyone holding it can mint a client the server accepts, or a server the clients accept. Keep it offline. Reflex never reads it.
- **Certificates do not carry identity.** The server does not read the CN of a client certificate. Identity is the `client_id` in the handshake plus the token for that id. Any certificate from the CA, together with `laptop-a`'s token, is `laptop-a`. This is why the token file and the `.token` files are secrets of the same weight as private keys.
- **No expiry from `ib-certgen`.** Certificates are valid until the year 4096. Rotation is a decision you make, not something the calendar forces. Certificates issued with the openssl recipes above expire after the `-days` value you choose, and rustls enforces that.
- **The end-to-end tests mint their own credentials** into a temporary directory on every run, so nothing in `certs/` is needed to run `cargo test`.
- **The server certificate file is the leaf only.** Do not append `ca.pem` to `server.pem`. The chain is one step and the clients already hold the root.
