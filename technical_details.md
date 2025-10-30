# Technical Details

> Note: Many details described in this document are patented or patent-pending technology.

## BPF-Level Instrumentation

To make it easier to follow along, the first half of this _BPF-Level Instrumentation_ section of the document covers the
algorithms for instrumenting and capturing encrypted messages **after** TLS Server Name (hostname) filtering has taken
place. The second half of this section describes the hostname filtering that takes place when connections are
established, which is more involved and adds on top of concepts from the first section.

The examples cover two illustrative use cases:

- A program that links to OpenSSL's libssl.so shared library at runtime
- A Rust program that statically links Rustls encryption library code into the executable file

There are other libraries that could be linked as shared libraries in place of OpenSSL, but the general techniques
described below for instrumentation is the same. Examples include swapping OpenSSL for BoringSSL, GnuTLS, or AWS-LC
shared libraries.

Similarly, there are other runtimes and libraries that could statically be linked into programs, but the general
approach described below is the same. Examples include using the Ring library in a Rust program, GoTLS in a Go program,
or statically compiling OpenSSL (and similar) libraries into a program.

### Capturing Encrypted Messages

#### Shared Encryption Library Function Example

`SSL_write()` is a function available from the OpenSSL Project's `libssl` library. For this example we will assume there
is a client program written as a PHP application that links against the shared libssl.so library file at runtime.

The following sequence shows how the client process is instrumented so that when it prepares a request to be encrypted
and sent to a server, the instrumenation can capture the message. This sequence only covers how the instrumentation
captures data that will be encrypted for a request message, but the mechanism can be roughly reversed to capture the
response from the server after it has been decrypted.

The agent can continuously monitor and instrument new processes as they run on the system. When the PHP executable file
is loaded it only contains base PHP code. There is nothing to instrument yet. At some point, the PHP code will use the
shared library system to further load the `libssl.so` library file. This means simply watching processes start is not
enough to instrument them. We must wait until they have loaded a file with encryption code.

Every time a new executable file is loaded (mmap'ed) into memory, we need to check whether it has encryption library
code. To make sure we don't miss any messages, we use PTRACE to pause execution of the program while we check the loaded
file. While a small race condition window exists, most processes do not have time to instantiate encrypted channels
before the process is paused. In fact, the agent has a tiny POSIX thread dedicated just to receiving Mmap events and
immediately pausing processes to reduce this critical race condition window. Other agent threads are used to parse and
instrument executable files. Although parsing an executable file looking for encryption library code to instrument is
expensive, the BPF mmap probe maintains a [BPF Map](https://docs.kernel.org/bpf/maps.html) (i.e. an area of storage that
can be used by a BPF probe across invocations) of records of previously evaluated executable files so each file is only
ever parsed and instrumented once.

```mermaid
sequenceDiagram
  participant shell as CLI Shell
  participant client as Client Process<br/><br/>/usr/bin/client
  participant mmap as mmap() syscall
  participant tls as SSL_write()<br/><br/>in /usr/lib/libssl.so
  participant agent as Agent

  agent->>mmap: Install BPF fexit probe to be notified<br/>of all executable files mapped into memory

  shell->>+shell: A user starts the Client Process:<br/><br/>$> client

  shell->>-mmap: 1. Shell calls fork() and exec() to start Client Process<br/>2. mmap() is called to load libssl.so shared library<br/>executable code into memory

  activate mmap

  mmap->>mmap: BPF fexit probe checks mmap call is to load<br/>an executable file into memory.<br/><br/>BPF probe checks a BPF Map to see if this<br/>file has already been instrumented.<br/><br/>File has not been instrumented before.

  mmap->>-agent: BPF fexit probe emits MMAP_EXEC_FILE event with<br/>libssl.so file location (technically the file's inode)

  activate agent

  agent->>-client: Use PTRACE to pause execution of process

  activate agent
  agent->>agent: 1. Reads libssl.so file,<br/>2. Parses for known encryption library function symbols,<br/>3. Locates SSL_write() function address

  agent->>tls: Install BPF uprobe

  agent->>-client: Use PTRACE to resume execution of process

  client->>+client: Prepares an HTTPS request

  client->>-tls: Calls SSL_write() to encrypt<br/>a message to send to the server

  activate tls

  tls->>tls: BPF uprobe checks its connection Map<br/>to determine whether to capture this<br/>request.<br/><br/>This connection is in the Map.<br/>

  tls->>tls: BPF uprobe copies the request<br/>message given to SSL_write()<br/>in one of the function arguments

  tls->>-agent: BPF uprobe emits SSL_EVENT_TYPE_WRITE event<br/>with captured message data
```

#### Static Encryption Library Function Example

`EVP_AEAD_CTX_seal()` is a function in a publicly available
[FIPS](https://csrc.nist.rip/groups/STM/cmvp/validation.html) module library (e.g. from BoringSSL and AWS-LC FIPS
modules). In this example, a client process is written in Rust using the Rustls encryption library. Rustls is a wrapper
library making it easy to use FIPS modules within Rust applications. The client has Rustls and the FIPS module
statically linked into its executable code file.

The only difference is that in this instance the encryption code is statically linked into the program executable file,
so the function is found in the initial program file load rather than a later load of a separate shared library file.

```mermaid
sequenceDiagram
  participant shell as CLI Shell
  participant client as Client Process<br/><br/>/usr/bin/client
  participant mmap as mmap() syscall
  participant tls as EVP_AEAD_CTX_seal()<br/><br/>statically linked in /usr/bin/client
  participant agent as Agent

  agent->>mmap: Install BPF fexit probe to be notified<br/>of all executable files mapped into memory

  shell->>+shell: A user starts the Client Process:<br/><br/>$> client

  shell->>-mmap: 1. Calls fork() and exec() to start Client Process<br/>2. mmap() loads /usr/bin/client<br/>executable code into memory

  activate mmap

  mmap->>mmap: BPF fexit probe checks mmap call is to load<br/>an executable file into memory.<br/><br/>BPF probe checks a BPF Map to see if this<br/>file has already been instrumented.<br/><br/>File has not been instrumented before.

  mmap->>-agent: BPF fexit probe emits MMAP_EXEC_FILE event with<br/>/usr/bin/client file location (technically the file's inode)

  activate agent

  agent->>-client: Use PTRACE to pause execution of process

  activate agent
  agent->>agent: 1. Reads /usr/bin/client,<br/>2. Parses for known encryption library function symbols,<br/>3. Locates EVP_AEAD_CTX_seal() function address

  agent->>tls: Install BPF uprobe

  agent->>-client: Use PTRACE to resume execution of process

  client->>+client: Prepares an HTTPS request

  client->>-tls: Calls EVP_AEAD_CTX_seal() to encrypt<br/>a message to send to the server

  activate tls

  tls->>tls: BPF uprobe checks its encryption key<br/>context Map to determine whether to <br/>capture this request<br/>.<br/><br/>This encryption key context is in the Map.

  tls->>tls: BPF uprobe copies the request<br/>message given to EVP_AEAD_CTX_seal()<br/>in one of the function arguments

  tls->>-agent: BPF uprobe emits SSL_EVENT_TYPE_WRITE event<br/>with captured message data
```

<div style="page-break-after: always;" />

<div id="filtering-captures-based-on-tls-server-name" style="display: inline" />

### Filtering Captures Based On TLS Server Name

If we captured all encrypted traffic on a server via BPF and sent it to the _Agent_ we would likely overload the
utilization of the server. This instrumentation system has multiple layers of filtering to prevent an overload of
utilization from happening. The following sequences show how this filtering occurs for a few different types of
encryption libraries.

In the following cases we are the client which is establishing a new TLS encrypted channel to a server. The client
application sets the expected server name (e.g. `api.acme.com`) in a TLS Server Name Indication (SNI) extension of the
TLS Client Hello message when establishing the new encrypted channel. The server then uses the server name to route
messages and respond with a matching SSL certificate (e.g. it might use the `*.acme.com` certificate if the client
begins an encrypted channel for `api.acme.com`).

#### OpenSSL / libssl.so as a Shared Library

When connecting to a server via OpenSSL the client application calls `SSL_ctrl()` to set the server name.

This sequence begins by observing and instrumenting encryption functions as executable code is loaded.

```mermaid
sequenceDiagram
  participant shell as CLI Shell
  participant client as Client Process<br/><br/>/usr/bin/client
  participant mmap as mmap() syscall
  participant tls as SSL_ctrl()<br/><br/>in /usr/lib/libssl.so
  participant agent as Agent

  agent->>mmap: Install BPF fexit probe to be notified<br/>of all executable files mapped into memory

  shell->>+shell: A user starts the Client Process:<br/><br/>$> client

  shell->>-mmap: 1. Shell calls fork() and exec() to start Client Process<br/>2. mmap() loads libssl.so shared library<br/>executable code into memory

  activate mmap

  mmap->>mmap: BPF fexit probe checks mmap call is to load<br/>an executable file into memory.<br/><br/>BPF probe checks a BPF Map to see if this<br/>file has already been instrumented.<br/><br/>File has not been instrumented before.

  mmap->>-agent: BPF fexit probe emits MMAP_EXEC_FILE event with<br/>libssl.so file location (technically the file's inode)

  activate agent

  agent->>client: Use PTRACE to pause execution of process

  agent->>agent: 1. Reads libssl.so file,<br/>2. Parses for known encryption library function symbols,<br/>3. Locates SSL_ctrl() function address

  agent->>tls: Install BPF uprobe

  agent->>-client: Use PTRACE to resume execution of process

  client->>+client: Prepares an HTTPS request<br/>for api.acme.com

  client->>-tls: Calls SSL_ctrl() to set the<br/>server name to api.acme.com

  activate tls

  tls->>tls: BPF uprobe checks this SSL_ctrl() invocation is to<br/>set the server name, then copies<br/>the name into a BPF program buffer.<br/>A string suffix filter, and optionally<br/>a prefix filter, is used to efficiently<br/>check whether to capture messages in this channel.<br/><br/>api.acme.com matches a filter.<br/><br>An entry is saved in an internal<br/>BPF Map to mark that messages from this<br/> connection in this Client Process (PID) should be captured.

  tls->>-agent: The server name matches a filter.<br/>The BPF uprobe emits SNI_CONFIGURED<br/>event with server name api.acme.com.

  activate agent

  agent->>-agent: Records that messages from<br/>this channel are for api.acme.com
```

#### Rust Application Using Statically Linked Rustls Library

When connecting to a server via Rustls the client application calls Rustls functions to set the server name. Rustls uses
a FIPS module library to perform encryption. Unfortunately, Rust does not have a stable ABI, meaning that although we
can get the addresses of Rustls functions and attach to them, we don't know at runtime how arguments are passed (i.e.
which register or stack position they are at). Instead, we attach probes to TCP sendmsg and recvmsg syscalls to parse
TLS Hello messages and to the FIPS module library symbols that perform the raw encryption/decryption of data.

This sequence begins by observing and instrumenting encryption functions as executable code is loaded. Then:

1. We parse TLS headers in BPF code to capture the hostname
2. We use multiple pieces of contextual information (Process / Thread IDs, Socket File Descriptors, and Encryption Keys
   / Key Contexts) to track the encryption channels across TCP syscalls and encryption library calls

The encryption key context values that are tracked vary by encryption library. In some cases the key context can be the
address of a structure in memory that contains data about the key used for the channel. In other cases (e.g. the Rust
Ring library), the key context can be the value of the first X-bytes of the pseudo-random key material (e.g. the first
8-bytes of key material), which should have sufficient entropy to practically guarantee the ability to map from the key
context value to the TLS connection it is used for to encrypt or decrypt messages.

By analyzing encryption library code we can determine the order of thread execution and syscall / library function
calls. We have determined through this analysis that calls into the FIPS module to create encryption key contexts are
performed on the same process thread immediately after TLS Server Hello messages are received. Thus, we can capture and
record that a given key context maps to a given TLS connection.

```mermaid
sequenceDiagram
  participant shell as CLI Shell
  participant client as Client Process<br/><br/>/usr/bin/client
  participant mmap as mmap() syscall
  participant sendmsg as tcp_sendmsg() syscall
  participant recvmsg as tcp_recvmsg() syscall
  participant key as EVP_AEAD_CTX_init_with_direction()<br/><br/>statically linked in /usr/bin/client
  participant agent as Agent

  agent->>mmap: Install BPF fexit probe to be notified<br/>of all executable files mapped into memory

  shell->>+shell: A user starts the Client Process:<br/><br/>$> client

  shell->>-mmap: 1. Shell calls fork() and exec() to start Client Process<br/>2. mmap() loads /usr/bin/client<br/>executable code into memory

  activate mmap

  mmap->>mmap: BPF fexit probe checks mmap call is to load<br/>an executable file into memory.<br/><br/>BPF probe checks a BPF Map to see if this<br/>file has already been instrumented.<br/><br/>File has not been instrumented before.

  mmap->>-agent: BPF fexit probe emits MMAP_EXEC_FILE event with<br/>/usr/bin/client file location (technically the file's inode)

  activate agent

  agent->>client: Use PTRACE to pause execution of process

  agent->>agent: 1. Reads /usr/bin/client file,<br/>2. Parses for known encryption library function symbols,<br/>3. Notices Rustls function address

  agent->>sendmsg: Install BPF fexit probe.<br/>Set BPF Map record to watch for new<br/>TCP connections from Client Process PID.

  agent->>recvmsg: Install BPF fexit probe.

  agent->>key: Install BPF uprobe

  agent->>-client: Use PTRACE to resume execution of process

  client->>+client: Creates TCP connection to api.acme.com.<br/>Calls Rustls api to establish TLS connection.

  client->>-sendmsg: Rustls calls send() to send TLS Client Hello message.

  activate sendmsg

  sendmsg->>sendmsg: BPF probe checks PID is being<br/>monitored for new TCP connections.<br/><br/>BPF probe captures first message on new socket.<br/>The message is parsed for TLS Client Hello headers.<br/>The SNI header is found for api.acme.com.<br/>A string suffix filter, and optionally<br/>a prefix filter, is used to efficiently<br/>check whether to capture messages in this channel.<br/><br/>api.acme.com matches a filter.<br/><br>An entry is saved in an internal<br/>BPF Map to mark that the next message from this<br/> connection in this Client Process (PID) and for the<br/>same socket FD should be checked for<br/>TLS Server Hello.

  sendmsg->>-agent: The BPF probe emits SNI_SENT<br/>event with server name api.acme.com.

  activate agent

  agent->>-agent: Records that messages from<br/>this channel are for api.acme.com

  client->>+recvmsg: Client process waits (within Rustls library) for TLS Server Hello response

  recvmsg->>-recvmsg: Server responds with TLS Server Hello.<br/>BPF probe checks this connection is<br/>waiting to see TLS Server Hello.<br/><br/>BPF probe validates successful TLS connection<br/>establishment.<br/><br/>An entry is saved in an internal<br/>BPF Map to mark that the next<br/>encryption key contexts created by this<br/>process thread should be captured.

  recvmsg->>client: TLS Server Hello message given back to Rustls library / Client.

  client->>+key: Client (via Rustls) calls EVP_AEAD_CTX_init_with_direction_entry to create encryption key context

  key->>-key: BPF probe records mapping of key context<br/>to api.acme.com TLS channel into BPF Map.
```
