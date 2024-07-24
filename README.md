# ZK Security Framework
Classification, rating, and security inspection framework for zero-knowledge proof vulnerabilities.



## ZKP Security Risks Intro

### 密码学基础风险
### 证明系统风险
### DSL执行层漏洞
### 其它项目（ZKVM、ZKEVM...）

## ZK Vulnerability Classification  

### Standard


### 🔴 High   🟡 Medium   🔵 Low   ⚫ Info

| NO. | Risk level | Vulnerability Name | Description |
| --- | --- | --- | --- |
| ZK-1 | 🔴 | --- | --- |
| ZK-1 | 🔴 | --- | --- |
| ZK-1 | 🔴 | --- | --- |
| ZK-1 | 🔴 | --- | --- |
| ZK-1 | 🔴 | --- | --- |
| --- | 🟡 | --- | --- |
| --- | 🟡 | --- | --- |
| --- | 🟡 | --- | --- |
| --- | 🟡 | --- | --- |
| --- | 🟡 | --- | --- |
| --- | 🔵 | --- | --- |
| --- | 🔵 | --- | --- |
| --- | 🔵 | --- | --- |
| --- | 🔵 | --- | --- |
| --- | 🔵 | --- | --- |
| --- | ⚫ | --- | --- |
| --- | ⚫ | --- | --- |
| --- | ⚫ | --- | --- |
| --- | ⚫ | --- | --- |
| --- | ⚫ | --- | --- |
| --- | ⚫ | --- | --- |
| --- | ⚫ | --- | --- |
| --- | ⚫ | --- | --- |
| --- | ⚫ | --- | --- |


## Learn Circuit Auditing


### Week 1

### Objectives:

Master Circom syntax

Familiarize with the Circom and Snarkjs development toolchain to write, test code, and generate target files

Learn to write Circom circuits using Tornado Cash as an example

### Study Tasks:

Read the [official documentation](https://docs.circom.io/) of the Circom circuit language

Read the [0xPARC Circom study section](https://learn.0xparc.org/)

Get familiar with the [circom](https://github.com/iden3/circom) + [snarkjs](https://github.com/iden3/snarkjs) toolchain and the online development platform [zkrepl](https://zkrepl.dev/) provided by iden3

Learn Circom circuit writing using [Tornado Cash](https://docs.tornadoeth.cash/tornado-cash-classic/circuits) as an example

Github: Deeply understand the principles of the [Tornado Cash project](https://github.com/tornadocash/tornado-core/tree/master/circuits)

Explore [other zk projects](https://github.com/arnaucube/awesome-circom) based on Circom, such as: [Dark Forest](https://github.com/darkforest-eth/circuits)  [Semaphore](https://github.com/semaphore-protocol/semaphore/tree/main/packages/circuits)

Extension: Understand the [application prospects](https://github.com/arnaucube/awesome-circom) of ZK technology in the web3 industry

### Week 2

### Objectives:

Understand the responsibilities of a zk audit engineer

Familiarize with common zk circuit vulnerabilities and proof system vulnerabilities

Learn to use auditing tools

### Study Tasks:

Read "[Security of ZKP projects: same but different](https://www.aumasson.jp/data/talks/zksec_zk7.pdf)"

Read the [0xPARC ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker/blob/main/README.md)

Read [audit reports](https://github.com/nullity00/zk-security-reviews),-currently focusing on Circom projects

Learn to use auditing tools like [PICUS](https://github.com/Veridise/Picus) and [CODA](https://github.com/Veridise/Coda)

### Week 3

### Objectives:

Further understand ZK security

### Study Tasks:

Learn through puzzles in [ZKHack](https://zkhack.dev/), which involve more proof systems such as STARK, not just limited to SNARK

### Learn through puzzles in ZKCTF:

[Ingonyama CTF](https://hackmd.io/@shuklaayush/SkWizdyBh)


### ZK Risk Level Description

<table>
  <tr>
    <td>Risk level</td>
    <td>Description</td>
  </tr>
  <tr>
    <td>High Risk</td>
    <td>The issue can lead to substantial financial, reputation, availability, or privacy damage.</td>
  </tr>
    <tr>
    <td>Medium Risk</td>
    <td>The issue can lead to moderate financial, reputation, availability, or privacy damage. Or the issue can lead to substantial damage under extreme and unlikely circumstances.</td>
  </tr>
    <tr>
    <td>Low Risk</td>
    <td>The issue does not pose an immediate security threat, but may be a lack of following best practices or more easily lead to the future introductions of bugs.</td>
  </tr>
    <tr>
    <td>Informational</td>
    <td>Information not relevant to security, but may be helpful for efficiency, costs, etc..</td>
  </tr>
</table>

### Circuit Check List

<table>
  <tr>
    <td>Classification</td>
    <td>Description</td>
  </tr>
  <tr>
    <td>Completeness Check</td>
    <td>Completeness Check</td>
  </tr>
    <tr>
    <td>Soundness Check</td>
    <td>Underconstrained input/output signal  |  Underconstrained component  |  Arithmetic operation correctness check  |  Bit length check(Range check) </td>
  </tr>
    <tr>
    <td>Knowledge Leakage</td>
    <td>Trusted Setup Leakage  |  Public information leakage privacy  </td>
  </tr>
    <tr>
    <td>Architeture Design</td>
    <td>E.g. H(x)=y with limited value of x</td>
  </tr>
</table>


## ZK Audit Database

### [Audit Report library](/report/)

### Literature Rack



