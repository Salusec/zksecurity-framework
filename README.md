# ZK Security Framework
This framework focuses on the completeness, soundness, and zero-knowledge properties of ZKP to meticulously classify existing vulnerabilities and explores multiple categories of vulnerabilities, including completeness issues, soundness problems, information leakage, and non-standardized cryptographic implementations. Furthermore, we propose a set of defense strategies that include a rigorous security audit process and a robust distributed network security ecosystem. This audit strategy employs a divide-and-conquer approach, segmenting the project into different levels, from the application layer to the platform-nature infrastructure layer, using threat modelling, line-by-line audit, and internal cross-review, among other means, aimed at comprehensively identifying vulnerabilities in ZKP circuits, revealing design flaws in ZKP applications, and accurately identifying inaccuracies in the integration process of ZKP primitives.

## ZKP Security Risks Intro

### Risks Caused by Cryptography Basics
### Proof System Risks
### Vulnerabilities in the DSL Execution Layer
### Others (ZKVM, ZKEVM...)

## ZK Vulnerability Classification  

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

### 🔴 High   🟡 Medium   🔵 Low   ⚫ Info

| NO. |  Risk level   | Vulnerability Name | Description |
| --- | --- | --- | --- |
| ZK-1 | 🔴 | --- | --- |
| ZK-2 | 🔴 | --- | --- |
| ZK-3 | 🔴 | --- | --- |
| ZK-4 | 🔴 | --- | --- |
| ZK-5 | 🔴 | --- | --- |
| ZK-6 | 🟡 | --- | --- |
| ZK-7 | 🟡 | --- | --- |
| ZK-8 | 🟡 | --- | --- |
| ZK-9 | 🟡 | --- | --- |
| ZK-10 | 🟡 | --- | --- |
| ZK-11 | 🔵 | --- | --- |
| ZK-12 | 🔵 | --- | --- |
| ZK-13 | 🔵 | --- | --- |
| ZK-14 | 🔵 | --- | --- |
| ZK-15 | 🔵 | --- | --- |
| ZK-16 | ⚫ | --- | --- |
| ZK-17 | ⚫ | --- | --- |
| ZK-18 | ⚫ | --- | --- |
| ZK-19 | ⚫ | --- | --- |
| ZK-20 | ⚫ | --- | --- |
| ZK-21 | ⚫ | --- | --- |
| ZK-22 | ⚫ | --- | --- |
| ZK-23 | ⚫ | --- | --- |
| ZK-24 | ⚫ | --- | --- |


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



