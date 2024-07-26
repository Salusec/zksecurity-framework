# ZK Security Framework
This framework focuses on the completeness, soundness, and zero-knowledge properties of ZKP to meticulously classify existing vulnerabilities and explores multiple categories of vulnerabilities, including completeness issues, soundness problems, information leakage, and non-standardized cryptographic implementations. Furthermore, we propose a set of defense strategies that include a rigorous security audit process and a robust distributed network security ecosystem. This audit strategy employs a divide-and-conquer approach, segmenting the project into different levels, from the application layer to the platform-nature infrastructure layer, using threat modelling, line-by-line audit, and internal cross-review, among other means, aimed at comprehensively identifying vulnerabilities in ZKP circuits, revealing design flaws in ZKP applications, and accurately identifying inaccuracies in the integration process of ZKP primitives.

## ZKP Security Risks Intro

### Risks Caused by Cryptography Basics
### Proof System Risks
### Vulnerabilities in the DSL Execution Layer
### Others (ZKVM, ZKEVM...)

## Vulnerability Classification  

### Risk Level Description

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

| NO.|  Risk level  | Vulnerability Name                             | Description                                                                                                                                                                                                            |
|:-------|:------------:|------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ZK-1&nbsp;&nbsp;|      🔴      | Under-constrained Circuits                     | Under-constrained circuits lack necessary constraints, allowing for exploits like using invalid values, and can lead to severe consequences.                                                               |
| ZK-2   |      🔴      | Nondeterministic Circuits                      | Nondeterministic circuits, a subset of under-constrained circuits, can allow multiple valid proofs for the same outcome, leading to vulnerabilities like double spending.                                              |
| ZK-3   |      🔴      | Arithmetic Over/Under Flows                    | In zk cryptography, modular arithmetic over a scalar field can cause unintended overflows and underflows if not properly checked, leading to vulnerabilities like an underflow in balance computation.                 |
| ZK-4   |      🔴      | Mismatching Bit Lengths                        | This vulnerability arises when inputs to CircomLib's LessThan circuit exceed the expected bit length, leading to incorrect outputs.                                                                                    |
| ZK-5   |      🔴      | Unused Public Inputs Optimized Out             | When public inputs without constraints are optimized out during compilation, allowing for the forging of evidence.                                                                                                     |
| ZK-6   |      🔴      | Frozen Heart: Forging of Zero Knowledge Proofs | If the zero-knowledge proof protocol is not secure, malicious provers can forge zk proofs that can pass verification, potentially proving anything they want, especially if the Fiat-Shamir transformation is insecure |
| ZK-7   |      🔴      | Trusted Setup Leak                             | When the 'toxic waste' in the trusted setup is exposed, this vulnerability arises, allowing for the forging of zk proofs.                                                                                              |
| ZK-8   |      🔴      | Assigned but not Constrained                   | This vulnerability arises when the commitments are mistakenly assumed to be constraints in the zk circuit, leading to insecure proofs.                                                                                 |
| ZK-9   |      🔴      | Missing Output Check Constraint                | For the outputs of component circuits,  the lack of secondary inspection leading to unexpected outputs like 0  being successfully verified                                                                             |
| ZK-10  |      🔴      | Missing Nullifier constrain                    | The vulnerability allows attackers to double spend by exploiting the lack of bit length checks on nullifiers, enabling multiple valid nullifiers for the same commitment due to overflow issues.                       |
| ZK-11  |      🔴      | 0 Bug                                          | This vulnerability allows attackers to forge a proof by setting specific elements to zero, which is misunderstood as an infinite point, leading to the proof being mistakenly accepted.                                |
| ZK-12  |      🔴      | Missing Blinding Factors                       | Due to the lack of blinding factors in the original Plonk implementation, private inputs can be extracted from the zero-knowledge proof.                                                                               |
| ZK-13  |      🔴      | Bad Polynomial Implementation                  | This is caused by the failure to trim trailing zero coefficients after arithmetic operations, leading to potential miscalculations or denial of service attacks through Rust panics.                                   |
| ZK-14  |      🔴      | Not an atomic operation                        | The vulnerability allows attackers to exploit concurrent operations caused by non-atomic updates, enabling unauthorized modifications to the state of the Merkle tree.                                                 |
| ZK-15  |      🟡      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-16  |      🟡      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-17  |      🟡      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-18  |      🟡      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-19  |      🟡      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-20  |      🟡      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-21  |      🔵      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-22  |      🔵      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-23  |      🔵      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-24  |      🔵      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-25  |      🔵      | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-26  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-27  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-28  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-29  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-30  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-31  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-32  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-33  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |
| ZK-34  |      ⚫       | ---                                            | ---                                                                                                                                                                                                                    |


## Learn Circom Auditing


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



