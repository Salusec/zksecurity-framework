[![ethereum](/pic/zketh.jpeg "ethereum")](#)
# ZK Security Framework
The ZK Security Framework is an evolving repository of ZKP security knowledge, built on the [ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker) and ["Zero-Knowledge Proof Vulnerability Analysis and Security Auditing"](https://eprint.iacr.org/2024/514). This framework focuses on the completeness, soundness, and zero-knowledge properties of ZKP, aiming to meticulously classify existing ZKP vulnerabilities and propose specific defense strategies and audit checklists. We also consider more circuit audit teaching work to enhance developers' understanding of specific security risks in ZKP.

### We are truly grateful to these sponsors; without your support, we would not be able to take this great first step.


## ZKP Security Risks Intro

### Completeness Issues --- Over-constrained Circuits

Excessive constraint in a circuit refers to adding additional constraints to a circuit that is already under normal constraints, which can result in the circuit failing to be successfully proved or verified. This issue may stem from the mechanism of the compiler itself. Taking circom and halo2 as examples, they establish constraints through assertions when compiling circuits. However, during the optimization process of compiling circuits, the compiler may introduce additional assertions, causing the inputs and outputs to not satisfy the current constraints during the proving process, leading to errors. Additionally, developers adding too many or repetitive constraints when designing circuits may also trigger such issues.

### Soundness Issues --- Under-constrained Circuits

The vulnerability of an incompletely constrained circuit refers to a situation in circuit design or programming implementation where some constraints are not set or set incompletely, leading to the circuit exhibiting unpredictable behavior or producing unexpected results. In certain cases, such incompletely constrained circuits may have serious consequences. For example, in the incremental Merkle tree implementation in ZK-kit smart contracts, the lack of range constraints on leaf node values allows malicious attackers to exploit this vulnerability to generate illegal zero-knowledge proofs, enabling them to carry out duplicate fund withdrawals.


### Information Leakage --- Trusted Setup Leak

In encryption protocols based on zero-knowledge proofs, the parameter generation process may expose some sensitive information, thereby compromising the security of the protocol. If a participant involved in generating the parameters retains some secret values, it is possible to use this information to forge valid proofs, deceiving other participants or stealing their assets.

### Arithmetic Over/Under Flows

In the field of zero-knowledge cryptography, modular arithmetic operations are common operations that are typically performed in scalar fields. However, due to the limitations of finite field orders, failure to handle overflow and underflow properly in arithmetic operations can lead to security risks.

## Unstandardized cryptographic implementation

### Forging of Zero Knowledge Proofs

If a zero-knowledge proof protocol has a security flaw, a malicious prover can construct a forged proof that passes verification. This forged proof can be used to "prove" any claim the prover desires, a security vulnerability referred to as the "Frozen Heart" bug by the TrailOfBits team.

The "Frozen Heart" bug is a severe security vulnerability that can jeopardize the correctness of various zero-knowledge proof systems, including PlonK and Bulletproofs. When such vulnerabilities affect a zero-knowledge proof system, protections for user privacy, data integrity, and transaction security are compromised. Many zero-knowledge proof protocols use the Fiat-Shamir transform to achieve non-interactive verification, which relies on the concept of a "random oracle model." However, as noted by TrailOfBits, the implementation of the Fiat-Shamir transform commonly encounters operational issues, primarily due to the lack of specific guidance on different protocol implementations. Typically, protocol design papers do not comprehensively include all essential details needed for coding practices, leading to defects and vulnerabilities in the implementation process. These vulnerabilities provide opportunities for attackers to exploit, enabling them to successfully forge proofs and undermine the correctness and security of zero-knowledge proof systems.

### Bad Randomness

At the core of zero-knowledge proofs is the ability to verify someone's knowledge or attributes without revealing any additional information, with randomness playing a crucial role. If a protocol uses an inappropriate source of randomness, attackers may have the opportunity to predict or infer the generated random numbers, rendering the interaction between the prover and verifier meaningless. If the proof system used by the prover has randomness vulnerabilities, sensitive information may be compromised. Similarly, if the random challenge issued by the verifier is singular or predictable, attackers can prepare fraudulent proofs in advance to deceive the verifier.

### Bad Polynomial Implementation

"Bad Polynomial Implementation" refers to implementation flaws that occur during the polynomial calculation process in zero-knowledge proof protocols. These flaws may stem from programming errors, incorrect algorithm choices, or a lack of understanding of mathematical properties. This issue can occur at critical junctures of zero-knowledge proof protocols, such as constructing polynomial commitments, performing polynomial evaluations, or verifying polynomial equations. Improper polynomial handling methods can result in inaccurate computation results or the inadvertent disclosure of originally confidential information, thereby compromising the security and effectiveness of zero-knowledge proofs.

### Deprecated Hash Function

The security and effectiveness of zero-knowledge proofs depend on the correct implementation and security of their cryptographic primitives (such as hash functions). With the advancement of computing power, some early hash functions like MD5, SHA-1, RIPEMD, RIPEMD-128, Whirlpool, etc., are no longer considered secure. Using these deprecated hash functions may make it easier for attackers to predict or uncover confidential information through brute force methods, compromising the fundamental properties of zero-knowledge proofs.


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

| NO.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; |  Risk level  | Vulnerability Name                             | Description                                                                                                                                                                           |
|:-------|:------------:|------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ZK-1   |      🔴      | Under-constrained Circuits                     | Under-constrained circuits lack necessary constraints, allowing for exploits like using invalid values, and can lead to severe consequences.                                                               |
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
| ZK-15  |      🟡      | ---                                            | ---                                                                                                                                                                                                                    |                                                                                                                                                                                                   |
| ZK-25  |      🔵      | ---                                            | ---                                                                                                                                                                                                                    |
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

### [Audit Report library](/zkreport/)





