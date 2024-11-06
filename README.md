
# ZK Security Framework
The ZK Security Framework is an evolving repository of ZKP security knowledge, built on the [ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker) and ["Zero-Knowledge Proof Vulnerability Analysis and Security Auditing"](https://eprint.iacr.org/2024/514). This framework focuses on the completeness, soundness, and zero-knowledge properties of ZKP, aiming to meticulously classify existing ZKP vulnerabilities and propose specific defense strategies and audit checklists. We also consider more circuit audit teaching work to enhance developers' understanding of specific security risks in ZKP.

### We are truly grateful to these sponsors; without your support, we would not be able to take this great first step.
[![ethereum](/pic/ethzk.jpeg "ethereum")](#)

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
| ZK-9   |      🔴      | Constraint Module Implementation Errors        | Basic constraint module errors, such as incorrect implementations of AND and XOR gates, may lead to deviations in the calculation logic of the entire circuit.                                                                                   |
| ZK-10  |      🔴      | Missing Nullifier constrain                    | The vulnerability allows attackers to double spend by exploiting the lack of bit length checks on nullifiers, enabling multiple valid nullifiers for the same commitment due to overflow issues.                       |
| ZK-11  |      🔴      | 0 Bug                                          | This vulnerability allows attackers to forge a proof by setting specific elements to zero, which is misunderstood as an infinite point, leading to the proof being mistakenly accepted.                                |
| ZK-12  |      🔴      | Missing Blinding Factors                       | The developer may have an incorrect understanding of the protocol, leading to the absence of Blinding Factors during the implementation or modification stages of the protocol, which could result in private inputs being inferred.                                                                              |
| ZK-13  |      🔴      | Bad Polynomial Implementation                  | It refers to errors in polynomial calculations within zero-knowledge proof protocols, typically caused by programming mistakes, unsuitable algorithms, or misinterpretations of mathematical principles. For example, a polynomial incorrectly containing trailing zero coefficients may trigger errors in certain polynomial-calling functions, leading to program panics or potential denial of service attacks.                                   |
| ZK-14  |      🔴      | Data are not fully verified during state update      | In decentralized systems like those using zk-SNARKs or other cryptographic proofs, state transitions should follow a strict set of rules to ensure that the new state is a legitimate result of the prior state and actions taken by users. If the system only partially verifies this transition, it could accept invalid or unauthorized state changes, leading to inconsistencies or potential exploits.                                                 |
| ZK-15  |      🔴      | Logic Flaws in Circuit Design      | These vulnerabilities stem from improper handling of mathematical operations, leading to unchecked or incorrectly constrained values. Such flaws can result in unexpected behavior, data integrity issues, and security risks, as the circuits fail to enforce necessary constraints on inputs and outputs, allowing potentially incorrect or manipulated results.                                                 |
| ZK-16  |      🔴      | Lack of Nullifier Length Check      | Some implementations do not verify that the nullifier's length is less than the field modulus. This oversight allows an attacker to manipulate the nullifier hash, potentially leading to double spending by passing the SNARK proof verification. Given the severity of the potential exploit, this vulnerability poses a significant risk to the integrity of the system.                                                 |
| ZK-17  |      🔴      | Unsafe Verifier      | In addition to circuit security, auditors should also consider potential security issues with the verifiers, such as overflow or underflow in variable calculations within on-chain verification contracts generated using DSL, or errors in the algorithm implementation of off-chain verifiers in ZKVM. An insecure verifier may lead to the rejection of an otherwise valid proof.                                                 |
| ZK-18  |      🔴      | Prover Can Lock User Funds      | Some circuits do not validate the format of the public keys, allowing a malicious prover to submit a malformed public key. This could prevent subsequent provers from generating valid proofs, effectively locking user funds and causing disruptions in the system's operation.                                                |
| ZK-19  |      🔴      | Circuit Does Not Check the ERC-20 Sum Correctly      | Some circuits only verify the total of ERC-20 tokens for the addresses specified in the input notes but fail to include other token addresses. This oversight could potentially allow a malicious actor to withdraw funds from the system without detection.                                                 |                               
| ZK-20  |      🟡      | Unintended Exposure of Private Inputs as Public Outputs      | Due to incorrect handling, private inputs are mistakenly revealed in the public reveal array when they fail to match a specified pattern. This error converts private data into public information, risking unintended data exposure. Proper management of input visibility, ensuring private data remains private regardless of matching results, is essential to maintain confidentiality.    |  
| ZK-21  |      🟡      | Exposure of Discrete Logarithm Relation in Hashing to the Curve      | The presence of predictable discrete logarithm relations between generated group elements implies that outputs are not truly independent, violating the BGM17 assumption of oracle output independence. If such relations are known, they compromise the security proof, undermining the protocol’s demonstrated security. To ensure secure hashing to elliptic curve groups, outputs must be independent and uniformly distributed, achievable through methods like hashing into separate coordinates or cofactor clearing.    | 
| ZK-22  |      🟡      | Insufficient Validation in Point Deserialization      | Failure to validate invalid bit patterns during point deserialization can lead to improperly decoded points, causing incorrect verifications and potential security risks. This issue is not unique to a specific curve (like BLS12-381) but can affect any cryptographic system that uses compressed point representations. Proper validation of point encoding is essential to avoid protocol inconsistencies and vulnerabilities across different cryptographic implementations.    | 
| ZK-23  |      🟡      | Uncaught Panics in Data Conversion Functions      | Data conversion functions, such as those converting hexadecimal or binary formats, can cause program crashes if the input is malformed and error handling is insufficient. Implementing rigorous checks for valid input format and length can prevent unexpected runtime errors and enhance stability.    | 
| ZK-24  |      🟡      | Dependence on User-Managed Data Validation      | This type of vulnerability arises when a system relies on external or user-provided validation for essential security checks rather than enforcing them internally. In this case, requiring users to ensure input constraints can lead to inconsistent data handling and increase the risk of misuse, especially if users overlook validation requirements.    | 
| ZK-25  |      🟡      | Proof Does Not Include FFT Generator in the Transcript      | According to the principles of the strong Fiat-Shamir transformation, the fft domain generator should be part of the initial Fiat-Shamir transcript. The omission of the fft domain generator from the initial Fiat-Shamir transcript presents a potential risk for malicious manipulation, although no specific attack vector was identified.    |   
| ZK-26  |      🟡      | Unbound Encrypted Outputs      | In some protocols, all transactions require users to submit additional data with off-chain ZKP proofs, including metadata and a calldata hash. While these inputs help prevent front-running, the unbound output could be exploited by an adversary creating a valid proof off-chain.    | 
| ZK-27  |      🟡      | Write a Proper Accompanying zk-SNARK Statement      | Some zk-SNARK circuits lack a detailed accompanying formal statement, which hinders thorough security analysis. Without this statement, the security properties and assumptions of the circuit may not be fully understood or evaluated, potentially leading to overlooked vulnerabilities.     |
| ZK-28  |      🔵      | Presence of Unused and Outdated Code Templates         | Certain templates lack sufficient documentation on the assumptions for input signals, meaning that developers may not be fully aware of the specific requirements or constraints for these inputs. Without clear guidance, developers might unintentionally provide inputs that do not meet the expected conditions, leading to incorrect calculations or unexpected system behavior.           | 
| ZK-29  |      🔵      | Missing Input Signal Documentation         | Certain templates lack sufficient documentation on the assumptions for input signals, meaning that developers may not be fully aware of the specific requirements or constraints for these inputs. Without clear guidance, developers might unintentionally provide inputs that do not meet the expected conditions, leading to incorrect calculations or unexpected system behavior.           |
| ZK-30  |      🔵      | Handling of Zero Values in Point Compression and Decompression         | In elliptic curve cryptography, handling zero values (identity elements) during point compression and decompression requires special attention. If zero values are not correctly supported, functions that involve mathematical operations like square roots, inversions, or other non-linear transformations can fail, potentially leading to runtime errors (e.g., panics in Rust) or incorrect proofs. This can occur when decoding points that represent the identity element, as they may not satisfy the expected properties of non-zero points. To ensure robustness, developers should add specific checks for zero inputs in compression and decompression functions, treating them in a way that avoids invalid operations.           |
| ZK-31  |      🔵      | Inappropriate error handling         | Direct panics in setup loading functions or initializing resources, such as cryptographic parameters or configuration files, can lead to unexpected application crashes.  Especially when this error occurs in the construction of protocols or circuits, it is even more catastrophic. Using error handling to propagate issues rather than causing panics provides better resilience.           |
| ZK-32  |      🔵      | Potentially Easy-to-Misuse Interface         | The application interface lacks input constraints, which could lead to user errors. While this may not present a direct security threat, it could affect the usability and stability of the system.           |
| ZK-33  |      🔵      | Vulnerability in MerkleRootCalculator         | Some circuits reconstruct the Merkle tree root but fails to properly validate membership, allowing attackers to generate valid Merkle proofs for non-member values. This occurs because the root hash does not encode the tree's height, enabling attackers to bypass checks and create invalid proofs, such as using zero inputs to prove membership of any intermediate node or the root.           |
| ZK-34  |      🔵      | Incorrect Polynomial Evaluation for Domain Shifts          | The function used to evaluate a polynomial at a given point fails to correctly initialize the FFT generator when the shift factor associated with the polynomial exceeds a certain threshold. This results in incorrect polynomial evaluations for larger domain shifts, potentially affecting the accuracy of computations in cryptographic protocols.           |
| ZK-35  |      🔵      | Operator Precedence Errors in Protocol and Merkle Tree Implementations         | Operator precedence errors can lead to critical issues in zero-knowledge protocol and Merkle tree implementations, where precise mathematical operations are essential. In protocol contexts, complex expressions involving bit shifts, arithmetic, and logical checks are commonly used for hash calculations, Merkle tree level checks, and constraint validations. Misinterpretation of operator precedence, such as missing parentheses around combined operations, can cause unintended behavior, potentially compromising proof validity, protocol security, or the integrity of tree structures. Attention to operator precedence is crucial to ensuring accurate calculations and maintaining security in ZK-based systems.           |
| ZK-36  |      🔵      | Conflicting Constraints in Circuit Configuration         | Conflicting constraints within circuit configuration functions may lead to conditions that are logically contradictory, preventing certain code paths from ever executing. Removing such dead code or constraints improves code readability and maintainability, especially in zero-knowledge proof circuits where each constraint impacts performance and clarity.           |
| ZK-37  |      ⚫       | Avoiding Redundant Constraints in Logical Operations   | In circuit implementations where inputs are guaranteed to be binary (0 or 1), using combined operation by Add(a, b) and Mul(a, b) instead of  logical operations can reduce unnecessary constraints. For example, functions like And(a, b) in gnark add additional checks to enforce that inputs are binary, which is redundant when the binary nature of inputs is already established. By substituting Mul for And in such cases, developers can optimize circuits by avoiding superfluous constraints, enhancing both efficiency and performance in zero-knowledge proofs.     |
| ZK-38  |      ⚫       | Lack of Descriptive Data Structures for Byte Field Representation   | IUsing raw byte sequences instead of structured data types can make the code harder to understand and audit, as the logical structure of data is not immediately clear. Leveraging more descriptive types, such as structs or arrays with constant generics, can improve code readability and make the handling of data more intuitive, reducing the risk of misinterpretation or errors.     |
| ZK-39  |      ⚫       | Use of Outdated Dependencies and Known Vulnerabilities   | Relying on outdated dependencies can expose a project to security vulnerabilities and stability issues, as older versions may contain known flaws that have been fixed in more recent releases. Regularly updating dependencies and running tools like cargo audit can help identify and address these vulnerabilities, ensuring the codebase remains secure and resilient against known attacks.     |
| ZK-40  |      ⚫       | Limited Error Detection with Random Values   | For unit testing, variables should primarily be tested using extreme values rather than random ones. In finite fields, the probability of selecting erroneous values is much lower than that of selecting correct values. Consequently, when random values are used in unit tests, they are more likely to fall within the correct range, making it difficult to identify actual errors. Using boundary or extreme values helps mitigate this issue and improves error detection.     |
| ZK-41  |      ⚫       | Inappropriate Handling of Random Oracle Zero Values   | In protocols that use random oracles to generate weights for batch verification, a zero value for the random oracle can cause all weighted terms to collapse, leading to a false positive in the verification process. This issue may arise in various cryptographic protocols, especially those involving pairing-based or zero-knowledge proofs where each proof component is multiplied by a random oracle.      |
| ZK-42  |      ⚫       | Unnecessary Complexity Circuit   | Some circuits, used for proofs related to staking, including deposit, stake, and unstake, have been identified as overly complex given its single instantiation.     |
| ZK-43  |      ⚫       | Inefficient Computation   | Some implementations contain unnecessary computations and redundant constraints, which increases computational overhead without providing additional functionality or security, potentially degrading system performance.     |


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





