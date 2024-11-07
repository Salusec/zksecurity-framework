
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


## Learn Zero Knowledge Proof

### Stage 1: **Mathematical and Computational Foundations**

#### Objectives:

- Build essential foundational knowledge in mathematics and cryptography needed to understand zero-knowledge proofs.
- Gain familiarity with fundamental cryptographic concepts and complexity theory relevant to ZKP.

#### Study Tasks and Resources:

1. **Basic Linear Algebra**:
   - **Topics**: Matrix operations, vector spaces, linear transformations.
   - **Resources**: 
     - [The-Art-of-Linear-Algebra](https://github.com/kenjihiranabe/The-Art-of-Linear-Algebra])
     - [MIT 18.06SC Linear Algebra, Fall 2011](https://www.youtube.com/watch?v=7UJ4CFRGd-U&list=PL221E2BBF13BECF6C)
2. **Basic Probability**:
   - **Topics**: Basic probability distributions, random variables, conditional probability.
   - **Resources**:
     - [Probability](https://github.com/DataForScience/Probability)
     - [Seeing-Theory](https://github.com/seeingtheory/Seeing-Theory)
     - [Probability_Theory](https://github.com/weijie-chen/Probability_Theory)
     - [MIT RES.6-012 Introduction to Probability, Spring 2018](https://www.youtube.com/watch?v=1uW3qMFA9Ho&list=PLUl4u3cNGP60hI9ATjSFgLZpbNJ7myAg6)
3. **Basic Cryptography Concepts**:
   - **Topics**: Symmetric and asymmetric encryption (RSA), hash functions, digital signatures.
   - **Resources**:
     - [Introduction to Modern Cryptography, Second Edition](https://eclass.uniwa.gr/modules/document/file.php/CSCYB105/Reading%20Material/[Jonathan_Katz,_Yehuda_Lindell]_Introduction_to_Mo(2nd).pdf)
     - [A Graduate Course in Applied Cryptography](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf)
     - [Cryptography I](https://www.youtube.com/watch?v=1bSjcU2GeG0&list=PL58C6Q25sEEHXvACYxiav_lC2DqSlC7Og)
4. **Basic Computational Complexity**:
   - **Topics**: Complexity classes (P, NP), algorithmic complexity basics.
   - **Resources**:
     - [Computational Complexity: A Modern Approach](https://theory.cs.princeton.edu/complexity/book.pdf)
     - [Introduction To The Theory Of Computation](https://fuuu.be/polytech/INFOF408/Introduction-To-The-Theory-Of-Computation-Michael-Sipser.pdf)
     - [MIT 18.404J Theory of Computation, Fall 2020](https://www.youtube.com/watch?v=9syvZr-9xwk&list=PLUl4u3cNGP60_JNv2MmK3wkOt9syvfQWY)

------

### Stage 2: **Introduction to Zero-Knowledge Proofs**

#### Objectives:

- Grasp the foundational concepts and properties of zero-knowledge proofs.
- Understand interactive and non-interactive ZKP models, and study basic protocols.

#### Study Tasks and Resources:

1. **Zero-Knowledge Proof Basics**:
   - **Topics**: Definitions, properties (completeness, soundness, zero-knowledge).
   - **Resources**:
     - [Zero Knowledge for Dummies: Introduction to ZK Proofs](https://medium.com/veridise/zero-knowledge-for-dummies-introduction-to-zk-proofs-29e3fe9604f1)
     - [Zero Knowledge Proofs: An illustrated primer](https://blog.cryptographyengineering.com/2014/11/27/zero-knowledge-proofs-illustrated-primer/)
     - [On Interactive Proofs and Zero-Knowledge: A Primer](https://medium.com/magicofc/interactive-proofs-and-zero-knowledge-b32f6c8d66c3)
     - [A guide to Zero Knowledge Proofs](https://medium.com/@Luca_Franceschini/a-guide-to-zero-knowledge-proofs-f2ff9e5959a8)
     - [Introduction to Zero Knowledge - Alon Rosen](https://www.youtube.com/watch?v=6uGimDYZPMw)
     - [Knowledge Complexity of Interactive Proof Systems](https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Proof%20Systems/The_Knowledge_Complexity_Of_Interactive_Proof_Systems.pdf)
     - [How to prove all NP-statements in zero-knowledge, and a methodology of cryptographic protocol design](https://link.springer.com/chapter/10.1007/3-540-47721-7_11)
     - [On Defining Proofs of Knowledge](https://www.wisdom.weizmann.ac.il/~oded/PSX/pok.pdf)
     - [The  9th BIU Winter School on Cryptography - Zero Knowledge](https://www.youtube.com/playlist?list=PL8Vt-7cSFnw29cLUVqAIuMlg1QJ-szV0K)
     - [ZK-Learning](https://zk-learning.org/)
2. **Interactive Zero-Knowledge Proofs**:
   - **Topics**: Structure of interactive proofs, challenge-response protocols.
   - **Resources**:
     - [Zero Knowledge Proof: Interactive vs. Non-Interactive](https://nfting.medium.com/zero-knowledge-proof-interactive-vs-non-interactive-a8ba6e2cd7c7)
     - [Introduction to Interactive Zero-Knowledge Proofs](https://blog.chain.link/interactive-zero-knowledge-proofs/)
     - [Interactive Proofs and Zero-Knowledge](https://crypto.stanford.edu/cs355/18sp/lec3.pdf)
     - [Interactive Proofs and the Sum-Check Protocol](https://theory.cs.princeton.edu/complexity/book.pdf)
     - [Interactive Proofs (Part I)](https://www.youtube.com/watch?v=2XrOdfYviwA&t=2s)
     - [Interactive Proofs (Part II)](https://www.youtube.com/watch?v=w-6R3TxJ5dw)
3. **Non-Interactive Zero-Knowledge Proofs (NIZK)**:
   - **Topics**: Non-interactive proofs, Fiat-Shamir heuristic.
   - **Resources**:
     - [The Fiat-Shamir Transformation](https://www.comp.nus.edu.sg/~prashant/teaching/CS6230/files/notes/lecture11.pdf)
     - [How To Prove Yourself: Practical Solutions to Identification and Signature Problems](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)
     - [Jens Groth: Introduction to ZK and Foundations of NIZK Arguments](https://www.youtube.com/watch?v=CJBmuYd4U6g)
4. **Example Protocols**:
   - **Topics**: Concrete examples like the "Ali Baba Cave" and Graph Isomorphism problem.
   - **Resources**:
     - [Zero-knowledge proofs explained in 3 examples](https://www.circularise.com/blogs/zero-knowledge-proofs-explained-in-3-examples)
     - [Understanding Zero-knowledge proofs through illustrated examples](https://blog.goodaudience.com/understanding-zero-knowledge-proofs-through-simple-examples-df673f796d99)
     - [Demonstration of Zero-Knowledge Proof for Sudoku Using Standard Playing Cards](https://www.wisdom.weizmann.ac.il/~naor/PAPERS/SUDOKU_DEMO/)
     - [Zero knowledge proofs: a tale of two friends](https://medium.com/hackernoon/zero-knowledge-proofs-a-tale-of-two-friends-d7a0ffac3185)

------

### Stage 3: **Advanced Zero-Knowledge Proofs**

#### Objectives:

- Explore advanced ZKP protocols such as zk-SNARKs and zk-STARKs.
- Understand real-world applications of ZKPs in blockchain, secure multi-party computation, and privacy-preserving technologies.
- Learn about the latest trends in ZKP research and their future implications.

#### Study Tasks and Resources:

1. **Sigma Protocols**:
   - **Topics**: Sigma protocols and their structure, interactive and non-interactive forms.
   - **Resources**:
     - [On Σ-protocols](https://www.cs.au.dk/~ivan/Sigma.pdf)
     - [Sigma Protocols, Secret Sharing](https://crypto.stanford.edu/cs355/19sp/lec6.pdf)
     - [Zero Knowledge Proofs with Sigma Protocols](https://medium.com/@loveshharchandani/zero-knowledge-proofs-with-sigma-protocols-91e94858a1fb)
     - [Zero-Knowledge Proof - Cryptographic Primitives and Sigma Protocol](https://www.byont.io/blog/zero-knowledge-proof-cryptographic-primitives-and-sigma-protocol)
2. **zk-SNARKs and zk-STARKs**:
   - **Topics**: Concepts of zk-SNARKs (Succinct Non-Interactive Argument of Knowledge) and zk-STARKs (Scalable Transparent Argument of Knowledge).
   - **Resources**:
     - zk-SNARKs
       - [What are zk-SNARKs (Zcash blog)](https://z.cash/technology/zksnarks)
       - [Introduction to zk-SNARKs with examples](https://consensys.io/blog/introduction-to-zk-snarks)
       - [BabySNARK- The simplest possible SNARK for NP. You know, for kids!](https://github.com/initc3/babySNARK)
       - [The MoonMath Manual to zk-SNARKs (A free learning resource for beginners to experts)](https://leastauthority.com/community-matters/moonmath-manual/)
       - [zk-SNARKs: A Gentle Introduction](https://www.di.ens.fr/~nitulesc/files/Survey-SNARKs.pdf)
       - [Overview of Modern SNARK Constructions ](https://youtu.be/bGEXYpt3sj0)
       - [Understanding PLONK](https://vitalik.eth.limo/general/2019/09/22/plonk.html)
       - [Groth16 Explained](https://www.rareskills.io/post/groth16)
       - [Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS - Pratyush Mishra](https://www.youtube.com/watch?v=bJDLf8KLdL0)
       - [Sonic: Zero-Knowledge SNARKs from Linear-Size Universal and Updateable Structured Reference Strings](https://eprint.iacr.org/2019/099)
       - [Doubly-efficient zkSNARKs without trusted setup](https://eprint.iacr.org/2017/1132.pdf)
       - [Spartan: Efficient and general-purpose zkSNARKs without trusted setup](https://eprint.iacr.org/2019/550)
       - [Libra: Succinct Zero-Knowledge Proofs with Optimal Prover Computation](https://eprint.iacr.org/2019/317)
       - [HyperPlonk: Plonk with Linear-Time Prover and High-Degree Custom Gates](https://eprint.iacr.org/2022/1355)
       - [Bulletproofs: Short Proofs for Confidential Transactions and More](https://eprint.iacr.org/2017/1066.pdf)
     - zk-STARKs
       - [Introduction to ZK-STARKs](https://hackmd.io/@_33nsoRFQwGYh2T1-T9lqQ/rJHYnQ3Z4?type=view)
       - [STARK 101](https://starkware.co/stark-101/)
       - [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/)
       - [STARK Math: The Journey Begins](https://medium.com/starkware/stark-math-the-journey-begins-51bd2b063c71)
       - [Zero-Knowledge Proof Algorithm: ZK-Stark-FRI Protocol](https://hackernoon.com/zero-knowledge-proof-algorithm-zk-stark-fri-protocol)
       - [Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046.pdf)
3. **Applications in Blockchain**:
   - **Topics**: zk-SNARKs in Zcash, zk-rollups in Ethereum.
   - **Resources**:
     - [SNARK-based permissioned database: rollup by BarryWhitehat](https://github.com/barryWhiteHat/roll_up)
     - [zkPoD: A Practical Decentralized System for Data Exchange](https://github.com/sec-bit/zkPoD-node)
     - [Dark Forest: zkSNARK space warfare strategy game](https://zkga.me/)
     - [Overview of ZKP Applications & zkRollup and zkEVM](https://youtu.be/vuQGdbpDWcs)
5. **Practical Implementation**:
   - **Topics**: Implementation of ZKPs with popular libraries like ZoKrates, libsnark.
   - **Resources**:
     - [libsnark tutorial](https://github.com/coder5876/libsnark-tutorial)
     - [circom tutorial](https://github.com/iden3/circom_old/blob/master/TUTORIAL.md)
     - [gnark turorial](https://github.com/ConsenSys/gnark)
     - [zokrates tutorial](https://zokrates.github.io/)
     - [arkworks tutorial](https://github.com/arkworks-rs/r1cs-tutorial/)



## ZK Audit Database

### [Audit Report library](/zkreport/)





