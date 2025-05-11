# SCIV – Supply-Chain Integrity Verifier (Executable JAR Edition)

This distribution bundles:
- Java 17 sources  
- Maven **Shade** plugin – produces a fat JAR with `Main-Class` manifest  
- Sample SBOM, YARA rule, policy file  

---

## Prerequisites

1. **Java 17+** installed and on your `PATH`.  
2. **YARA** installed and on your `PATH`.  
   - **macOS** (Homebrew):  
     ```bash
     brew install yara
     ```
   - **Ubuntu/Debian**:  
     ```bash
     sudo apt update && sudo apt install yara
     ```
   - **Windows** (Chocolatey):  
     ```powershell
     choco install yara
     ```
   - Or download binaries/source from https://github.com/VirusTotal/yara/releases and follow the instructions for your platform.

3. **MVN** installed and on your `PATH` (optional if you want to compile yourself).


    Install via your platform’s package manager:

    - **Ubuntu/Debian**
        ```bash
        sudo apt update
        sudo apt install maven
        ```
    - **macOS** (Homebrew):
        ```bash
        brew update
        brew install maven
        ```
    - **Windows** (Chocolatey):  
        ```powershell
        choco install maven
        ```
---

## Run SCIV


1. **Double Click Precompiled jar (Recommended)**

Simply double click on the precompiled CompiledSCIV.jar file after installing Yara and Java

2. **Build with Maven (optional)**

If you prefer to build yourself:
(From project root (Where pom.xml is located))
```bash
mvn clean package
```
(or `./mvnw clean package` on Unix, or `mvnw.cmd clean package` on Windows)

The shaded JAR will be produced at:
target/sciv-1.0-SNAPSHOT-shaded.jar

Locate and double click the built JAR (e.g. `target/sciv-1.0-SNAPSHOT-shaded.jar`).  

---
## Test

Drag and drop the three test files in each testpayload subfolder at the same time
into the gui and click verify.

```bash
testpayloads/
├─ valid/
│  ├─ artefact.zip
│  ├─ artefact.sig
│  └─ vendor.crt

```bash