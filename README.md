# Java Side-channel Patches
> Various patches to aid side-channel analysis in Java.

## Introduction
When analyzing Java programs, you will occasionally encounter very highly obfuscated or otherwise protected JARs.
Removing those protections can be very time-consuming, and may not even be a requirement for the purpose of your analysis.
Using Java's open nature, we can re-write its runtime - the JRE, to intercept and/or modify APIs of interest.

This project includes some of the most common changes you will want to do to a JRE to extract useful information.

## Notes
- If the JARs you edit are signed, the JVM will refuse to start
- These changes are made for [Amazon Corretto 8](https://github.com/corretto/corretto-8). They may not work on another JRE version or distribution.

## Features
- Crypto dumper (`%USERNAME%/Desktop/hey/dump/`)
- `RuntimeMXBean.getInputArguments` bypass for Java agents

## Usage
Use [Recaf](https://github.com/Col-E/Recaf) to compile the classes and replace the originals in `jre8/lib/jce.jar` and `rt.jar`.
