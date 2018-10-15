# jsch-111-bugfix

This project provides an alternative implementation of SignatureDSA.java to fix [JSCH bug 111](https://sourceforge.net/p/jsch/bugs/111/).

## How to use

In your pom.xml, include the following dependency:
```xml
<dependency>
	<groupId>org.jurr.jsch</groupId>
	<artifactId>jsch-111-bugfix</artifactId>
	<version><!-- Insert latest available version here --></version>
</dependency>
```
Now, before using JSCH (or a framework that depends on it, say Apache VFS for example), add the following call:
```java
JSCH111BugFix.init();
```
That all. JSCH will now use the following implementations instead of the default ones:

* org.jurr.jsch.bugfix111.SignatureDSA
* org.jurr.jsch.bugfix111.SignatureRSA

## Please review my code

This might not be die hard cryptography, but I still hope many people review this code for potential flaws.
Please take into account that this code is more or less based on a copy of the JSCH code.
So when you find a bug, please (also) notify the [JSCH](http://www.jcraft.com/jsch/) team.

## License

This project is licensed under [the 3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).