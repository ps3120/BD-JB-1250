package org.bdj.external;

import org.bdj.Status;
import org.bdj.api.*;

public class Helper {
    // Constants
    public static final int AF_INET = 2;
    public static final int AF_INET6 = 28;
    public static final int AF_UNIX = 1;
    public static final int SOCK_DGRAM = 2;
    public static final int SOCK_STREAM = 1;
    public static final int IPPROTO_UDP = 17;
    public static final int IPPROTO_TCP = 6;
    public static final int IPPROTO_IPV6 = 41;
    public static final int SOL_SOCKET = 0xffff;
    public static final int SO_REUSEADDR = 4;
    public static final int SO_LINGER = 0x80;
    public static final int TCP_INFO = 0x20;
    public static final int TCPS_ESTABLISHED = 4;

    // IPv6 Constants
    public static final int IPV6_RTHDR = 51;
    public static final int IPV6_TCLASS = 61;
    public static final int IPV6_2292PKTOPTIONS = 25;
    public static final int IPV6_PKTINFO = 46;
    public static final int IPV6_NEXTHOP = 48;

    // AIO Constants
    public static final int AIO_CMD_READ = 1;
    public static final int AIO_CMD_WRITE = 2;
    public static final int AIO_CMD_FLAG_MULTI = 0x1000;
    public static final int AIO_CMD_MULTI_READ = AIO_CMD_FLAG_MULTI | AIO_CMD_READ;
    public static final int AIO_CMD_MULTI_WRITE = AIO_CMD_FLAG_MULTI | AIO_CMD_WRITE;
    public static final int AIO_STATE_COMPLETE = 3;
    public static final int AIO_STATE_ABORTED = 4;
    public static final int AIO_PRIORITY_HIGH = 3;
    public static final int SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    public static final int MAX_AIO_IDS = 0x80;

    // CPU and Threading Constants
    public static final int CPU_LEVEL_WHICH = 3;
    public static final int CPU_WHICH_TID = 1;
    public static final int RTP_SET = 1;
    public static final int RTP_PRIO_REALTIME = 2;

    // Syscall Numbers
    public static final int SYS_READ = 0x3;
    public static final int SYS_WRITE = 0x4;
    public static final int SYS_OPEN = 0x5;
    public static final int SYS_CLOSE = 0x6;
    public static final int SYS_GETPID = 0x14;
    public static final int SYS_GETUID = 0x18;
    public static final int SYS_ACCEPT = 0x1e;
    public static final int SYS_PIPE = 0x2a;
    public static final int SYS_MPROTECT = 0x4a;
    public static final int SYS_SOCKET = 0x61;
    public static final int SYS_CONNECT = 0x62;
    public static final int SYS_BIND = 0x68;
    public static final int SYS_SETSOCKOPT = 0x69;
    public static final int SYS_LISTEN = 0x6a;
    public static final int SYS_GETSOCKOPT = 0x76;
    public static final int SYS_NETGETIFLIST = 0x7d;
    public static final int SYS_SOCKETPAIR = 0x87;
    public static final int SYS_SYSCTL = 0xca;
    public static final int SYS_NANOSLEEP = 0xf0;
    public static final int SYS_SIGACTION = 0x1a0;
    public static final int SYS_THR_SELF = 0x1b0;
    public static final int SYS_CPUSET_GETAFFINITY = 0x1e7;
    public static final int SYS_CPUSET_SETAFFINITY = 0x1e8;
    public static final int SYS_RTPRIO_THREAD = 0x1d2;
    public static final int SYS_EVF_CREATE = 0x21a;
    public static final int SYS_EVF_DELETE = 0x21b;
    public static final int SYS_EVF_SET = 0x220;
    public static final int SYS_EVF_CLEAR = 0x221;
    public static final int SYS_IS_IN_SANDBOX = 0x249;
    public static final int SYS_DLSYM = 0x24f;
    public static final int SYS_DYNLIB_LOAD_PRX = 0x252;
    public static final int SYS_DYNLIB_UNLOAD_PRX = 0x253;
    public static final int SYS_AIO_MULTI_DELETE = 0x296;
    public static final int SYS_AIO_MULTI_WAIT = 0x297;
    public static final int SYS_AIO_MULTI_POLL = 0x298;
    public static final int SYS_AIO_MULTI_CANCEL = 0x29a;
    public static final int SYS_AIO_SUBMIT_CMD = 0x29d;

    public static final int SYS_MUNMAP = 0x49;
    public static final int SYS_MMAP = 477;
    public static final int SYS_JITSHM_CREATE = 0x215;
    public static final int SYS_JITSHM_ALIAS = 0x216;
    public static final int SYS_KEXEC = 0x295;
    
    public static final int SYS_SETUID = 0x17;

    public static API api;
    private static long libkernelBase;
    private static long[] syscallWrappers;
    public static Buffer AIO_ERRORS;
    private static String firmwareVersion;

    static {
        try {
            api = API.getInstance();
            syscallWrappers = new long[0x400];
            AIO_ERRORS = new Buffer(4 * MAX_AIO_IDS);
            initSyscalls();
            detectFirmwareVersion();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static long getLibkernelBase() {
        return libkernelBase;
    }

    private static void initSyscalls() throws Exception {
        collectInfo();
        findSyscallWrappers();

        int[] requiredSyscalls = {
            SYS_AIO_SUBMIT_CMD, SYS_AIO_MULTI_DELETE, SYS_AIO_MULTI_WAIT,
            SYS_AIO_MULTI_POLL, SYS_AIO_MULTI_CANCEL, SYS_SOCKET,
            SYS_BIND, SYS_LISTEN, SYS_CONNECT, SYS_ACCEPT,
            SYS_SETSOCKOPT, SYS_GETSOCKOPT, SYS_SOCKETPAIR,
            SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_OPEN,
            SYS_EVF_CREATE, SYS_EVF_DELETE, SYS_EVF_SET, SYS_EVF_CLEAR,
            SYS_GETPID, SYS_GETUID, SYS_SYSCTL, SYS_IS_IN_SANDBOX,
            SYS_CPUSET_GETAFFINITY, SYS_CPUSET_SETAFFINITY, SYS_RTPRIO_THREAD,
            SYS_MUNMAP, SYS_MMAP, SYS_JITSHM_CREATE, SYS_JITSHM_ALIAS, SYS_KEXEC, SYS_SETUID
            // SYS_MUNMAP, SYS_MMAP, SYS_JITSHM_CREATE, SYS_JITSHM_ALIAS, SYS_KEXEC,
            // SYS_SETUID
            
        };

        boolean allFound = true;
        for (int i = 0; i < requiredSyscalls.length; i++) {
            int syscall = requiredSyscalls[i];
            if (syscallWrappers[syscall] == 0) {
                Status.println("Warning: Syscall " + Integer.toHexString(syscall) + " not found");
                allFound = false;
            }
        }

        if (!allFound) {
            throw new RuntimeException("Required syscalls not found");
        }
    }

    private static void detectFirmwareVersion() {
        firmwareVersion = sysctlByName("kern.sdk_version");
    }

    public static String getCurrentFirmwareVersion() {
        return firmwareVersion;
    }

    private static String sysctlByName(String name) {
        Buffer translateNameMib = new Buffer(8);
        Buffer mib = new Buffer(0x70);
        Buffer size = new Buffer(8);
        Buffer resultBuf = new Buffer(8);
        Buffer resultSize = new Buffer(8);
        
        // Setup translate name mib
        translateNameMib.putLong(0, 0x300000000L);
        size.putLong(0, 0x70);
        
        // Convert string name to byte array with null terminator
        byte[] nameBytes = new byte[name.length() + 1];
        for (int i = 0; i < name.length(); i++) {
            nameBytes[i] = (byte)name.charAt(i);
        }
        nameBytes[name.length()] = 0;
        Buffer nameBuffer = new Buffer(nameBytes.length);
        nameBuffer.put(0, nameBytes);
        
        // Translate name to mib
        long result = syscall(SYS_SYSCTL, translateNameMib.address(), 2L, 
                             mib.address(), size.address(), 
                             nameBuffer.address(), (long)nameBytes.length);
        if (result < 0) {
            throw new RuntimeException("Failed to translate sysctl name to mib: " + name);
        }
        
        // Get the actual value
        resultSize.putLong(0, 8);
        result = syscall(SYS_SYSCTL, mib.address(), 2L, 
                        resultBuf.address(), resultSize.address(), 0L, 0L);
        if (result < 0) {
            throw new RuntimeException("Failed to get sysctl value for: " + name);
        }
        
        int majorByte = resultBuf.getByte(3) & 0xFF;  // Second byte of version data
        int minorByte = resultBuf.getByte(2) & 0xFF;  // First byte of version data
        
        String majorHex = Integer.toHexString(majorByte);
        String minorHex = Integer.toHexString(minorByte);
        if (minorHex.length() == 1) {
            minorHex = "0" + minorHex;
        }
        return majorHex + "." + minorHex;
    }

    public static boolean isJailbroken() {
        try {
            long setuidResult = syscall(SYS_SETUID, 0L);
            if (setuidResult == 0) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    private static void collectInfo() throws Exception {
        final int SEGMENTS_OFFSET = 0x160;
        long sceKernelGetModuleInfoFromAddr = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "sceKernelGetModuleInfoFromAddr");
        if (sceKernelGetModuleInfoFromAddr == 0) {
            throw new RuntimeException("sceKernelGetModuleInfoFromAddr not found");
        }

        long addrInsideLibkernel = sceKernelGetModuleInfoFromAddr;
        Buffer modInfo = new Buffer(0x300);

        long ret = api.call(sceKernelGetModuleInfoFromAddr, addrInsideLibkernel, 1, modInfo.address());
        if (ret != 0) {
            throw new RuntimeException("sceKernelGetModuleInfoFromAddr() error: 0x" + Long.toHexString(ret));
        }

        libkernelBase = api.read64(modInfo.address() + SEGMENTS_OFFSET);
    }

    private static void findSyscallWrappers() {
        final int TEXT_SIZE = 0x40000;
        byte[] libkernelText = new byte[TEXT_SIZE];
        for (int i = 0; i < TEXT_SIZE; i++) {
            libkernelText[i] = api.read8(libkernelBase + i);
        }

        for (int i = 0; i <= TEXT_SIZE - 12; i++) {
            if (libkernelText[i] == 0x48 &&
            libkernelText[i + 1] == (byte)0xc7 &&
            libkernelText[i + 2] == (byte)0xc0 &&
            libkernelText[i + 7] == 0x49 &&
            libkernelText[i + 8] == (byte)0x89 &&
            libkernelText[i + 9] == (byte)0xca &&
            libkernelText[i + 10] == 0x0f &&
            libkernelText[i + 11] == 0x05) {

                int syscallNum = (libkernelText[i + 3] & 0xFF) |
                ((libkernelText[i + 4] & 0xFF) << 8) |
                ((libkernelText[i + 5] & 0xFF) << 16) |
                ((libkernelText[i + 6] & 0xFF) << 24);

                if (syscallNum >= 0 && syscallNum < syscallWrappers.length) {
                    syscallWrappers[syscallNum] = libkernelBase + i;
                }
            }
        }
    }

    // Syscall wrappers
    public static long syscall(int number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
        return api.call(syscallWrappers[number], arg0, arg1, arg2, arg3, arg4, arg5);
    }

    public static long syscall(int number, long arg0, long arg1, long arg2, long arg3, long arg4) {
        return api.call(syscallWrappers[number], arg0, arg1, arg2, arg3, arg4);
    }

    public static long syscall(int number, long arg0, long arg1, long arg2, long arg3) {
        return api.call(syscallWrappers[number], arg0, arg1, arg2, arg3);
    }

    public static long syscall(int number, long arg0, long arg1, long arg2) {
        return api.call(syscallWrappers[number], arg0, arg1, arg2);
    }

    public static long syscall(int number, long arg0, long arg1) {
        return api.call(syscallWrappers[number], arg0, arg1);
    }

    public static long syscall(int number, long arg0) {
        return api.call(syscallWrappers[number], arg0);
    }

    public static long syscall(int number) {
        return api.call(syscallWrappers[number]);
    }

    // Utility functions
    public static short htons(int port) {
        return (short)(((port << 8) | (port >>> 8)) & 0xFFFF);
    }

    public static int aton(String ip) {
        String[] parts = split(ip, "\\.");
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        int c = Integer.parseInt(parts[2]);
        int d = Integer.parseInt(parts[3]);
        return (d << 24) | (c << 16) | (b << 8) | a;
    }

    public static String toHexString(int value, int minWidth) {
        String hex = Integer.toHexString(value);
        StringBuffer sb = new StringBuffer();
        for (int i = hex.length(); i < minWidth; i++) {
            sb.append("0");
        }
        sb.append(hex);
        return sb.toString();
    }

    public static String[] split(String str, String regex) {
        java.util.Vector parts = new java.util.Vector();
        int start = 0;
        int pos = 0;

        while ((pos = str.indexOf(".", start)) != -1) {
            parts.addElement(str.substring(start, pos));
            start = pos + 1;
        }
        parts.addElement(str.substring(start));

        String[] result = new String[parts.size()];
        for (int i = 0; i < parts.size(); i++) {
            result[i] = (String)parts.elementAt(i);
        }
        return result;
    }

    public static int createUdpSocket() {
        long result = syscall(SYS_SOCKET, (long)AF_INET6, (long)SOCK_DGRAM, (long)IPPROTO_UDP);
        if (result == -1) {
            throw new RuntimeException("new_socket() error: " + result);
        }
        return (int)result;
    }

    public static int createTcpSocket() {
        long result = syscall(SYS_SOCKET, (long)AF_INET, (long)SOCK_STREAM, 0L);
        if (result == -1) {
            throw new RuntimeException("new_tcp_socket() error: " + result);
        }
        return (int)result;
    }

    public static void setSockOpt(int sd, int level, int optname, Buffer optval, int optlen) {
        long result = syscall(SYS_SETSOCKOPT, (long)sd, (long)level, (long)optname, optval.address(), (long)optlen);
        if (result == -1) {
            throw new RuntimeException("setsockopt() error: " + result);
        }
    }

    public static int getSockOpt(int sd, int level, int optname, Buffer optval, int optlen) {
        Buffer size = new Buffer(8);
        size.putInt(0, optlen);
        long result = syscall(SYS_GETSOCKOPT, (long)sd, (long)level, (long)optname, optval.address(), size.address());
        if (result == -1) {
            throw new RuntimeException("getsockopt() error: " + result);
        }
        return size.getInt(0);
    }

    public static int getCurrentCore() {
        try {
            Buffer mask = new Buffer(0x10);
            mask.fill((byte)0);

            long result = syscall(SYS_CPUSET_GETAFFINITY, (long)CPU_LEVEL_WHICH, (long)CPU_WHICH_TID, -1L, 0x10L, mask.address());
            if (result != 0) {
                return -1;
            }

            int maskValue = mask.getInt(0);
            int position = 0;
            int num = maskValue;

            while (num > 0) {
                num = num >>> 1;
                position++;
            }

            return Math.max(0, position - 1);
        } catch (Exception e) {
            return -1;
        }
    }

    public static boolean pinToCore(int core) {
        try {
            Buffer mask = new Buffer(0x10);
            mask.fill((byte)0);

            int maskValue = 1 << core;
            mask.putShort(0, (short)maskValue);

            long result = syscall(SYS_CPUSET_SETAFFINITY, (long)CPU_LEVEL_WHICH, (long)CPU_WHICH_TID, -1L, 0x10L, mask.address());
            return result == 0;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean setRealtimePriority(int priority) {
        try {
            Buffer rtprio = new Buffer(0x4);
            rtprio.putShort(0, (short)RTP_PRIO_REALTIME);
            rtprio.putShort(2, (short)priority);

            long result = syscall(SYS_RTPRIO_THREAD, (long)RTP_SET, 0L, rtprio.address());
            return result == 0;
        } catch (Exception e) {
            return false;
        }
    }

    // AIO operations
    public static Buffer createAioRequests(int numReqs) {
        Buffer reqs1 = new Buffer(0x28 * numReqs);
        for (int i = 0; i < numReqs; i++) {
            reqs1.putInt(i * 0x28 + 0x20, -1); // fd = -1
        }
        return reqs1;
    }

    public static long aioSubmitCmd(int cmd, long reqs, int numReqs, int prio, long ids) {
        return syscall(SYS_AIO_SUBMIT_CMD, (long)cmd, reqs, (long)numReqs, (long)prio, ids);
    }

    public static long aioMultiCancel(long ids, int numIds, long states) {
        return syscall(SYS_AIO_MULTI_CANCEL, ids, (long)numIds, states);
    }

    public static long aioMultiPoll(long ids, int numIds, long states) {
        return syscall(SYS_AIO_MULTI_POLL, ids, (long)numIds, states);
    }

    public static long aioMultiDelete(long ids, int numIds, long states) {
        return syscall(SYS_AIO_MULTI_DELETE, ids, (long)numIds, states);
    }

    public static long aioMultiWait(long ids, int numIds, long states, int mode, long timeout) {
        return syscall(SYS_AIO_MULTI_WAIT, ids, (long)numIds, states, (long)mode, timeout);
    }

    // Bulk AIO operations
    public static void cancelAios(long ids, int numIds) {
        int len = MAX_AIO_IDS;
        int rem = numIds % len;
        int numBatches = (numIds - rem) / len;

        for (int i = 0; i < numBatches; i++) {
            aioMultiCancel(ids + (i * 4 * len), len, AIO_ERRORS.address());
        }

        if (rem > 0) {
            aioMultiCancel(ids + (numBatches * 4 * len), rem, AIO_ERRORS.address());
        }
    }

    public static void freeAios(long ids, int numIds, boolean doCancel) {
        int len = MAX_AIO_IDS;
        int rem = numIds % len;
        int numBatches = (numIds - rem) / len;

        for (int i = 0; i < numBatches; i++) {
            long addr = ids + (i * 4 * len);
            if (doCancel) {
                aioMultiCancel(addr, len, AIO_ERRORS.address());
            }
            aioMultiPoll(addr, len, AIO_ERRORS.address());
            aioMultiDelete(addr, len, AIO_ERRORS.address());
        }

        if (rem > 0) {
            long addr = ids + (numBatches * 4 * len);
            if (doCancel) {
                aioMultiCancel(addr, rem, AIO_ERRORS.address());
            }
            aioMultiPoll(addr, rem, AIO_ERRORS.address());
            aioMultiDelete(addr, rem, AIO_ERRORS.address());
        }
    }

    public static void freeAios(long ids, int numIds) {
        freeAios(ids, numIds, true);
    }

    // IPv6 routing header operations
    public static int buildRoutingHeader(Buffer buf, int size) {
        int len = ((size >>> 3) - 1) & (~1);
        size = (len + 1) << 3;

        buf.putByte(0, (byte)0);             // ip6r_nxt
        buf.putByte(1, (byte)len);           // ip6r_len
        buf.putByte(2, (byte)0);             // ip6r_type
        buf.putByte(3, (byte)(len >>> 1));   // ip6r_segleft

        return size;
    }

    public static int getRthdr(int sd, Buffer buf, int len) {
        return getSockOpt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
    }

    public static void setRthdr(int sd, Buffer buf, int len) {
        setSockOpt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
    }

    public static void freeRthdrs(int[] sds) {
        for (int i = 0; i < sds.length; i++) {
            if (sds[i] >= 0) {
                setSockOpt(sds[i], IPPROTO_IPV6, IPV6_RTHDR, new Buffer(1), 0);
            }
        }
    }

    // EVF operations
    public static int createEvf(long name, int flags) {
        long result = syscall(SYS_EVF_CREATE, name, 0L, (long)flags);
        if (result == -1) {
            throw new RuntimeException("evf_create() error: " + result);
        }
        return (int)result;
    }

    public static void setEvfFlags(int id, int flags) {
        long clearResult = syscall(SYS_EVF_CLEAR, (long)id, 0L);
        if (clearResult == -1) {
            throw new RuntimeException("evf_clear() error: " + clearResult);
        }

        long setResult = syscall(SYS_EVF_SET, (long)id, (long)flags);
        if (setResult == -1) {
            throw new RuntimeException("evf_set() error: " + setResult);
        }
    }

    public static void freeEvf(int id) {
        long result = syscall(SYS_EVF_DELETE, (long)id);
        if (result == -1) {
            throw new RuntimeException("evf_delete() error: " + result);
        }
    }

    // Array manipulation helpers
    public static void removeSocketFromArray(int[] sds, int index) {
        if (index >= 0 && index < sds.length) {
            for (int i = index; i < sds.length - 1; i++) {
                sds[i] = sds[i + 1];
            }
            sds[sds.length - 1] = -1;
        }
    }

    public static void addSocketToArray(int[] sds, int socket) {
        for (int i = 0; i < sds.length; i++) {
            if (sds[i] == -1) {
                sds[i] = socket;
                break;
            }
        }
    }

    // String extraction helper
    public static String extractStringFromBuffer(Buffer buf) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 8; i++) {
            byte b = buf.getByte(i);
            if (b == 0) break;
            if (b >= 32 && b <= 126) {
                sb.append((char)b);
            } else {
                break;
            }
        }
        return sb.toString();
    }

    public static String getPlatform() {
        return "ps4";
    }

    // Print system information - simplified to remove KernelOffset dependencies
    public static void printSystemInfo() {
        Status.println("=== System Information ===");
        Status.println("Platform: " + getPlatform());
        Status.println("Firmware: " + getCurrentFirmwareVersion());
    }

}