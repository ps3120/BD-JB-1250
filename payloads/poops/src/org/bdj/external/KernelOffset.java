package org.bdj.external;

import org.bdj.Status;
import java.util.Hashtable;

public class KernelOffset {

    // proc structure
    public static final int PROC_PID = 0xb0;
    public static final int PROC_FD = 0x48;
    public static final int PROC_VM_SPACE = 0x200;
    public static final int PROC_COMM = 0x448;
    public static final int PROC_SYSENT = 0x470;

    // filedesc
    public static final int FILEDESC_OFILES = 0x0;
    public static final int SIZEOF_OFILES = 0x8;

    // vmspace structure  
    public static final int VMSPACE_VM_PMAP = 0x1C8;
    public static final int VMSPACE_VM_VMID = 0x1D4;

    // pmap structure
    public static final int PMAP_CR3 = 0x28;

    // network
    public static final int SO_PCB = 0x18;
    public static final int INPCB_PKTOPTS = 0x118;

    // PS4 IPv6 structure
    public static final int PS4_OFF_TCLASS = 0xb0;
    public static final int PS4_OFF_IP6PO_RTHDR = 0x68;

    private static Hashtable ps4KernelOffsets;
    private static Hashtable shellcodeData;
    private static String currentFirmware = null;

    static {
        initializePS4Offsets();
        initializeShellcodes();
    }

    private static void initializePS4Offsets() {
        ps4KernelOffsets = new Hashtable();

         // PS4 9.00
        addFirmwareOffsets("9.00", 0x7f6f27L, 0x111f870L, 0x21eff20L, 0x221688dL, 0x1107f00L, 0x4c7adL, 0x3977F0);

        // PS4 9.03/9.04  
        addFirmwareOffsets("9.03", 0x7f4ce7L, 0x111b840L, 0x21ebf20L, 0x221288dL, 0x1103f00L, 0x5325bL, 0x3959F0);
        addFirmwareOffsets("9.04", 0x7f4ce7L, 0x111b840L, 0x21ebf20L, 0x221288dL, 0x1103f00L, 0x5325bL, 0x3959F0);

        // PS4 9.50/9.51/9.60
        addFirmwareOffsets("9.50", 0x769a88L, 0x11137d0L, 0x21a6c30L, 0x221a40dL, 0x1100ee0L, 0x15a6dL, 0x85EE0);
        addFirmwareOffsets("9.51", 0x769a88L, 0x11137d0L, 0x21a6c30L, 0x221a40dL, 0x1100ee0L, 0x15a6dL, 0x85EE0);
        addFirmwareOffsets("9.60", 0x769a88L, 0x11137d0L, 0x21a6c30L, 0x221a40dL, 0x1100ee0L, 0x15a6dL, 0x85EE0);

        // PS4 10.00/10.01
        addFirmwareOffsets("10.00", 0x7b5133L, 0x111b8b0L, 0x1b25bd0L, 0x1b9e08dL, 0x110a980L, 0x68b1L, 0x45B10);
        addFirmwareOffsets("10.01", 0x7b5133L, 0x111b8b0L, 0x1b25bd0L, 0x1b9e08dL, 0x110a980L, 0x68b1L, 0x45B10);

        // PS4 10.50/10.70/10.71
        addFirmwareOffsets("10.50", 0x7a7b14L, 0x111b910L, 0x1bf81f0L, 0x1be460dL, 0x110a5b0L, 0x50dedL, 0x25E330);
        addFirmwareOffsets("10.70", 0x7a7b14L, 0x111b910L, 0x1bf81f0L, 0x1be460dL, 0x110a5b0L, 0x50dedL, 0x25E330);
        addFirmwareOffsets("10.71", 0x7a7b14L, 0x111b910L, 0x1bf81f0L, 0x1be460dL, 0x110a5b0L, 0x50dedL, 0x25E330);

        // PS4 11.00
        addFirmwareOffsets("11.00", 0x7fc26fL, 0x111f830L, 0x2116640L, 0x221c60dL, 0x1109350L, 0x71a21L, 0x58F10);

        // PS4 11.02
        addFirmwareOffsets("11.02", 0x7fc22fL, 0x111f830L, 0x2116640L, 0x221c60dL, 0x1109350L, 0x71a21L, 0x58F10);

        // PS4 11.50/11.52
        addFirmwareOffsets("11.50", 0x784318L, 0x111fa18L, 0x2136e90L, 0x21cc60d, 0x110a760L, 0x704d5L, 0xE6C20);
        addFirmwareOffsets("11.52", 0x784318L, 0x111fa18L, 0x2136e90L, 0x21cc60d, 0x110a760L, 0x704d5L, 0xE6C20);

        // PS4 12.00/12.02
        addFirmwareOffsets("12.00", 0x784798L, 0x111fa18L, 0x2136e90L, 0x21cc60dL, 0x110a760L, 0x47b31L, 0xE6C20);
        addFirmwareOffsets("12.02", 0x784798L, 0x111fa18L, 0x2136e90L, 0x21cc60dL, 0x110a760L, 0x47b31L, 0xE6C20);

        // PS4 12.50/12.52, fill only really needed ones
        addFirmwareOffsets("12.50", 0, 0x111fa18L, 0x2136e90L, 0, 0x110a760L, 0x47b31L, 0xE6C20);
        addFirmwareOffsets("12.52", 0, 0x111fa18L, 0x2136e90L, 0, 0x110a760L, 0x47b31L, 0xE6C20);
		
		// PS4 13.00, fill only really needed ones
		addFirmwareOffsets("13.00", 0, 0x111fa18L, 0x2136e90L, 0, 0x110a760L, 0x47b31L, 0xE6C20);
    }

    private static void initializeShellcodes() {
        shellcodeData = new Hashtable();

        shellcodeData.put("9.00", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b990e9ffff4881c2edc5040066898174686200c681cd0a0000ebc681fd132700ebc68141142700ebc681bd142700ebc68101152700ebc681ad162700ebc6815d1b2700ebc6812d1c2700eb6689b15f716200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c681061a0000ebc7818d0b08000000000066448989c4ae2300c6817fb62300ebc781401b22004831c0c3c6812a63160037c6812d63160037c781200510010200000048899128051001c7814c051001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("9.03", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b990e9ffff4881c29b30050066898134486200c681cd0a0000ebc6817d102700ebc681c1102700ebc6813d112700ebc68181112700ebc6812d132700ebc681dd172700ebc681ad182700eb6689b11f516200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c681061a0000ebc7818d0b0800000000006644898994ab2300c6814fb32300ebc781101822004831c0c3c681da62160037c681dd62160037c78120c50f010200000048899128c50f01c7814cc50f01010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("9.50", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b990e9ffff4881c2ad580100668981e44a6200c681cd0a0000ebc6810d1c2000ebc681511c2000ebc681cd1c2000ebc681111d2000ebc681bd1e2000ebc6816d232000ebc6813d242000eb6689b1cf536200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c68136a51f00ebc7813d6d1900000000006644898924f71900c681dffe1900ebc781601901004831c0c3c6817a2d120037c6817d2d120037c78100950f010200000048899108950f01c7812c950f01010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("10.00", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b990e9ffff4881c2f166000066898164e86100c681cd0a0000ebc6816d2c4700ebc681b12c4700ebc6812d2d4700ebc681712d4700ebc6811d2f4700ebc681cd334700ebc6819d344700eb6689b14ff16100c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c68156772600ebc7817d2039000000000066448989a4fa1800c6815f021900ebc78140ea1b004831c0c3c6819ad50e0037c6819dd50e0037c781a02f100102000000488991a82f1001c781cc2f1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("10.50", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb0000006689811330210041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c22d0c05006689b1233021006689b94330210066448981b47d6200c681cd0a0000ebc681bd720d00ebc68101730d00ebc6817d730d00ebc681c1730d00ebc6816d750d00ebc6811d7a0d00ebc681ed7a0d00eb664489899f866200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681c6c10800ebc781eeb2470000000000668981d42a2100c7818830210090e93c01c78160ab2d004831c0c3c6812ac4190037c6812dc4190037c781d02b100102000000488991d82b1001c781fc2b1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("11.00", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981334c1e0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2611807006689b1434c1e006689b9634c1e0066448981643f6200c681cd0a0000ebc6813ddd2d00ebc68181dd2d00ebc681fddd2d00ebc68141de2d00ebc681eddf2d00ebc6819de42d00ebc6816de52d00eb664489894f486200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c68126154300ebc781eec8350000000000668981f4461e00c781a84c1e0090e93c01c781e08c08004831c0c3c6816a62150037c6816d62150037c781701910010200000048899178191001c7819c191001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("11.02", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981534c1e0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2611807006689b1634c1e006689b9834c1e0066448981043f6200c681cd0a0000ebc6815ddd2d00ebc681a1dd2d00ebc6811dde2d00ebc68161de2d00ebc6810de02d00ebc681bde42d00ebc6818de52d00eb66448989ef476200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681b6144300ebc7810ec935000000000066898114471e00c781c84c1e0090e93c01c781e08c08004831c0c3c6818a62150037c6818d62150037c781701910010200000048899178191001c7819c191001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("11.50", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2150307006689b1b3761b006689b9d3761b0066448981b4786200c681cd0a0000ebc681edd22b00ebc68131d32b00ebc681add32b00ebc681f1d32b00ebc6819dd52b00ebc6814dda2b00ebc6811ddb2b00eb664489899f816200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681a6123900ebc781aebe2f000000000066898164711b00c78118771b0090e93c01c78120d63b004831c0c3c6813aa61f0037c6813da61f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("12.00", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2717904006689b1b3761b006689b9d3761b0066448981f47a6200c681cd0a0000ebc681cdd32b00ebc68111d42b00ebc6818dd42b00ebc681d1d42b00ebc6817dd62b00ebc6812ddb2b00ebc681fddb2b00eb66448989df836200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681e6143900ebc781eec02f000000000066898164711b00c78118771b0090e93c01c78160d83b004831c0c3c6811aa71f0037c6811da71f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("12.50", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981e3761b0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2717904006689b1f3761b006689b913771b0066448981347b6200c681cd0a0000ebc6810dd42b00ebc68151d42b00ebc681cdd42b00ebc68111d52b00ebc681bdd62b00ebc6816ddb2b00ebc6813ddc2b00eb664489891f846200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c68126153900ebc7812ec12f0000000000668981a4711b00c78158771b0090e93c01c781a0d83b004831c0c3c6815aa71f0037c6815da71f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3");
        
		shellcodeData.put("13.00","b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981e3761b00b8eb04000041b9eb00000041baeb0000006689814cc12f0041bbeb000000b890e9ffff4881c2717904006689b1f3761b006689b913771b0066448981847b6200c681cd0a0000ebc6812dd42b00ebc68171d42b00ebc681edd42b00ebc68131d52b00ebc681ddd62b00ebc6818ddb2b00ebc6815ddc2b00eb664489896f846200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c68146153900eb668981a4711b00c78158771b0090e93c01c781c0d83b004831c0c3c6817aa71f0037c6817da71f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3");
		
        shellcodeData.put("9.04", shellcodeData.get("9.03"));
        shellcodeData.put("9.51", shellcodeData.get("9.50"));
        shellcodeData.put("9.60", shellcodeData.get("9.50"));
        shellcodeData.put("10.01", shellcodeData.get("10.00"));
        shellcodeData.put("10.70", shellcodeData.get("10.50"));
        shellcodeData.put("10.71", shellcodeData.get("10.50"));
        shellcodeData.put("11.52", shellcodeData.get("11.50"));
        shellcodeData.put("12.02", shellcodeData.get("12.00"));
        shellcodeData.put("12.52", shellcodeData.get("12.50"));
    }

    private static void addFirmwareOffsets(String fw, long evf, long prison0, long rootvnode, 
                                         long targetId, long sysent661, long jmpRsi, long klLock) {
        Hashtable offsets = new Hashtable();
        offsets.put("EVF_OFFSET", new Long(evf));
        offsets.put("PRISON0", new Long(prison0));
        offsets.put("ROOTVNODE", new Long(rootvnode));
        offsets.put("TARGET_ID_OFFSET", new Long(targetId));
        offsets.put("SYSENT_661_OFFSET", new Long(sysent661));
        offsets.put("JMP_RSI_GADGET", new Long(jmpRsi));
        offsets.put("KL_LOCK", new Long(klLock));
        ps4KernelOffsets.put(fw, offsets);
    }

    public static String getFirmwareVersion() {
        if (currentFirmware == null) {
            currentFirmware = Helper.getCurrentFirmwareVersion();
        }
        return currentFirmware;
    }

    public static boolean hasPS4Offsets() {
        return ps4KernelOffsets.containsKey(getFirmwareVersion());
    }

    public static long getPS4Offset(String offsetName) {
        String fw = getFirmwareVersion();
        Hashtable offsets = (Hashtable)ps4KernelOffsets.get(fw);
        if (offsets == null) {
            throw new RuntimeException("No offsets available for firmware " + fw);
        }

        Long offset = (Long)offsets.get(offsetName);
        if (offset == null) {
            throw new RuntimeException("Offset " + offsetName + " not found for firmware " + fw);
        }

        return offset.longValue();
    }

    public static boolean shouldApplyKernelPatches() {
        return hasPS4Offsets() && hasShellcodeForCurrentFirmware();
    }

    public static byte[] getKernelPatchesShellcode() {
        String firmware = getFirmwareVersion();
        String shellcode = (String)shellcodeData.get(firmware);
        if (shellcode == null || shellcode.length() == 0) {
            return new byte[0];
        }
        return hexToBinary(shellcode);
    }

    public static boolean hasShellcodeForCurrentFirmware() {
        String firmware = getFirmwareVersion();
        return shellcodeData.containsKey(firmware);
    }

    private static byte[] hexToBinary(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            int value = Integer.parseInt(hex.substring(index, index + 2), 16);
            result[i] = (byte)value;
        }
        return result;
    }

    // Initialize method to set firmware from Helper
    public static void initializeFromHelper() {
        String helperFirmware = Helper.getCurrentFirmwareVersion();
        if (helperFirmware != null) {
            currentFirmware = helperFirmware;
        }
    }
}
