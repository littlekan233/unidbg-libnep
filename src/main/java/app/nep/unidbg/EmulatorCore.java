package app.nep.unidbg;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class EmulatorCore extends AbstractJni {
    private final AndroidEmulator emulator; // 虚拟机本体
    private final VM emuvm; // 虚拟机Dalvik VM
    private final DvmClass nepTools; // 大神 Tools类
    private final Logger log = LoggerFactory.getLogger(EmulatorCore.class);
    // JNI句柄 --GPT 5.6 Sol
    private final String JNI_ONLOAD = "JNI_OnLoad";
    private final String JNI_GETSIGN = "Java_com_netease_nep_Tools_getGetMethodSignatures";
    private final String JNI_POSTSIGN = "Java_com_netease_nep_Tools_getPostMethodSignatures";

    public EmulatorCore(String cwd){
        // init emulator
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .setProcessName("com.netease.gl")
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
        // 拿到内存空间，配置库解析器，注册mprotect服务
        Memory emumem = emulator.getMemory();
        emumem.setLibraryResolver(new AndroidResolver(23));
        UnidbgPointer mprotectCompat = emulator.getSvcMemory().registerSvc(new Arm64Svc("mprotect-compat") {
            @Override
            public long handle(Emulator<?> _emu) {
                long addr = _emu.getContext().getLongArg(0);
                int len = _emu.getContext().getIntArg(1);
                int prot = _emu.getContext().getIntArg(2);
                if (addr == 0 || len <= 0) return -1;
                try {
                    return _emu.getMemory().mprotect(addr, len, prot);
                } catch (RuntimeException e) {
                    return -1;
                }
            }
        });
        emumem.addHookListener((svcMemory, libraryName, symbolName, old) ->
                "mprotect".equals(symbolName) ? mprotectCompat.peer : 0);
        log.info("已初始化 arm64 模拟器");
        // 创建dalvik vm，加载apk
        emuvm = emulator.createDalvikVM(new File(cwd, "godlike.apk"));
        log.info("成功创建Dalvik VM并加载大神apk！");
        // 设置jni
        emuvm.setJni(this);
        emuvm.setVerbose(true);
        // 提前解析com.netease.nep.Tools
        nepTools = emuvm.resolveClass("com/netease/nep/Tools");

        // 加载库，并加载一个虚拟so模块
        DalvikModule dvmMod = emuvm.loadLibrary("nep", true);
        log.info("成功加载 libnep.so！");
        Module mod = dvmMod.getModule();
        Map<String, Long> foundedSym = discoverRuntimeSymbols(
                mod, Set.of(JNI_ONLOAD, JNI_GETSIGN, JNI_POSTSIGN));
        Map<String, UnidbgPointer> symbols = new LinkedHashMap<>();
        foundedSym.forEach((name, addr) ->
                symbols.put(name, UnidbgPointer.pointer(emulator, addr)));
        emumem.loadVirtualModule("libnep-unpacked.so", symbols);

        // 给姆斯大头！
        long jniOnLoad = symbols.get(JNI_ONLOAD).peer;
        Number version = mod.callFunction(
                emulator, jniOnLoad - mod.base, emuvm.getJavaVM(), null
        );
        log.debug("FIXED_JNI_ONLOAD=0x{}", version.intValue());
        foundedSym.forEach((name, addr) ->
                log.debug("Found symbol {}=0x{}, offset=0x{}", name, addr, addr - mod.base));
        log.info("如果不出意外的话，模拟器似乎成功启动了！");
    }

    public void destroy() throws IOException {
        // 不销毁等着你服务器💥吧（？
        emulator.close();
    }

    // 以下方法由GPT 5.6 Sol生成。
    private Map<String, Long> discoverRuntimeSymbols(Module mod, Set<String> target) {
        /*
         * 在unidbg Module中寻找一组方法的符号。
         * @param mod 模块
         * @param target 要寻找的方法
         * @return 一个Map，键为方法名，值为符号地址。
         */
        long phoff = readU64(mod.base + 0x20);
        int phentsize = readU16(mod.base + 0x36);
        int phnum = readU16(mod.base + 0x38);
        long dynamic = 0;
        for (int i = 0; i < phnum; i++) {
            long phdr = mod.base + phoff + (long) i * phentsize;
            if (readU32(phdr) == 2) {
                // PT_DYNAMIC
                dynamic = mod.base + readU64(phdr + 0x10);
                break;
            }
        }
        if (dynamic == 0) throw new IllegalStateException("PT_DYNAMIC not found");
        Map<Long, Long> tags = new HashMap<>();
        for (long entry = dynamic; ; entry += 16) {
            long tag = readU64(entry);
            if (tag == 0) break;
            tags.put(tag, readU64(entry + 8));
        }
        long hash = runtimeAddress(mod, requiredTag(tags, 4)); // DT_HASH
        long strtab = runtimeAddress(mod, requiredTag(tags, 5)); // DT_STRTAB
        long symtab = runtimeAddress(mod, requiredTag(tags, 6)); // DT_SYMTAB
        long strsz = requiredTag(tags, 10); // DT_STRSZ
        long syment = requiredTag(tags, 11); // DT_SYMENT
        long symbolCount = Integer.toUnsignedLong(readU32(hash + 4)); // nchain

        Map<String, Long> found = new LinkedHashMap<>();
        for (long index = 0; index < symbolCount; index++) {
            long symbol = symtab + index * syment;
            long nameOffset = Integer.toUnsignedLong(readU32(symbol));
            int section = readU16(symbol + 6);
            if (nameOffset == 0 || nameOffset >= strsz || section == 0) continue;
            String name = readCString(strtab + nameOffset, strsz - nameOffset);
            if (!target.contains(name)) continue;
            found.put(name, runtimeAddress(mod, readU64(symbol + 8)));
        }
        if (!found.keySet().containsAll(target))
            throw new IllegalStateException("Missing runtime symbols: " + diff(target, found.keySet()));
        return found;
    }

    private int readU16(long addr) {
        return Short.toUnsignedInt(read(addr, 2).getShort());
    }
    private int readU32(long addr) {
        return read(addr, 4).getInt();
    }
    private long readU64(long addr) {
        return read(addr, 8).getLong();
    }
    private ByteBuffer read(long addr, int size) {
        return ByteBuffer.wrap(emulator.getBackend().mem_read(addr, size))
                .order(ByteOrder.LITTLE_ENDIAN);
    }

    private long runtimeAddress(Module mod, long val) {
        return val >= mod.base && val < mod.base + mod.size
                ? val : mod.base + val;
    }
    private static long requiredTag(Map<Long, Long> tags, long tag) {
        Long val = tags.get(tag);
        if (val == null) throw new IllegalStateException("Missing dynamic tag: 0x" + Long.toHexString(tag));
        return val;
    }
    private String readCString(long address, long maxlen) {
        int limit = (int) Math.min(maxlen, 4096);
        byte[] bytes = emulator.getBackend().mem_read(address, limit);
        int len = 0;
        while (len < bytes.length && bytes[len] != 0) len++;
        return new String(bytes, 0, len, StandardCharsets.UTF_8);
    }
    private static Set<String> diff(Set<String> expected, Set<String> actual) {
        Set<String> missing = new HashSet<>(expected);
        missing.removeAll(actual);
        return missing;
    }

    private ByteArray bytes(String value) {
        /*
         * 将字符串转为ByteArray（byte[]）。
         * @param values 字符串
         * @return ByteArray（byte[]）
         */
        return new ByteArray(emuvm, value.getBytes(StandardCharsets.UTF_8));
    }
    public String signPost(
            String url,
            String body,
            Map<String, String> headers
    ){
        /*
         为POST请求url签名。
         * @param url 原url
         * @param body 请求内容
         * @param headers 请求头
         * @return 签名过的url
         */
        // 初始化headers的key和value ArrayObject
        ArrayObject keys = null;
        ArrayObject values = null;
        if (headers != null) {
            // 请求头不为空，进行转化
            DvmObject<?>[] keyobjs = new DvmObject<?>[headers.size()];
            DvmObject<?>[] valobjs = new DvmObject<?>[headers.size()];

            int i = 0;
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                keyobjs[i] = bytes(entry.getKey());
                valobjs[i] = bytes(entry.getValue());
                i++;
            }
            // dump到ArrayObject
            keys = new ArrayObject(keyobjs);
            values = new ArrayObject(valobjs);
        }

        // 将参数丢给libnep.so
        DvmObject<?> result = nepTools.callStaticJniMethodObject(
                emulator,
                "getPostMethodSignatures([B[B[Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/String;",
                bytes(url),
                bytes(body),
                keys,
                values
        );

        // 获取结果并返回
        return result == null ? null : (String) result.getValue();
    }
    public String signGet(
            String url,
            Map<String, String> headers
    ){
        /*
         为GET请求url签名。
         * @param url 原url
         * @param headers 请求头
         * @return 签名过的url
         */
        // 初始化headers的key和value ArrayObject
        ArrayObject keys = null;
        ArrayObject values = null;
        if (headers != null) {
            // 请求头不为空，进行转化
            DvmObject<?>[] keyobjs = new DvmObject<?>[headers.size()];
            DvmObject<?>[] valobjs = new DvmObject<?>[headers.size()];

            int i = 0;
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                keyobjs[i] = bytes(entry.getKey());
                valobjs[i] = bytes(entry.getValue());
                i++;
            }
            // dump到ArrayObject
            keys = new ArrayObject(keyobjs);
            values = new ArrayObject(valobjs);
        }

        // 将参数丢给libnep.so
        DvmObject<?> result = nepTools.callStaticJniMethodObject(
                emulator,
                "getGetMethodSignatures([B[Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/String;",
                bytes(url),
                keys,
                values
        );

        // 获取结果并返回
        return result == null ? null : (String) result.getValue();
    }
}
