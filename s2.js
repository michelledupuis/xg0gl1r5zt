'use strict';
const TARGET_PKG      = 'com.app.ecobank';
const TARGET_LIB      = 'libdexprotector.so';
const DUMP_DIR        = `/data/data/${TARGET_PKG}/files/dp_dumps`;
const TARGET_INIT_RVA                       = ptr('0x3360');
const DP_JNI_ONLOAD_RVA                     = ptr('0x3420');
const DP_JNI_ONLOAD_CALL_HIDDEN_RVA         = ptr('0x3431');
const DP_JNI_ONLOAD_RET_AFTER_HIDDEN_RVA    = ptr('0x3437');
const DP_DWORD_INIT_STATUS_RVA              = ptr('0xbfd0');
const DP_OFF_HIDDEN_ENTRY_RVA               = ptr('0xbfd8');
const DP_VM_INTERPRETER_RVA                 = ptr('0xa40');
const H_SUB_4E354_RVA        = ptr('0x4e354');  
const H_SUB_4E7D8_RVA        = ptr('0x4e7d8');  
const H_QWORD_8CEF0_RVA      = ptr('0x8cef0');  
const H_QWORD_8CEF8_RVA      = ptr('0x8cef8');  
const H_SUB_5E684_RVA        = ptr('0x5e684');  
const H_SUB_54944_RVA        = ptr('0x54944');  
const H_SUB_3EA28_RVA        = ptr('0x3ea28');  
const H_SUB_6A05C_RVA        = ptr('0x6a05c');  
const H_SUB_3F158_RVA        = ptr('0x3f158');  
const H_SUB_20754_RVA        = ptr('0x20754');  
const H_SUB_71844_RVA        = ptr('0x71844');  
const H_SUB_320B4_RVA        = ptr('0x320b4');  
const H_SUB_16190_RVA        = ptr('0x16190');  
const H_SUB_15F44_RVA        = ptr('0x15f44');  
const H_SUB_15DD4_RVA        = ptr('0x15dd4');  
const H_SUB_402E0_RVA        = ptr('0x402e0');  
const H_SUB_4E340_RVA        = ptr('0x4e340');  
const H_SUB_41108_RVA        = ptr('0x41108');  
const H_SUB_4DDB4_RVA        = ptr('0x4ddb4');  
const H_SUB_4E338_RVA        = ptr('0x4e338');  
const H_SUB_54B10_RVA        = ptr('0x54b10');  
const H_SUB_55718_RVA        = ptr('0x55718');  
const H_SUB_56078_S_DECODER_RVA = ptr('0x56078'); 
const H_SUB_51E4C_RVA        = ptr('0x51e4c');  
const H_SUB_53390_RVA        = ptr('0x53390');  
const H_SUB_3601C_RVA        = ptr('0x3601c');  
const H_SUB_3662C_RVA        = ptr('0x3662c');  
const H_SUB_35BE8_RVA        = ptr('0x35be8');  
const H_BYTE_8CB48_RVA       = ptr('0x8cb48');  
const H_THREAD_5CB5C_RVA     = ptr('0x5cb5c');  
const H_THREAD_5D730_RVA     = ptr('0x5d730');  
const CS_AFTER_STORE_QWORD_8CEF0 = ptr('0x4e37c');
const CS_AFTER_SUB3B6D8   = ptr('0x4e424');
const CS_AFTER_SUB363F0   = ptr('0x4e434');
const CS_AFTER_SUB5E38C   = ptr('0x4e468');
const CS_AFTER_SUB63EA8   = ptr('0x4e4b0');
const CS_AFTER_SUB5CB1C   = ptr('0x4e4f0');
const CS_AFTER_SUB5D6F0   = ptr('0x4e4f8');
const CS_AFTER_SUB3601C   = ptr('0x4e514');
const CS_AFTER_SUB3662C   = ptr('0x4e524');
const CS_AFTER_SUB3E038   = ptr('0x4e5c0');
const CS_AFTER_SUB16190   = ptr('0x4e5e8');
const CS_POISON_PATH      = ptr('0x4e5f0');
const CS_AFTER_SUB15DD4   = ptr('0x4e638');
const CS_AFTER_SUB59F40   = ptr('0x4e76c');
const CS_AFTER_SUB36764   = ptr('0x4e78c');
const CS_AFTER_SUB5E684   = ptr('0x4e7a8');
const CS_AFTER_SUB4EB9C   = ptr('0x4e7c8');
const RA_AFTER_OPEN_ICDAT = ptr('0x5e6bc');
const RA_AFTER_DECRYPT    = ptr('0x5e7f0');
const RA_AFTER_DECOMP     = ptr('0x5e860');
const H_SUB_4EB9C_RVA = ptr('0x4eb9c');
const H_SUB_4EFB0_RVA = ptr('0x4efb0');
const CS_4EB9C_AFTER_SUB5B5B8 = ptr('0x4ed30');  
const CS_4EB9C_AFTER_SUB5B740 = ptr('0x4ede0');  
const EXPECTED_MAGIC_4E354 = [0x8f, 0xf9, 0xa6, 0xbe];
const CLEAN_SUB3E038_HASH_LEN = 0x7caa0;
const H_PROTECTED_CODE_START_RVA = ptr('0x10e00');
const H_PROTECTED_CODE_END_RVA   = ptr('0x771e8');
let CLEAN_RBRK_BYTES = null;
let RESOLVED_RDEBUG_ADDR = null;  
const PROP_OVERRIDE_MAP = {
  'ro.build.fingerprint': 'google/google/G011A:9/mv-dev1030410/42:user/release-keys',
  'ro.boot.fingerprint': 'google/google/G011A:9/mv-dev1030410/42:user/release-keys',
  'ro.bootimage.build.fingerprint': 'google/google/G011A:9/mv-dev1030410/42:user/release-keys',
  'ro.vendor.build.fingerprint': 'google/google/G011A:9/mv-dev1030410/42:user/release-keys',
  'ro.product.model': 'G011A',
  'ro.product.brand': 'google',
  'ro.product.name': 'google',
  'ro.product.device': 'G011A',
  'ro.product.manufacturer': 'Google',
  'ro.product.board': 'G011A',
  'ro.board.platform': 'G011A',
  'ro.build.id': 'mv-dev1030410',
  'ro.build.display.id': 'mv-dev1030410',
  'ro.build.tags': 'release-keys',
  'ro.build.type': 'user',
  'ro.build.version.release': '9',
  'ro.build.version.sdk': '28',
  'ro.build.version.incremental': '42',
  'ro.build.version.security_patch': '2025-09-05',
  'ro.build.description': 'G011A-user 9 mv-dev1030410 42 release-keys',
  'ro.build.flavor': 'G011A-user',
  'ro.build.product': 'G011A',
  'ro.product.cpu.abi': 'x86_64',
  'ro.product.cpu.abilist': 'x86_64,x86,arm64-v8a,armeabi-v7a,armeabi',
  'ro.boot.hardware': 'G011A',
  'ro.hardware': 'G011A',
  'ro.boot.serialno': 'EMULATOR36X6X11X0',
  'ro.serialno': 'EMULATOR36X6X11X0',
  'ro.bootmode': 'unknown',
  'ro.boot.mode': 'unknown',
  'ro.build.characteristics': 'nosdcard',
};
const SPOOFED_EPOCH_SECONDS = 1758888000;
const SPOOF_OUTER_KEY                       = true;  
const BYPASS_PRE_ICDAT_CHECKS               = true;  
const FORCE_CLEAN_SUB3E038_DIGEST           = true;  
const BYPASS_SUB16190_FUNC                  = true;  
const BYPASS_SUB55718_INTEGRITY_COMPARE     = true;  
const FORCE_CLASSES_DAT_HASH_MATCH          = true;  
const USE_CLEAN_COPY_FOR_CLASSES_SELECTOR   = true;
const BYPASS_SUB3601C_3662C_BY_FUNCTION     = true;
const SKIP_SUB5E684_AFTER_FIRST_SUCCESS     = true;
const WRAP_SUB5E684_WITH_ORIGINAL           = true;
const BYPASS_EMULATOR_CHECKS                = true;  
const JNI_FIND_CLASS_OFF                = 0x30;
const JNI_GET_METHOD_ID_OFF             = 0x108;
const JNI_GET_STATIC_METHOD_ID_OFF      = 0x388;
const JNI_CALL_STATIC_VOID_METHOD_OFF   = 0x468;
const JNI_REGISTER_NATIVES_OFF          = 0x6b8;
const JNI_GET_STRING_UTF_CHARS_OFF      = 0x548;
const JNI_RELEASE_STRING_UTF_CHARS_OFF  = 0x550;
const JNI_NEW_STRING_UTF_OFF            = 0x538;
const JNI_EXCEPTION_CHECK_OFF           = 0x720;
const JNI_EXCEPTION_CLEAR_OFF           = 0x88;
const JNI_GET_OBJECT_CLASS_OFF          = 0xf8;
const JNI_CALL_OBJECT_METHOD_OFF        = 0x110;
const JNI_DELETE_LOCAL_REF_OFF          = 0xb8;
const JNI_NEW_GLOBAL_REF_OFF            = 0xa8;
const JNI_FROM_REFLECTED_METHOD_OFF     = 0x38;
const JNI_FROM_REFLECTED_FIELD_OFF      = 0x40;
const JNI_NEW_INT_ARRAY_OFF             = 0x598;
const JNI_GET_STATIC_FIELD_ID_OFF       = 0x480;
const JNI_EXCEPTION_OCCURRED_OFF        = 0x78;
const JVM_GET_ENV_OFF                   = 0x30;
const JNI_VERSION_1_4                   = 0x00010004;
const JNI_VERSION_1_6                   = 0x00010006;
const installedOuterBases  = new Set();
const installedHiddenBases = new Set();
const hooked               = new Set();
const blockedWatchdogThreadStarts = {};
let pthreadCreateBlockerInstalled  = false;
let pthreadDetachZeroBlockerInstalled = false;
let hiddenBase                          = null;
let runtimeCleanHiddenImageCopy         = null;
let runtimeCleanSub3E038DigestBytes     = null;
let runtimeCleanSub16190Hash            = null;
let sub16190FuncHookInstalled           = false;
let sub5e684HadSuccess                  = false;
let outerHiddenReturnAddress            = null;
let pendingHiddenLoadBias               = null;
let seq = 0;
const IMPORTANT_LOG_PATTERNS = [
  '[start]', '[linker call_constructors]', `[${TARGET_LIB}]`,
  '[VM enter]', '[VM leave]', '[ctor enter]', '[ctor leave]',
  '[JNI_OnLoad enter]', '[JNI_OnLoad leave]', '[JNI_OnLoad pre-hidden]',
  '[JNI_OnLoad post-hidden]',
  '[hidden]', '[hooked]', '[replaced]', '[DUMP]',
  '[runtime clean hidden snapshot]', '[runtime clean sub_3E038 digest]',
  '[runtime clean sub_16190]', '[sub_16190 spoof protected]',
  '[precheck SKIP]', '[watchdog BLOCK]',
  '[ic.dat decrypt', '[ic.dat decrypted]', '[ic.dat decompress',
  '[ic.dat decompressed]', '[ic.dat parsed]',
  '[DPMP3 decrypt', '[DPMP3 decrypted]', '[DPMP3 decompress',
  '[DPMP3 decompressed]', '[DPMP3 hash clean-copy]',
  '[classes.ecobank.dat selector',
  '[sub_55718 HMAC', 'RegisterNatives', 'name="s"',
  '[emulator check SKIP]',
];
function installPropSpoofHooks() {
  const T = PROP_OVERRIDE_MAP;
  function spoofVal(name) {
    if (Object.prototype.hasOwnProperty.call(T, name)) return T[name];
    return null;
  }
  try {
    const p = Module.findExportByName(null, '__system_property_get');
    if (p) {
      Interceptor.attach(p, {
        onEnter(args) { this.name = args[0].readCString(); this.val = args[1]; },
        onLeave(retval) {
          if (!this.name) return;
          const v = spoofVal(this.name);
          if (v === null) return;
          const bytes = [];
          for (let i = 0; i < v.length; i++) bytes.push(v.charCodeAt(i) & 0xff);
          bytes.push(0);
          try { for (let i = 0; i < bytes.length; i++) this.val.add(i).writeU8(bytes[i]); } catch (_) {}
          retval.replace(bytes.length - 1);
        }
      });
      log(`[prop-spoof] hooked __system_property_get (${Object.keys(T).length} properties)`);
    }
  } catch (e) { warn(`[prop-spoof] __system_property_get hook failed: ${e}`); }
  try {
    const p = Module.findExportByName(null, '__system_property_read_callback');
    if (p) {
      Interceptor.attach(p, {
        onEnter(args) { this.pi = args[0]; this.cb = args[1]; this.ctx = args[2]; },
        onLeave(retval) {}
      });
    }
  } catch (e) {}
}
function installTimeSpoofHooks() {
  const T = SPOOFED_EPOCH_SECONDS;
  try {
    const p = Module.findExportByName(null, 'time');
    if (p) {
      Interceptor.attach(p, {
        onEnter(args) { this.outPtr = args[0]; },
        onLeave(retval) {
          retval.replace(T);
          if (this.outPtr && !this.outPtr.isNull()) {
            try { this.outPtr.writeU64(T); } catch (_) {}
          }
        }
      });
      log(`[time-spoof] hooked time() -> ${T}`);
    }
  } catch (e) { warn(`[time-spoof] time hook failed: ${e}`); }
  try {
    const p = Module.findExportByName(null, 'gettimeofday');
    if (p) {
      Interceptor.attach(p, {
        onEnter(args) { this.tv = args[0]; },
        onLeave(retval) {
          if (this.tv && !this.tv.isNull()) {
            try {
              this.tv.writeU64(T);
              this.tv.add(8).writeU64(0);
            } catch (_) {}
          }
          retval.replace(0);
        }
      });
      log(`[time-spoof] hooked gettimeofday()`);
    }
  } catch (e) { warn(`[time-spoof] gettimeofday hook failed: ${e}`); }
  try {
    const p = Module.findExportByName(null, 'clock_gettime');
    if (p) {
      Interceptor.attach(p, {
        onEnter(args) { this.clk = args[0].toInt32(); this.tp = args[1]; },
        onLeave(retval) {
          if (this.clk === 0 && this.tp && !this.tp.isNull()) {
            try {
              this.tp.writeU64(T);
              this.tp.add(8).writeU64(0);
            } catch (_) {}
          }
        }
      });
      log(`[time-spoof] hooked clock_gettime() (CLOCK_REALTIME only)`);
    }
  } catch (e) { warn(`[time-spoof] clock_gettime hook failed: ${e}`); }
}
function log(s) {
  s = String(s);
  for (const pat of IMPORTANT_LOG_PATTERNS) {
    if (s.indexOf(pat) !== -1) { console.log(s); return; }
  }
}
function warn(s) { console.warn(String(s)); }
function hexBytes(b) {
  if (b === null) return '<read failed>';
  return Array.from(new Uint8Array(b))
    .map(x => ('0' + (x & 0xff).toString(16)).slice(-2)).join('');
}
function bytesEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if ((a[i] & 0xff) !== (b[i] & 0xff)) return false;
  return true;
}
function readBytes(p, n) {
  try {
    if (!p || p.isNull() || n <= 0) return null;
    return Array.from(new Uint8Array(p.readByteArray(n)));
  } catch (_) { return null; }
}
function tryWriteBytes(p, bytes) {
  try { p.writeByteArray(new Uint8Array(bytes).buffer); return true; } catch (_) { return false; }
}
function ptrEq(a, b) { try { return a.compare(b) === 0; } catch (_) { return false; } }
function safeCString(p) {
  try { if (!p || p.isNull()) return null; return p.readCString(); } catch (_) { return null; }
}
function readU64Ptr(p) { try { return p.readPointer(); } catch (_) { return null; } }
function u64ToSafeNumber(v) {
  try { const n = v.toNumber(); if (Number.isSafeInteger(n)) return n; } catch (_) {}
  try { return v.toUInt32(); } catch (_) {}
  return -1;
}
function bytesToAscii(bs) {
  if (!bs) return '<read failed>';
  let s = '';
  for (let i = 0; i < bs.length; i++) {
    const c = bs[i] & 0xff;
    s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
  }
  return s;
}
function moduleDesc(p) {
  try {
    const m = Process.findModuleByAddress(p);
    if (m) return `${m.name}+0x${p.sub(m.base).toString(16)}`;
  } catch (_) {}
  if (hiddenBase) {
    try {
      const off = p.sub(hiddenBase);
      if (off.compare(ptr(0)) >= 0 && off.compare(ptr('0x1000000')) < 0)
        return `hidden+0x${off.toString(16)}`;
    } catch (_) {}
  }
  return String(p);
}
function findExport(name) {
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(null, name); } catch (_) {}
  }
  if (typeof Module.findGlobalExportByName === 'function') {
    try { return Module.findGlobalExportByName(name); } catch (_) {}
  }
  return null;
}
function attachOnce(addr, label, handlers) {
  const k = `${label}@${addr}`;
  if (hooked.has(k)) return;
  try { Interceptor.attach(addr, handlers); hooked.add(k); log(`[hooked] ${label} @ ${addr}`); }
  catch (e) { warn(`[hook FAIL] ${label} @ ${addr}: ${e}`); }
}
function replaceOnce(addr, label, callback) {
  const k = `replace:${label}@${addr}`;
  if (hooked.has(k)) return;
  try { Interceptor.replace(addr, callback); hooked.add(k); log(`[replaced] ${label} @ ${addr}`); }
  catch (e) { warn(`[replace FAIL] ${label} @ ${addr}: ${e}`); }
}
function findLinkerModule() {
  const want = Process.pointerSize === 8 ? 'linker64' : 'linker';
  const mods = Process.enumerateModules();
  return mods.find(m => m.name === want) ||
         mods.find(m => /\/(linker64|linker)$/.test(m.path)) ||
         mods.find(m => m.name.indexOf('linker') !== -1);
}
function enumSymbols(m) {
  if (m && typeof m.enumerateSymbols === 'function') return m.enumerateSymbols();
  if (typeof Module.enumerateSymbolsSync === 'function') return Module.enumerateSymbolsSync(m.name);
  if (typeof Module.enumerateSymbols === 'function') return Module.enumerateSymbols(m.name);
  throw new Error('No symbol enumeration API available');
}
function findRDebugStructure() {
  const linker = findLinkerModule();
  if (!linker) return null;
  let syms; try { syms = enumSymbols(linker); } catch (_) { return null; }
  const candidates = [
    '__dl__r_debug', '_r_debug', '__dl_r_debug',
    '__dl__ZL12r_debug_tail', 'r_debug_tail'
  ];
  for (const name of candidates) {
    const sym = syms.find(s => s.name === name);
    if (!sym) continue;
    try {
      const rVersion = sym.address.readU32();
      if (rVersion !== 1) continue;
      const rBrk = sym.address.add(0x10).readPointer();
      if (rBrk.isNull() ||
          rBrk.compare(linker.base) < 0 ||
          rBrk.compare(linker.base.add(linker.size)) >= 0) continue;
      log(`[r_debug] resolved via symbol ${name} @ ${sym.address}  r_brk=${rBrk}`);
      return { rdebug: sym.address, rbrk: rBrk };
    } catch (_) { continue; }
  }
  return null;
}
function captureCleanRBrkBytes() {
  const linker = findLinkerModule();
  if (!linker) { warn('linker64 not found'); return null; }
  const rdebugInfo = findRDebugStructure();
  if (rdebugInfo) {
    const bytes = readBytes(rdebugInfo.rbrk, 4);
    if (bytes) {
      log(`captured CLEAN r_brk bytes @ ${rdebugInfo.rbrk} (via r_debug struct) = ${hexBytes(bytes)}`);
      RESOLVED_RDEBUG_ADDR = rdebugInfo.rdebug;
      return bytes;
    }
  }
  let syms; try { syms = enumSymbols(linker); } catch (e) { return null; }
  const sym = syms.find(s => s.type === 'function' &&
    (s.name === '_rtld_debug_state' || s.name === 'rtld_db_dlactivity'));
  if (!sym) return null;
  const bytes = readBytes(sym.address, 4);
  log(`captured CLEAN r_brk bytes @ ${sym.address} = ${hexBytes(bytes)}`);
  return bytes;
}
function readRDebug(rdebug) {
  if (!rdebug || rdebug.isNull()) return null;
  try {
    const rbrk = rdebug.add(0x10).readPointer();
    return { rbrk, bytes4: readBytes(rbrk, 4) };
  } catch (_) { return null; }
}
function fixOuterKey(finalKey, liveRBrk4, cleanRBrk4) {
  const fixed = finalKey.slice();
  fixed[0]  ^= (liveRBrk4[0] ^ cleanRBrk4[0]);
  fixed[4]  ^= (liveRBrk4[1] ^ cleanRBrk4[1]);
  fixed[8]  ^= (liveRBrk4[2] ^ cleanRBrk4[2]);
  fixed[12] ^= (liveRBrk4[3] ^ cleanRBrk4[3]);
  return fixed;
}
function mkdirP(path) {
  const parts = path.split('/');
  let cur = '';
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p === '') { cur = '/'; continue; }
    cur = cur === '/' ? '/' + p : cur + '/' + p;
    try {
      const fn = Module.findGlobalExportByName
        ? Module.findGlobalExportByName('mkdir')
        : Module.findExportByName(null, 'mkdir');
      if (fn) new NativeFunction(fn, 'int', ['pointer', 'int'])(Memory.allocUtf8String(cur), 0x1c0);
    } catch (_) {}
  }
}
function mkdirOne(path) {
  try {
    const p = findExport('mkdir'); if (!p) return false;
    new NativeFunction(p, 'int', ['pointer', 'int'])(Memory.allocUtf8String(path), 0x1c0);
    return true;
  } catch (_) { return false; }
}
function dumpMemoryToFile(name, addr, len) {
  mkdirP(DUMP_DIR);
  const path = `${DUMP_DIR}/${name}`;
  const f = new File(path, 'wb');
  let written = 0, skipped = 0;
  try {
    let ab = null;
    try { ab = addr.readByteArray(len); } catch (_) { ab = null; }
    if (ab !== null) {
      f.write(ab);
      written = len;
    } else {
      const PAGE = 0x1000;
      const zeros = new Uint8Array(PAGE);
      for (let off = 0; off < len; off += PAGE) {
        const chunk = Math.min(PAGE, len - off);
        try {
          f.write(addr.add(off).readByteArray(chunk));
          written += chunk;
        } catch (_) {
          f.write(zeros.buffer.slice(0, chunk));
          skipped += chunk;
        }
      }
    }
    f.flush();
  } finally { f.close(); }
  log(`[DUMP] ${name} addr=${addr} len=0x${len.toString(16)} written=0x${written.toString(16)} skipped=0x${skipped.toString(16)} -> ${path}`);
}
function dumpPreview(tag, addr, len) {
  const n = Math.min(len, 0x80);
  const b = readBytes(addr, n);
  log(`[${tag}] first_${n}=${hexBytes(b)}`);
}
function installWatchdogThreadBlocker(loadBias) {
  const starts = [
    [loadBias.add(H_THREAD_5CB5C_RVA), 'sub_5CB5C'],
    [loadBias.add(H_THREAD_5D730_RVA), 'sub_5D730'],
  ];
  starts.forEach(([addr, label]) => { blockedWatchdogThreadStarts[addr.toString()] = label; });
  if (!pthreadCreateBlockerInstalled) {
    const pCreate = findExport('pthread_create');
    if (pCreate) {
      const realCreate = new NativeFunction(pCreate, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
      Interceptor.replace(pCreate, new NativeCallback(function (threadPtr, attr, start, arg) {
        const label = blockedWatchdogThreadStarts[start.toString()];
        if (label !== undefined) {
          if (!threadPtr.isNull()) threadPtr.writePointer(ptr(0));
          log(`[watchdog BLOCK] pthread_create start=${moduleDesc(start)} ${label} -> 0`);
          return 0;
        }
        return realCreate(threadPtr, attr, start, arg);
      }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
      pthreadCreateBlockerInstalled = true;
      log(`[hooked] pthread_create selective blocker`);
    }
  }
  if (!pthreadDetachZeroBlockerInstalled) {
    const pDetach = findExport('pthread_detach');
    if (pDetach) {
      const realDetach = new NativeFunction(pDetach, 'int', ['pointer']);
      Interceptor.replace(pDetach, new NativeCallback(function (tid) {
        if (tid.isNull()) { log('[watchdog BLOCK] pthread_detach(0) -> 0'); return 0; }
        return realDetach(tid);
      }, 'int', ['pointer']));
      pthreadDetachZeroBlockerInstalled = true;
      log(`[hooked] pthread_detach zero blocker`);
    }
  }
}
function snapshotRuntimeCleanHiddenImage(loadBias) {
  if (runtimeCleanHiddenImageCopy) return runtimeCleanHiddenImageCopy;
  try {
    runtimeCleanHiddenImageCopy = Memory.alloc(CLEAN_SUB3E038_HASH_LEN);
    Memory.copy(runtimeCleanHiddenImageCopy, loadBias, CLEAN_SUB3E038_HASH_LEN);
    log(`[runtime clean hidden snapshot] src=${loadBias} dst=${runtimeCleanHiddenImageCopy} len=0x${CLEAN_SUB3E038_HASH_LEN.toString(16)}`);
  } catch (e) {
    runtimeCleanHiddenImageCopy = null;
    warn(`[runtime clean hidden snapshot] failed: ${e}`);
  }
  return runtimeCleanHiddenImageCopy;
}
function computeRuntimeCleanSub3E038Digest(loadBias) {
  if (!FORCE_CLEAN_SUB3E038_DIGEST) return null;
  if (runtimeCleanSub3E038DigestBytes) return runtimeCleanSub3E038DigestBytes;
  try {
    snapshotRuntimeCleanHiddenImage(loadBias);
    const out = Memory.alloc(32);
    const hashFn = new NativeFunction(
      loadBias.add(H_SUB_320B4_RVA), 'int',
      ['pointer', 'ulong', 'pointer', 'pointer']);
    const ret = hashFn(loadBias, CLEAN_SUB3E038_HASH_LEN, out, ptr(0));
    runtimeCleanSub3E038DigestBytes = readBytes(out, 32);
    if (runtimeCleanSub3E038DigestBytes) {
      log(`[runtime clean sub_3E038 digest] ret=${ret} digest=${hexBytes(runtimeCleanSub3E038DigestBytes)}`);
    }
  } catch (e) { warn(`[runtime clean sub_3E038 digest] failed: ${e}`); }
  return runtimeCleanSub3E038DigestBytes;
}
function computeRuntimeCleanSub16190Hash(loadBias) {
  if (!BYPASS_SUB16190_FUNC) return null;
  if (runtimeCleanSub16190Hash) return runtimeCleanSub16190Hash;
  try {
    const key = Memory.alloc(16);
    key.writeByteArray(new Uint8Array(16).buffer);
    const start = loadBias.add(H_PROTECTED_CODE_START_RVA);
    const len = H_PROTECTED_CODE_END_RVA.sub(H_PROTECTED_CODE_START_RVA).toUInt32();
    const siphash = new NativeFunction(
      loadBias.add(H_SUB_16190_RVA), 'pointer',
      ['pointer', 'ulong', 'pointer']);
    runtimeCleanSub16190Hash = siphash(start, len, key);
    log(`[runtime clean sub_16190] data=${start} len=0x${len.toString(16)} hash=${runtimeCleanSub16190Hash}`);
  } catch (e) { warn(`[runtime clean sub_16190] failed: ${e}`); }
  return runtimeCleanSub16190Hash;
}
function installHiddenHooks(loadBias) {
  const key = loadBias.toString();
  if (installedHiddenBases.has(key)) return;
  installedHiddenBases.add(key);
  hiddenBase = loadBias;
  mkdirP(DUMP_DIR);
  log(`[hidden] load_bias=${loadBias}`);
  installWatchdogThreadBlocker(loadBias);
  
  if (FORCE_CLEAN_SUB3E038_DIGEST) {
    const digestBytes = runtimeCleanSub3E038DigestBytes;
    if (digestBytes) {
      const addr = loadBias.add(H_SUB_320B4_RVA);
      Interceptor.attach(addr, {
        onEnter(args) {
          this.data = this.context.rdi;
          this.len  = u64ToSafeNumber(this.context.rsi);
          this.out  = this.context.rdx;
          this.flag = this.context.rcx;
          this.isSub3E038 = (this.len === CLEAN_SUB3E038_HASH_LEN && ptrEq(this.data, loadBias));
        },
        onLeave(retval) {
          if (!this.isSub3E038) return;
          const real = readBytes(this.out, 32);
          tryWriteBytes(this.out, digestBytes);
          log(`[sub_320B4/sub_3E038 force digest] real=${hexBytes(real)} clean=${hexBytes(digestBytes)}`);
        }
      });
      log(`[hooked] sub_320B4 self-hash redirect @ ${addr}`);
    }
  }
  
  if (BYPASS_SUB16190_FUNC && !sub16190FuncHookInstalled) {
    const expected = runtimeCleanSub16190Hash || readU64Ptr(loadBias.add(H_QWORD_8CEF8_RVA));
    const targetData = loadBias.add(H_PROTECTED_CODE_START_RVA);
    const targetLen = H_PROTECTED_CODE_END_RVA.sub(H_PROTECTED_CODE_START_RVA).toUInt32();
    if (expected) {
      Interceptor.attach(loadBias.add(H_SUB_16190_RVA), {
        onEnter(args) {
          this.data = this.context.rdi;
          this.len  = u64ToSafeNumber(this.context.rsi);
          this.key  = this.context.rdx;
          this.match = ptrEq(this.data, targetData) && this.len === targetLen;
        },
        onLeave(retval) {
          if (!this.match) return;
          const real = ptr(retval);
          retval.replace(expected);
          log(`[sub_16190 spoof protected] real=${real} -> ${expected}`);
        }
      });
      sub16190FuncHookInstalled = true;
      log(`[hooked] sub_16190 spoof @ ${loadBias.add(H_SUB_16190_RVA)}`);
    }
  }
  
  if (BYPASS_PRE_ICDAT_CHECKS) {
    const addr = loadBias.add(ptr('0x5c4a4'));  
    replaceOnce(addr, 'sub_5C4A4 anti-Frida -> 0', new NativeCallback(function () {
      try { loadBias.add(ptr('0x8a0d4')).writeU8(0); } catch (_) {}
      try {
        if (outerHiddenReturnAddress) {
          loadBias.add(H_QWORD_8CEF0_RVA).writePointer(outerHiddenReturnAddress);
        }
      } catch (_) {}
      log('[precheck SKIP] sub_5C4A4 -> 0');
      return 0;
    }, 'int', []));
  }
  
  
  if (BYPASS_EMULATOR_CHECKS) {
    [
      ['sub_5B5B8 emulator check 1', ptr('0x5b5b8')],  
      ['sub_5B740 emulator check 2', ptr('0x5b740')],  
    ].forEach(([label, rva]) => {
      const addr = loadBias.add(rva);
      replaceOnce(addr, `${label} -> 0`, new NativeCallback(function () {
        log(`[emulator check SKIP] ${label} -> 0`);
        return 0;
      }, 'int', []));
    });
  }
  
  if (BYPASS_SUB3601C_3662C_BY_FUNCTION) {
    [H_SUB_3601C_RVA, H_SUB_3662C_RVA].forEach((rva, i) => {
      attachOnce(loadBias.add(rva), `sub_36${i ? '62C' : '01C'} -> zero`, {
        onLeave(retval) {
          const v = retval.toInt32();
          if (v !== 0) { log(`[function BYPASS] sub_36${i ? '62C' : '01C'} ret=${v} -> 0`); retval.replace(0); }
        }
      });
    });
  }
  
  if (WRAP_SUB5E684_WITH_ORIGINAL) {
    const sub5e684 = loadBias.add(H_SUB_5E684_RVA);
    let origSub5e684 = null;
    const wrapper = new NativeCallback(function (ctx) {
      const id = ++seq;
      if (SKIP_SUB5E684_AFTER_FIRST_SUCCESS && sub5e684HadSuccess) {
        log(`[sub_5E684 wrapper skip #${id}] -> 0`);
        return 0;
      }
      log(`[sub_5E684 wrapper enter #${id}] ctx=${ctx}`);
      const ret = origSub5e684(ctx);
      log(`[sub_5E684 wrapper leave #${id}] ret=${ret}`);
      if (ret === 0) sub5e684HadSuccess = true;
      return ret;
    }, 'int', ['pointer']);
    try {
      if (typeof Interceptor.replaceFast === 'function') {
        const origPtr = Interceptor.replaceFast(sub5e684, wrapper);
        origSub5e684 = new NativeFunction(origPtr, 'int', ['pointer']);
        log(`[replaced-fast] sub_5E684 wrapper @ ${sub5e684} orig=${origPtr}`);
      } else {
        origSub5e684 = new NativeFunction(sub5e684, 'int', ['pointer']);
        Interceptor.replace(sub5e684, wrapper);
        log(`[replaced] sub_5E684 wrapper @ ${sub5e684}`);
      }
    } catch (e) { warn(`sub_5E684 wrapper replace failed: ${e}`); }
  }
  
  attachOnce(loadBias.add(H_SUB_54944_RVA), 'sub_54944 open asset', {
    onEnter(args) {
      this.id  = this.context.rdi.toInt32();
      this.out = this.context.rsi;
      this.fromIc = ptrEq(this.context.rip, loadBias.add(RA_AFTER_OPEN_ICDAT));
    },
    onLeave(retval) {
      if (!this.fromIc || this.id !== 6) return;
      const ret = retval.toInt32();
      log(`[ic.dat raw open] ret=${ret}`);
      if (ret !== 0) return;
      try {
        const base = this.out.readPointer();
        const size = this.out.add(Process.pointerSize).readPointer().toUInt32();
        log(`[ic.dat raw] base=${base} size=0x${size.toString(16)}`);
        dumpMemoryToFile('ic_raw_encrypted_asset.bin', base, size);
      } catch (e) { warn(`[ic.dat raw] dump failed: ${e}`); }
    }
  });
  
  attachOnce(loadBias.add(H_SUB_20754_RVA), 'sub_20754 AEAD decrypt', {
    onEnter(args) {
      this.fromIc = ptrEq(this.context.rip, loadBias.add(RA_AFTER_DECRYPT));
      if (!this.fromIc) return;
      
      this.len   = this.context.rsi.toUInt32();
      this.tag   = this.context.rsp.readPointer();  
      this.input = this.context.rsp.add(8).readPointer();
      this.out   = this.context.rsp.add(16).readPointer();
      log(`[ic.dat decrypt enter] len=0x${this.len.toString(16)} in=${this.input} out=${this.out}`);
    },
    onLeave(retval) {
      if (!this.fromIc) return;
      const ret = retval.toInt32();
      log(`[ic.dat decrypt leave] ret=${ret}`);
      if (ret !== 0) return;
      try {
        const decompSize = this.out.readU32() >>> 0;
        const compSize = Math.max(0, this.len - 4);
        log(`[ic.dat decrypted] decomp_size=0x${decompSize.toString(16)} comp_size=0x${compSize.toString(16)}`);
        dumpMemoryToFile('ic_decrypted_with_size_and_compressed.bin', this.out, this.len);
        if (compSize > 0) {
          dumpMemoryToFile('ic_decrypted_compressed_payload.bin', this.out.add(4), compSize);
        }
      } catch (e) { warn(`[ic.dat decrypted] dump failed: ${e}`); }
    }
  });
  
  attachOnce(loadBias.add(H_SUB_71844_RVA), 'sub_71844 inflate', {
    onEnter(args) {
      this.fromIc = ptrEq(this.context.rip, loadBias.add(RA_AFTER_DECOMP));
      if (!this.fromIc) return;
      this.out      = this.context.rdi;
      this.expected = this.context.rsi.toUInt32();
      this.comp     = this.context.rdx;
      this.compLen  = this.context.rcx.toUInt32();
    },
    onLeave(retval) {
      if (!this.fromIc) return;
      const written = retval.toUInt32();
      log(`[ic.dat decompress leave] written=0x${written.toString(16)} expected=0x${this.expected.toString(16)}`);
      const len = Math.min(written, this.expected);
      if (len <= 0) return;
      try {
        dumpMemoryToFile('ic_decompressed.bin', this.out, len);
        if (len >= 0x24) {
          const key0 = readBytes(this.out, 16);
          const expectedHash = this.out.add(0x18).readU64();
          const count = this.out.add(0x20).readU32();
          log(`[ic.dat parsed] siphash_key16=${hexBytes(key0)} expected_hash=${expectedHash} entry_count=${count}`);
        }
      } catch (e) { warn(`[ic.dat decompressed] dump failed: ${e}`); }
    }
  });
  
  if (BYPASS_SUB55718_INTEGRITY_COMPARE) {
    attachOnce(loadBias.add(H_SUB_15F44_RVA), 'sub_55718 HMAC clean-snapshot redirect', {
      onEnter(args) {
        this.enabled = false;
        this.caller = this.context.rip;  
        const keyLen = u64ToSafeNumber(this.context.rsi);
        const data   = this.context.rdx;
        const len    = u64ToSafeNumber(this.context.rcx);
        this.enabled = (keyLen === 0) && ptrEq(data, loadBias) &&
          (len === CLEAN_SUB3E038_HASH_LEN) && runtimeCleanHiddenImageCopy;
        if (!this.enabled) return;
        this.origData = data;
        this.out = this.context.r8;
        this.context.rdx = runtimeCleanHiddenImageCopy;
        log(`[sub_55718 HMAC redirect] data ${this.origData} -> ${runtimeCleanHiddenImageCopy}`);
      },
      onLeave(retval) { if (this.enabled) log(`[sub_55718 HMAC leave] ret=${retval}`); }
    });
  }
  
  if (FORCE_CLASSES_DAT_HASH_MATCH) {
    attachOnce(loadBias.add(H_SUB_6A05C_RVA), 'sub_6A05C classes.dat selector', {
      onEnter(args) {
        this.enabled = false;
        this.caller = this.context.rip;
        const data = this.context.rdi;
        const len  = u64ToSafeNumber(this.context.rsi);
        this.enabled = ptrEq(data, loadBias) &&
          (len === CLEAN_SUB3E038_HASH_LEN) &&
          (USE_CLEAN_COPY_FOR_CLASSES_SELECTOR && runtimeCleanHiddenImageCopy);
        if (!this.enabled) return;
        this.originalData = data;
        this.context.rdi = runtimeCleanHiddenImageCopy;
        log(`[classes.ecobank.dat selector clean-copy] arg0 ${data} -> ${runtimeCleanHiddenImageCopy}`);
      }
    });
  }
  
  attachOnce(loadBias.add(H_SUB_4E354_RVA), 'sub_4E354 hidden native entry', {
    onEnter(args) {
      this.id = ++seq;
      log(`\n[sub_4E354 enter #${this.id}] env=${this.context.rdi} caller=${moduleDesc(this.context.rsp.readPointer())}`);
    },
    onLeave(retval) { log(`[sub_4E354 leave #${this.id}] ret=${retval}`); }
  });
}
function installOuterHooks(libPath) {
  let m = Process.findModuleByName(TARGET_LIB);
  if (!m) m = Process.enumerateModules().find(x => x.path === libPath);
  if (!m) return;
  const base = m.base;
  log(`[${TARGET_LIB}] base=${base} path=${m.path}`);
  outerHiddenReturnAddress = base.add(DP_JNI_ONLOAD_RET_AFTER_HIDDEN_RVA);
  
  attachOnce(base.add(DP_VM_INTERPRETER_RVA), 'VM interpreter (sub_918 equiv)', {
    onEnter(args) {
      this.tid    = this.threadId;
      this.out    = this.context.rdi;
      this.rdebug = RESOLVED_RDEBUG_ADDR || this.context.rsi;
      this.info   = readRDebug(this.rdebug);
    },
    onLeave(retval) {
      if (!this.info || !CLEAN_RBRK_BYTES) return;
      const finalKey = readBytes(this.out, 32);
      if (!finalKey) return;
      const corrected = fixOuterKey(finalKey, this.info.bytes4, CLEAN_RBRK_BYTES);
      tryWriteBytes(this.out, corrected);
      log(`[VM leave] corrected_key=${hexBytes(corrected)}`);
    }
  });
  
  attachOnce(base.add(DP_JNI_ONLOAD_RVA), 'JNI_OnLoad', {
    onEnter(args) {
      log(`\n[JNI_OnLoad enter] vm=${this.context.rdi}`);
      try {
        const status = base.add(DP_DWORD_INIT_STATUS_RVA).readS32();
        const entry  = base.add(DP_OFF_HIDDEN_ENTRY_RVA).readPointer();
        log(`  init_status=${status}  hidden_entry=${entry}`);
        if (!entry.isNull()) {
          
          const loadBias = entry.sub(H_SUB_4E354_RVA);
          log(`  computed load_bias=${loadBias}  (entry - H_SUB_4E354_RVA)`);
          if (pendingHiddenLoadBias === null) {
            pendingHiddenLoadBias = loadBias;
            computeRuntimeCleanSub3E038Digest(loadBias);
            computeRuntimeCleanSub16190Hash(loadBias);
            installHiddenHooks(loadBias);
          }
        }
      } catch (_) {}
    },
    onLeave(retval) {
      log(`[JNI_OnLoad leave] ret=${retval}  signed=${retval.toInt32()}`);
    }
  });
  
  attachOnce(base.add(DP_JNI_ONLOAD_CALL_HIDDEN_RVA), 'JNI_OnLoad pre-hidden', {
    onEnter() {
      log(`[JNI_OnLoad pre-hidden] rip=${this.context.rip}  rax=${this.context.rax}`);
    }
  });
  
  attachOnce(base.add(DP_JNI_ONLOAD_RET_AFTER_HIDDEN_RVA), 'JNI_OnLoad post-hidden', {
    onEnter() {
      log(`[JNI_OnLoad post-hidden] hidden_ret=${this.context.rax}`);
    }
  });
  
  attachOnce(base.add(TARGET_INIT_RVA), '.init_array ctor', {
    onEnter() { log(`\n[ctor enter] libdexprotector.so+0x3360`); },
    onLeave(retval) {
      try {
        const status = base.add(DP_DWORD_INIT_STATUS_RVA).readS32();
        const entry  = base.add(DP_OFF_HIDDEN_ENTRY_RVA).readPointer();
        log(`[ctor leave] ret=${retval}  init_status=${status}  hidden_entry=${entry}`);
      } catch (_) {}
    }
  });
}
function installLinkerConstructorHooks() {
  const linker = findLinkerModule();
  if (!linker) { warn('linker64 not found'); return; }
  log(`[start] linker=${linker.name} base=${linker.base}`);
  let syms;
  try { syms = enumSymbols(linker); } catch (e) { warn(`enum linker syms failed: ${e}`); return; }
  const ctorSyms = syms.filter(s => s.type === 'function' &&
    s.name.indexOf('call_constructors') !== -1 &&
    s.name.indexOf('call_pre_init') === -1 &&
    s.name.indexOf('call_destructors') === -1);
  const getRealpathSym = syms.find(s => s.type === 'function' &&
    s.name.indexOf('soinfo') !== -1 && s.name.indexOf('get_realpath') !== -1);
  const getRealpath = getRealpathSym
    ? new NativeFunction(getRealpathSym.address, 'pointer', ['pointer']) : null;
  ctorSyms.forEach(s => {
    Interceptor.attach(s.address, {
      onEnter(args) {
        const si = this.context.rdi;
        let path = `<soinfo ${si}>`;
        if (getRealpath) {
          try { const p = getRealpath(si); if (!p.isNull()) path = p.readCString() || path; } catch (_) {}
        }
        if (path.indexOf(TARGET_LIB) !== -1) {
          log(`[linker call_constructors] target=${path}`);
          installOuterHooks(path);
        }
      }
    });
  });
  const already = Process.findModuleByName(TARGET_LIB);
  if (already) {
    log(`[start] ${TARGET_LIB} already mapped; installing outer hooks directly`);
    installOuterHooks(already.path);
  }
}
function main() {
  mkdirP(DUMP_DIR);
  
  installPropSpoofHooks();
  installTimeSpoofHooks();
  CLEAN_RBRK_BYTES = captureCleanRBrkBytes();
  installLinkerConstructorHooks();
  log('===========================================================');
  log('Stage 2 full bypass ready.  Make sure you have filled in all');
  log('the H_*_RVA hidden-image offsets from your Stage 1 Ghidra work.');
  log('===========================================================');
}
main();
