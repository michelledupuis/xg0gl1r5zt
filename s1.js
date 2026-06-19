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
const DP_CUSTOM_LINKER_RVA                  = ptr('0x167c');  
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
  'ro.build.date.utc': '1758105600',
  'ro.build.user': 'android-build',
  'ro.build.host': 'build-server',
  'gsm.version.baseband': 'unknown',
  'gsm.version.ril-impl': 'unknown',
  'ro.build.fingerprint Verizon': 'google/google/G011A:9/mv-dev1030410/42:user/release-keys',
};
const SPOOFED_EPOCH_SECONDS = 1758888000;
const vmState = {};
const installedOuterBases = new Set();
let pendingHiddenLoadBias = null;
let hiddenImageDumped = false;
let outerLibDumped = false;
function installPropSpoofHooks() {
  const T = PROP_OVERRIDE_MAP;
  function spoofVal(name) {
    if (Object.prototype.hasOwnProperty.call(T, name)) return T[name];
    return null;
  }
  function applyGet(name, valueBuf, maxLen) {
    const v = spoofVal(name);
    if (v === null) return -1;
    const bytes = [];
    for (let i = 0; i < v.length; i++) bytes.push(v.charCodeAt(i) & 0xff);
    bytes.push(0);
    const n = Math.min(bytes.length, maxLen);
    try {
      for (let i = 0; i < n; i++) valueBuf.add(i).writeU8(bytes[i]);
    } catch (_) {}
    return n - 1;
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
    const p = Module.findExportByName(null, '__system_property_find');
    if (p) {
      Interceptor.attach(p, {
        onEnter(args) { this.name = args[0].readCString(); },
        onLeave(retval) {
          if (!this.name) return;
          if (spoofVal(this.name) === null) return;
          this._spoofedName = this.name;
          this._spoofedRetVal = retval;
        }
      });
    }
  } catch (e) { warn(`[prop-spoof] __system_property_find hook failed: ${e}`); }
  try {
    const p = Module.findExportByName(null, '__system_property_read_callback');
    if (p) {
      Interceptor.attach(p, {
        onEnter(args) {
          this.pi = args[0];
          this.cb = args[1];
          this.ctx = args[2];
        },
        onLeave(retval) {}
      });
    }
  } catch (e) {}
  try {
    const p = Module.findExportByName(null, '__system_property_serial');
    if (p) {}
  } catch (e) {}
  try {
    const syms = Process.enumerateModules().map(m => {
      try { return m.enumerateSymbols(); } catch (_) { return []; }
    }).flat();
    const cands = syms.filter(s =>
      s.name && (s.name.indexOf('GetProperty') !== -1 ||
                 s.name.indexOf('ReadProperty') !== -1));
    cands.forEach(s => {
      try {
        Interceptor.attach(s.address, {
          onEnter(args) {
            try { this.propName = args[0].readCString(); } catch (_) {}
          },
          onLeave(retval) {}
        });
      } catch (_) {}
    });
    if (cands.length > 0) log(`[prop-spoof] attached to ${cands.length} additional property-read symbols`);
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
      log(`[time-spoof] hooked time() -> ${T} (2025-09-25 12:00:00 UTC)`);
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
        onEnter(args) {
          this.clk = args[0].toInt32();
          this.tp  = args[1];
        },
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
function log(s)  { console.log('[s1] ' + s); }
function warn(s) { console.warn('[s1] ' + s); }
function hexBytes(b) {
  if (!b) return '<null>';
  return Array.from(new Uint8Array(b))
    .map(x => ('0' + (x & 0xff).toString(16)).slice(-2))
    .join('');
}
function readBytes(p, n) {
  try {
    if (!p || p.isNull() || n <= 0) return null;
    return Array.from(new Uint8Array(p.readByteArray(n)));
  } catch (_) { return null; }
}
function tryWriteBytes(p, bytes) {
  try {
    p.writeByteArray(new Uint8Array(bytes).buffer);
    return true;
  } catch (_) { return false; }
}
function ptrEq(a, b) {
  try { return a.compare(b) === 0; } catch (_) { return false; }
}
function moduleDesc(p) {
  try {
    const m = Process.findModuleByAddress(p);
    if (m) return `${m.name}+0x${p.sub(m.base).toString(16)}`;
  } catch (_) {}
  return String(p);
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
    const p = Module.findGlobalExportByName
      ? Module.findGlobalExportByName('mkdir')
      : Module.findExportByName(null, 'mkdir');
    if (!p) return false;
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
          const page = addr.add(off).readByteArray(chunk);
          f.write(page);
          written += chunk;
        } catch (_) {
          f.write(zeros.buffer.slice(0, chunk));
          skipped += chunk;
        }
      }
    }
    f.flush();
  } finally { f.close(); }
  log(`[DUMP] ${name}  addr=${addr}  len=0x${len.toString(16)}  written=0x${written.toString(16)}  skipped=0x${skipped.toString(16)}  -> ${path}`);
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
  let syms;
  try { syms = enumSymbols(linker); }
  catch (_) { return null; }
  const candidates = [
    '__dl__r_debug',                  
    '_r_debug',
    '__dl_r_debug',
    '__dl__ZL12r_debug_tail',         
    'r_debug_tail'
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
  if (!linker) { warn('linker64 not found; cannot capture clean r_brk bytes'); return null; }
  
  
  const rdebugInfo = findRDebugStructure();
  if (rdebugInfo) {
    const bytes = readBytes(rdebugInfo.rbrk, 4);
    if (bytes) {
      log(`captured CLEAN r_brk bytes @ ${rdebugInfo.rbrk} (via r_debug struct) = ${hexBytes(bytes)}`);
      log(`  first byte 0x${bytes[0].toString(16)} (expect 0xc3 = ret on x86_64)`);
      RESOLVED_RDEBUG_ADDR = rdebugInfo.rdebug;
      return bytes;
    }
  }
  
  let syms;
  try { syms = enumSymbols(linker); }
  catch (e) { warn(`cannot enumerate linker symbols: ${e}`); return null; }
  
  const sym = syms.find(s => s.type === 'function' &&
    (s.name === '_rtld_debug_state' ||
     s.name === '__rtld_debug_state' ||
     s.name === 'rtld_db_dlactivity'));
  if (!sym) {
    
    const candidates = syms.filter(s =>
      /rtld|debug|brk|dlactivity/i.test(s.name));
    if (candidates.length === 0) {
      warn(`neither _rtld_debug_state nor rtld_db_dlactivity found in ${linker.name}`);
      warn(`  (also no symbols matched /rtld|debug|brk|dlactivity/i — linker may be stripped)`);
    } else {
      warn(`neither _rtld_debug_state nor rtld_db_dlactivity found in ${linker.name}; candidates:`);
      candidates.slice(0, 20).forEach(s =>
        warn(`    ${s.name}  type=${s.type}  addr=${s.address}`));
    }
    
    
    
    const fallback = [0xC3, 0x00, 0x00, 0x00];
    log(`using FALLBACK r_brk bytes = ${hexBytes(fallback)} (x86_64 ret + 3 zero padding)`);
    log(`  if Stage 1 fails with init_status=500, inspect the candidate symbols`);
    log(`  above and add the right name to captureCleanRBrkBytes()`);
    return fallback;
  }
  const bytes = readBytes(sym.address, 4);
  if (!bytes) { warn(`read 4 bytes at ${sym.address} failed`); return null; }
  log(`captured CLEAN r_brk bytes @ ${sym.address} (${sym.name}) = ${hexBytes(bytes)}`);
  log(`  first byte 0x${bytes[0].toString(16)} (expect 0xc3 = ret on x86_64)`);
  return bytes;
}
function fixOuterKey(finalKey, liveRBrk4, cleanRBrk4) {
  const fixed = finalKey.slice();
  fixed[0]  ^= (liveRBrk4[0] ^ cleanRBrk4[0]);
  fixed[4]  ^= (liveRBrk4[1] ^ cleanRBrk4[1]);
  fixed[8]  ^= (liveRBrk4[2] ^ cleanRBrk4[2]);
  fixed[12] ^= (liveRBrk4[3] ^ cleanRBrk4[3]);
  return fixed;
}
function attachOnce(addr, label, handlers) {
  const k = `${label}@${addr}`;
  if (installedOuterBases.has(k)) return;
  try {
    Interceptor.attach(addr, handlers);
    installedOuterBases.add(k);
    log(`[hooked] ${label} @ ${addr}`);
  } catch (e) {
    warn(`[hook FAIL] ${label} @ ${addr}: ${e}`);
  }
}
function readRDebug(rdebug) {
  
  
  
  
  if (!rdebug || rdebug.isNull()) return null;
  
  
  
  
  const rdebugAddr = rdebug;
  const high32 = rdebugAddr.shr(32).toUInt32 ? rdebugAddr.shr(32).toUInt32() : 0;
  if (rdebugAddr.compare(ptr('0x10000')) < 0) {
    
    return null;
  }
  try {
    const rbrk = rdebug.add(0x10).readPointer();
    const rmap = rdebug.add(0x08).readPointer();
    const rstate = rdebug.add(0x18).readU32();
    return { rbrk, rmap, rstate, bytes4: readBytes(rbrk, 4) };
  } catch (_) { return null; }
}
function installOuterHooks(libPath) {
  let m = Process.findModuleByName(TARGET_LIB);
  if (!m) m = Process.enumerateModules().find(x => x.path === libPath);
  if (!m) { warn(`libdexprotector.so not visible yet path=${libPath}`); return; }
  const base = m.base;
  log(`[libdexprotector.so] base=${base} path=${m.path} size=0x${m.size.toString(16)}`);
  
  if (!outerLibDumped) {
    try {
      dumpMemoryToFile('outer_libdexprotector.so', base, m.size);
      outerLibDumped = true;
    } catch (e) { warn(`outer lib dump failed: ${e}`); }
  }
  
  attachOnce(base.add(DP_VM_INTERPRETER_RVA), 'VM interpreter (sub_918 equiv)', {
    onEnter(args) {
      
      
      this.tid    = this.threadId;
      this.out    = this.context.rdi;
      this.rdebug = RESOLVED_RDEBUG_ADDR || this.context.rsi;
      const info  = readRDebug(this.rdebug);
      vmState[this.tid] = { out: this.out, rdebug: this.rdebug, info };
      log(`\n[VM enter] tid=${this.tid} out=${this.out} r_debug=${this.rdebug}` +
          (RESOLVED_RDEBUG_ADDR ? ` (symbol-resolved)` : ``));
      if (info) {
        log(`  r_brk=${info.rbrk}  r_state=${info.rstate}  live4=${hexBytes(info.bytes4)}`);
        if (CLEAN_RBRK_BYTES && info.bytes4) {
          const same = info.bytes4.every((b, i) => b === CLEAN_RBRK_BYTES[i]);
          log(`  clean4=${hexBytes(CLEAN_RBRK_BYTES)}  same_as_live=${same}`);
        }
      } else {
        
        warn(`  r_debug parse failed (r_debug=${this.rdebug} looks invalid)`);
        warn(`  GPRs: rdi=${this.context.rdi} rsi=${this.context.rsi} rdx=${this.context.rdx} rcx=${this.context.rcx} r8=${this.context.r8} r9=${this.context.r9}`);
        warn(`  If r_debug is small (e.g. 0x588a1), the calling convention for sub_a40 is wrong.`);
        warn(`  Inspect sub_a40 (RVA 0xa40) in Ghidra and update this.onEnter to use the right register.`);
      }
    },
    onLeave(retval) {
      const st = vmState[this.tid];
      if (!st) return;
      const finalKey = readBytes(st.out, 32);
      log(`[VM leave] tid=${this.tid} ret=${retval}`);
      log(`  final_key (live-r_brk-XORed) = ${hexBytes(finalKey)}`);
      
      if (CLEAN_RBRK_BYTES && st.info && st.info.bytes4) {
        const corrected = fixOuterKey(finalKey, st.info.bytes4, CLEAN_RBRK_BYTES);
        const ok = tryWriteBytes(st.out, corrected);
        log(`  corrected_key              = ${hexBytes(corrected)}  write_ok=${ok}`);
        try { dumpMemoryToFile('outer_key.bin', st.out, 32); } catch (e) { warn(`outer_key dump failed: ${e}`); }
      } else if (finalKey) {
        try { dumpMemoryToFile('outer_key.bin', st.out, 32); } catch (e) {}
      }
      delete vmState[this.tid];
    }
  });
  
  
  
  
  
  
  
  
  attachOnce(base.add(DP_JNI_ONLOAD_RVA), 'JNI_OnLoad', {
    onEnter(args) {
      this.vm = this.context.rdi;  
      log(`\n[JNI_OnLoad enter] vm=${this.vm}`);
      try {
        const status = base.add(DP_DWORD_INIT_STATUS_RVA).readS32();
        const entry  = base.add(DP_OFF_HIDDEN_ENTRY_RVA).readPointer();
        log(`  init_status=${status}  hidden_entry=${entry}`);
      } catch (_) {}
      
      
      if (!hiddenImageDumped) {
        try { dumpAnonymousExecutableRegions(); hiddenImageDumped = true; }
        catch (e) { warn(`anonymous region dump failed: ${e}`); }
      }
    },
    onLeave(retval) {
      log(`[JNI_OnLoad leave] ret=${retval}  signed=${retval.toInt32()}  valid=${
        retval.toInt32() === 0x10004 || retval.toInt32() === 0x10006}`);
    }
  });
  
  attachOnce(base.add(DP_JNI_ONLOAD_CALL_HIDDEN_RVA), 'JNI_OnLoad pre-hidden-call', {
    onEnter() {
      log(`[JNI_OnLoad pre-hidden] rip=${this.context.rip}  rax=${this.context.rax}`);
      
    }
  });
  
  attachOnce(base.add(DP_JNI_ONLOAD_RET_AFTER_HIDDEN_RVA), 'JNI_OnLoad post-hidden', {
    onEnter() {
      log(`[JNI_OnLoad post-hidden] hidden_ret=${this.context.rax}  signed=${this.context.rax.toInt32()}`);
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
function dumpAnonymousExecutableRegions() {
  const ranges = Process.enumerateRanges({ protection: 'r-x', coalesce: true });
  const wellKnown = new Set();
  Process.enumerateModules().forEach(m => wellKnown.add(m.base.toString()));
  let dumped = 0;
  for (const r of ranges) {
    if (r.size < 100 * 1024) continue;          
    if (wellKnown.has(r.base.toString())) continue; 
    const name = `anon_rwx_${r.base.toString(16)}_${r.size.toString(16)}.bin`;
    try {
      dumpMemoryToFile(name, r.base, r.size);
      dumped++;
    } catch (e) {
    }
  }
  log(`[anon-dump] dumped ${dumped} anonymous executable regions (each > 100 KB)`);
  log(`[anon-dump] inspect each offline; the hidden image is ~570-600 KB and`);
  log(`[anon-dump] has a non-ELF custom header followed by ARM-like or x86-64 code.`);
}
function installLinkerConstructorHooks() {
  const linker = findLinkerModule();
  if (!linker) { warn('linker64 not found'); return; }
  log(`[start] linker=${linker.name} base=${linker.base}`);
  let syms;
  try { syms = enumSymbols(linker); }
  catch (e) { warn(`cannot enumerate linker symbols: ${e}`); return; }
  const ctorSyms = syms.filter(s => s.type === 'function' &&
    s.name.indexOf('call_constructors') !== -1 &&
    s.name.indexOf('call_pre_init') === -1 &&
    s.name.indexOf('call_destructors') === -1);
  log(`[start] call_constructors symbols found: ${ctorSyms.length}`);
  ctorSyms.forEach(s => {
    Interceptor.attach(s.address, {
      onEnter(args) {
        const si = this.context.rdi;
        let path = `<soinfo ${si}>`;
        try {
          const getRealpathSym = syms.find(x => x.type === 'function' &&
            x.name.indexOf('soinfo') !== -1 &&
            x.name.indexOf('get_realpath') !== -1);
          if (getRealpathSym) {
            const fn = new NativeFunction(getRealpathSym.address, 'pointer', ['pointer']);
            const p = fn(si);
            if (!p.isNull()) path = p.readCString() || path;
          }
        } catch (_) {}
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
  log('Stage 1 dumper ready.  If you used `frida -H 127.0.0.1:37194 -f com.app.ecobank`,');
  log('the app is now spawning and libdexprotector.so will be loaded.');
  log('Watch for [linker call_constructors] target=...libdexprotector.so.');
  log('Once JNI_OnLoad fires, anonymous executable regions will be dumped');
  log(`to ${DUMP_DIR}/.`);
  log('===========================================================');
}
main();
