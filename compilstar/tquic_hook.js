// tquic_auto_hook.js
// 目标：即使 .a 静态库/非导出/符号被strip，也尽可能定位到 TQUIC 的关键函数

const CANDIDATE_FUNCS = [
  "quic_endpoint_connect",
  "http3_conn_new",
  "http3_stream_new",
  "http3_send_headers",
  "http3_send_body",
  "http3_for_each_header",
  "http3_recv_body",
  "http3_stream_close",
  "quic_stream_write", // 兜底
];

const colors = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};
function log(c, tag, m) { console.log(`${c}[${tag}]${colors.reset} ${m}`); }

// 统一解析器：尽量在所有模块中找符号（导出、非导出、部分匹配）
function resolveFunc(name) {
  // 1) 先找导出（全局）
  let p = Module.findExportByName(null, name);
  if (p) return p;

  // 2) 遍历所有模块：尝试 findExportByName(module, name)
  const mods = Process.enumerateModulesSync();
  for (const m of mods) {
    try {
      p = Module.findExportByName(m.name, name);
      if (p) return p;
    } catch (e) {}
  }

  // 3) 非导出符号（很多静态库编进主二进制）：枚举符号名匹配
  for (const m of mods) {
    try {
      const syms = Module.enumerateSymbolsSync(m.name);
      for (const s of syms) {
        if (!s.name) continue;
        // 完整匹配或尾部匹配（iOS符号常带下划线/_$s等）
        if (s.name === name || s.name.endsWith(name) || s.name.indexOf(name) !== -1) {
          return s.address;
        }
      }
    } catch (e) {}
  }

  // 4) ApiResolver（exports/imports）补一刀
  try {
    const resolver = new ApiResolver("module");
    const matches = resolver.enumerateMatchesSync(`exports:*!${name}`);
    if (matches.length > 0) return matches[0].address;
  } catch (e) {}

  return null;
}

// 自检：打印包含 "tquic" 或 "http3"/"quic_" 的模块/符号线索
(function probe() {
  const mods = Process.enumerateModulesSync();
  const hitMods = [];
  for (const m of mods) {
    const lname = m.name.toLowerCase();
    if (lname.indexOf("tquic") !== -1 || lname.indexOf("http3") !== -1 || lname.indexOf("quic") !== -1) {
      hitMods.push(m);
    }
  }
  log(colors.cyan, "PROBE", `候选模块: ${hitMods.map(m => m.name).join(", ") || "(无明显特征模块)"}`);

  const found = [];
  for (const f of CANDIDATE_FUNCS) {
    const addr = resolveFunc(f);
    if (addr) {
      found.push({ f, addr });
      log(colors.green, "RESOLVE", `${f} => ${addr}`);
    } else {
      log(colors.yellow, "RESOLVE", `${f} 未解析`);
    }
  }
  if (found.length === 0) {
    log(colors.red, "HINT", "未找到任何TQUIC入口符号，极可能被strip或未集成HTTP/3 C API。");
    log(colors.red, "HINT", "先确认：目标App是否启用了h3特性，或是否使用TQUIC C API（而不是直接Rust接口）。");
  }
})();

// 简单工具
function readCString(ptr, len) {
  if (!ptr || ptr.isNull()) return "";
  try {
    if (len && len.toInt32 && len.toInt32() > 0) return ptr.readUtf8String(len.toInt32());
    if (typeof len === "number" && len > 0) return ptr.readUtf8String(len);
    return ptr.readCString();
  } catch (_) { return ""; }
}

function parseSockAddr(sockaddrPtr) {
  if (!sockaddrPtr || sockaddrPtr.isNull()) return "null";
  try {
    const family = sockaddrPtr.readU16();
    if (family === 2) { // AF_INET
      const port = ((sockaddrPtr.add(2).readU8() << 8) | sockaddrPtr.add(3).readU8());
      const ip = [];
      for (let i = 0; i < 4; i++) ip.push(sockaddrPtr.add(4 + i).readU8());
      return `${ip.join(".")}:${port}`;
    } else if (family === 10 || family === 30) { // AF_INET6
      const port = ((sockaddrPtr.add(2).readU8() << 8) | sockaddrPtr.add(3).readU8());
      const ipWords = [];
      const offset = 8;
      for (let i = 0; i < 16; i += 2) {
        const w = (sockaddrPtr.add(offset + i).readU8() << 8) | sockaddrPtr.add(offset + i + 1).readU8();
        ipWords.push(w.toString(16));
      }
      return `[${ipWords.join(":")}]:${port}`;
    }
  } catch (e) {}
  return "unknown";
}

// 连接/流上下文
const streams = new Map();

// 安全 attach
function safeAttach(name, cb) {
  const addr = resolveFunc(name);
  if (!addr) {
    log(colors.yellow, "SKIP", `${name} 未找到，跳过`);
    return;
  }
  Interceptor.attach(addr, cb);
  log(colors.green, "HOOK", `✓ ${name}`);
}

// 1) quic_endpoint_connect：拿到remote与SNI
safeAttach("quic_endpoint_connect", {
  onEnter(args) {
    this.serverName = readCString(args[5], 0);
    this.remote = parseSockAddr(args[3]);
    log(colors.cyan, "CONNECT", `连接 ${this.serverName} (${this.remote})`);
  },
  onLeave(ret) {
    if (ret.toInt32() !== 0) log(colors.red, "CONNECT", `失败 ret=${ret}`);
  }
});

// 2) http3_stream_new：记录流
safeAttach("http3_stream_new", {
  onEnter(args) {
    this.h3 = args[0]; this.qc = args[1];
  },
  onLeave(ret) {
    const sid = ret.toInt64 ? ret.toInt64() : ret.toInt32();
    if (sid >= 0) {
      streams.set(String(sid), { headers: {}, reqBody: [], rspBody: [] });
      log(colors.blue, "STREAM", `创建 stream=${sid}`);
    }
  }
});

// 3) http3_send_headers：请求头与URL
safeAttach("http3_send_headers", {
  onEnter(args) {
    const sid = String(args[2].toInt64 ? args[2].toInt64() : args[2].toInt32());
    const headersPtr = args[3];
    const headersLen = args[4].toInt32();
    const fin = args[5].toInt32() === 1;

    const h = {};
    let method="", path="", authority="", scheme="https";
    for (let i=0;i<headersLen;i++){
      const base = headersPtr.add(i * Process.pointerSize * 4);
      const name = base.readPointer();
      const nameLen = base.add(Process.pointerSize).readUSize();
      const val = base.add(Process.pointerSize * 2).readPointer();
      const valLen = base.add(Process.pointerSize * 3).readUSize();
      const k = readCString(name, nameLen);
      const v = readCString(val, valLen);
      h[k] = v;
      if (k === ":method") method = v;
      else if (k === ":path") path = v;
      else if (k === ":authority") authority = v;
      else if (k === ":scheme") scheme = v;
    }

    const st = streams.get(sid) || {};
    st.headers = h; st.method = method; st.path = path; st.authority = authority; st.scheme = scheme;
    streams.set(sid, st);

    log(colors.yellow, "REQUEST", `${method} ${scheme}://${authority}${path}`);
    Object.keys(h).filter(k => !k.startsWith(":")).forEach(k => log(colors.yellow, "REQUEST", `  ${k}: ${h[k]}`));
    if (fin) log(colors.yellow, "REQUEST", "[无请求体]");
  }
});

// 4) http3_send_body：请求体
safeAttach("http3_send_body", {
  onEnter(args) {
    const sid = String(args[2].toInt64 ? args[2].toInt64() : args[2].toInt32());
    const bodyPtr = args[3];
    const bodyLen = args[4].toInt32();
    if (bodyLen > 0 && !bodyPtr.isNull()) {
      let body = ""; try { body = bodyPtr.readUtf8String(bodyLen); } catch (_) {}
      log(colors.yellow, "REQUEST", `Stream ${sid} body (${bodyLen}B): ${body || "[binary]"}`);
      const st = streams.get(sid) || {};
      st.reqBody = st.reqBody || [];
      st.reqBody.push(bodyLen);
      streams.set(sid, st);
    }
  }
});

// 5) http3_for_each_header：捕获响应头（如果SDK使用它遍历）
safeAttach("http3_for_each_header", {
  onEnter(args) {
    const orig = args[1];
    const self = this;
    this.collected = [];
    const wrapped = new NativeCallback(function(name, name_len, value, value_len, user_argp) {
      const k = readCString(name, name_len);
      const v = readCString(value, value_len);
      self.collected.push({k, v});
      return new NativeFunction(orig, "int", ["pointer","size_t","pointer","size_t","pointer"])(name, name_len, value, value_len, user_argp);
    }, "int", ["pointer","size_t","pointer","size_t","pointer"]);
    args[1] = wrapped;
  },
  onLeave(_) {
    if (this.collected && this.collected.length) {
      log(colors.magenta, "RESPONSE", "响应头:");
      this.collected.forEach(({k,v}) => log(colors.magenta, "RESPONSE", `  ${k}: ${v}`));
    }
  }
});

// 6) http3_recv_body：响应体
safeAttach("http3_recv_body", {
  onEnter(args) {
    this.sid = String(args[2].toInt64 ? args[2].toInt64() : args[2].toInt32());
    this.out = args[3]; this.max = args[4].toInt32();
  },
  onLeave(ret) {
    const n = ret.toInt32();
    if (n > 0 && this.out && !this.out.isNull()) {
      let s = ""; try { s = this.out.readUtf8String(n); } catch (_) {}
      log(colors.magenta, "RESPONSE", `Stream ${this.sid} body (${n}B): ${s || "[binary]"}`);
      const st = streams.get(this.sid) || {};
      st.rspBody = st.rspBody || []; st.rspBody.push(n);
      streams.set(this.sid, st);
    }
  }
});

// 7) http3_stream_close：收尾
safeAttach("http3_stream_close", {
  onEnter(args) {
    const sid = String(args[2].toInt64 ? args[2].toInt64() : args[2].toInt32());
    const st = streams.get(sid);
    if (st) {
      log(colors.cyan, "STREAM", `关闭 stream=${sid} (${st.method || "?"} ${st.scheme || "?"}://${st.authority || "?"}${st.path || "?"})`);
      streams.delete(sid);
    } else {
      log(colors.cyan, "STREAM", `关闭 stream=${sid}`);
    }
  }
});

log(colors.green, "INIT", "TQUIC auto-hook ready. 如果无日志，请看诊断步骤。");

// RPC：辅助排查
rpc.exports = {
  findsymbols(pattern) {
    const result = [];
    for (const m of Process.enumerateModulesSync()) {
      try {
        Module.enumerateSymbolsSync(m.name).forEach(s => {
          if (s.name && s.name.indexOf(pattern) !== -1) result.push({module: m.name, name: s.name, addr: s.address});
        });
      } catch (_){}
    }
    return result;
  }
};