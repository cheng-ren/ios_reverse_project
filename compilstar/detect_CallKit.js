// trace_dictation.js
if (ObjC.available) {
    try {
        var targetName = "_UIDictationTelephonyMonitor";
        console.log("[*] Looking for ObjC class: " + targetName);

        function printBacktrace(context) {
            try {
                var bt = Thread.backtrace(context || this.context, Backtracer.ACCURATE)
                    .slice(0, 40)
                    .map(function (addr) {
                        try {
                            return DebugSymbol.fromAddress(addr);
                        } catch (e) {
                            return addr.toString();
                        }
                    })
                    .join("\n");
                return bt;
            } catch (e) {
                return "Backtrace unavailable: " + e;
            }
        }

        function logCreation(note, recv) {
            var t = new Date().toISOString();
            var clsName = "(unknown)";
            try {
                if (recv) {
                    try { clsName = ObjC.Object(recv).$className || ObjC.Object(recv).className(); } catch (e) { }
                }
            } catch (e) {}
            console.log("\n\n[+] Detected creation of " + targetName + "  [" + note + "]  at " + t);
            console.log("[+] Receiver/class: " + clsName);
            // print process modules nearby the return addresses
            console.log("[+] Backtrace:\n" + printBacktrace());
            console.log("[+] --------- resolved symbols above (module::symbol or address) ---------\n");
        }

        // If the class exists, hook +alloc and -init (preferred)
        if (ObjC.classes[targetName]) {
            var C = ObjC.classes[targetName];
            console.log("[*] Class found via ObjC.classes.");

            // Hook +alloc
            try {
                var allocImp = C['+ alloc'].implementation || C['+alloc'].implementation;
                Interceptor.attach(allocImp, {
                    onEnter: function (args) {
                        // args[0] = receiver (Class), args[1] = selector
                        this.recv = args[0];
                        this.sel = ObjC.selectorAsString(args[1]);
                        this._t = Date.now();
                    },
                    onLeave: function (ret) {
                        try {
                            // ret is the allocated object (id)
                            logCreation("+alloc -> onLeave", this.recv);
                        } catch (e) {}
                    }
                });
                console.log("[*] Hooked +alloc");
            } catch (e) {
                console.log("[!] Failed to hook +alloc:", e);
            }

            // Hook -init variants: -init, -initWith..., -initWithDelegate..., try common ones
            var inits = ["- init", "- initWithFrame:", "- initWithCoder:", "- initWithDelegate:", "- initWithQueue:", "- initWithSomething:"];
            try {
                // try generic -init
                if (C['- init']) {
                    Interceptor.attach(C['- init'].implementation, {
                        onEnter: function (args) {
                            this.recv = args[0];
                        },
                        onLeave: function (ret) {
                            logCreation("-init -> onLeave", this.recv);
                        }
                    });
                    console.log("[*] Hooked -init");
                }
            } catch (e) {
                console.log("[!] Failed to hook -init:", e);
            }

            // Try to hook any instance method whose name contains "init" (best-effort)
            try {
                var methods = ObjC.classes[targetName].$ownMethods;
                methods.forEach(function(m) {
                    if (m.indexOf("init") !== -1 && m.indexOf("init") < 10) { // heuristic
                        try {
                            var impl = ObjC.classes[targetName][m].implementation;
                            Interceptor.attach(impl, {
                                onEnter: function(args) { this.recv = args[0]; this.sel = ObjC.selectorAsString(args[1]); },
                                onLeave: function(ret) {
                                    logCreation(m + " -> onLeave (hooked)", this.recv);
                                }
                            });
                            console.log("[*] Hooked instance method: " + m);
                        } catch (ee) { /* ignore individual failures */ }
                    }
                });
            } catch (e) {}

        } else {
            console.log("[*] ObjC class " + targetName + " NOT found in ObjC.classes.");
        }

        // As a fallback: hook objc_msgSend to detect when a class with that name receives alloc/new/init
        // WARNING: hooking objc_msgSend is intrusive; we filter and return quickly for performance.
        try {
            var objc_msgSend = null;
            // Try common symbol names for objc_msgSend
            var candidates = ["_objc_msgSend", "objc_msgSend"];
            for (var i = 0; i < candidates.length; i++) {
                try {
                    objc_msgSend = Module.findExportByName(null, candidates[i]);
                    if (objc_msgSend) break;
                } catch (e) {}
            }
            if (objc_msgSend) {
                Interceptor.attach(objc_msgSend, {
                    onEnter: function (args) {
                        try {
                            // args[0] = receiver, args[1] = selector
                            var selptr = args[1];
                            var selName = "(unknown)";
                            try { selName = ObjC.selectorAsString(selptr); } catch (e) {}
                            // only inspect alloc/new/init selectors to minimize overhead
                            if (selName === "alloc" || selName === "new" || selName.indexOf("init") !== -1) {
                                // try to get class name for the receiver (could be Class or instance)
                                var cname = "(unknown)";
                                try {
                                    var obj = ObjC.Object(args[0]);
                                    if (obj) cname = obj.$className || obj.className();
                                } catch (e) {
                                    // maybe args[0] is a Class object, try to read isa->classname
                                    try {
                                        var classObj = new ObjC.Object(args[0]);
                                        cname = classObj.$className || cname;
                                    } catch (ee) {}
                                }
                                if (cname === targetName) {
                                    // capture backtrace and log
                                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                        .slice(0, 40)
                                        .map(function (addr) {
                                            try { return DebugSymbol.fromAddress(addr).toString(); } catch (e) { return addr.toString(); }
                                        }).join("\n");
                                    console.log("\n\n[!] objc_msgSend matched for " + targetName + " selector=" + selName);
                                    console.log("[!] Receiver/class: " + cname);
                                    console.log("[!] Backtrace:\n" + bt);
                                    console.log("[!] -----------------------------------------\n");
                                }
                            }
                        } catch (e) {}
                    }
                });
                console.log("[*] Hooked objc_msgSend (filtered on alloc/new/init)");
            } else {
                console.log("[!] objc_msgSend not found; cannot hook fallback.");
            }
        } catch (e) {
            console.log("[!] Failed to attach objc_msgSend fallback:", e);
        }

        console.log("[*] Setup complete. Waiting for creation events...");
    } catch (err) {
        console.log("[!] Exception: " + err);
    }
} else {
    console.log("[-] ObjC runtime is not available!");
}