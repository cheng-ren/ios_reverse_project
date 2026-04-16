// iOS敏感API检测脚本（Frida）
// 用法：frida -U -f <bundleId> -l compilstar/baojia.js --no-pause

function logSensitive(api, details, context) {
    console.warn(`[敏感API] ${api}: ${details}`);
    if (context) {
        var bt = Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .map(function(sym) { return sym.toString(); });
        console.warn(`[调用堆栈] ${api}:\n` + bt.join('\n'));
    }
}

console.log("[敏感API检测] Hook已注入，开始监控敏感API调用...");

if (ObjC.available) {
    // 检测CC_MD5
    // try {
    //     var cc_md5 = Module.findExportByName(null, "CC_MD5");
    //     if (cc_md5) {
    //         Interceptor.attach(cc_md5, {
    //             onEnter: function(args) {
    //                 var hex = Memory.readUtf8String(args[0], args[1].toInt32())
    //                 logSensitive("CC_MD5", `调用CC_MD5, 加密前数据: ${hex}`, this.context);
    //             }
    //         });
    //     } else {
    //         console.error("[敏感API检测] 未找到 CC_MD5 地址");
    //     }
    // } catch (e) { console.error("[敏感API检测] CC_MD5 Hook异常: " + e); }

//     // 检测uname
//     try {
//         var uname_ptr = Module.findExportByName(null, "uname");
//         if (uname_ptr) {
//             Interceptor.attach(uname_ptr, {
//                 onEnter: function(args) {
//                     logSensitive("uname", "调用uname", this.context);
//                 }
//             });
//         } else {
//             console.error("[敏感API检测] 未找到 uname 地址");
//         }
//     } catch (e) { console.error("[敏感API检测] uname Hook异常: " + e); }
//
//     // 检测[UIDevice currentDevice].systemVersion, model, localizedModel
//     try {
//         var UIDevice = ObjC.classes.UIDevice;
//         if (UIDevice) {
//             // systemVersion
//             Interceptor.attach(UIDevice["- systemVersion"].implementation, {
//                 onLeave: function(retval) {
//                     logSensitive("UIDevice.systemVersion", "获取系统版本: " + new ObjC.Object(retval).toString(), this.context);
//                 }
//             });
//             // model
//             Interceptor.attach(UIDevice["- model"].implementation, {
//                 onLeave: function(retval) {
//                     logSensitive("UIDevice.model", "获取设备型号: " + new ObjC.Object(retval).toString(), this.context);
//                 }
//             });
//             // localizedModel
//             Interceptor.attach(UIDevice["- localizedModel"].implementation, {
//                 onLeave: function(retval) {
//                     logSensitive("UIDevice.localizedModel", "获取本地化设备型号: " + new ObjC.Object(retval).toString(), this.context);
//                 }
//             });
//         } else {
//             console.error("[敏感API检测] 未找到 UIDevice 类");
//         }
//     } catch (e) { console.error("[敏感API检测] UIDevice Hook异常: " + e); }
//
    // 检测CXCallObserver setDelegate
    // try {
    //     var CXCallObserver = ObjC.classes.CXCallObserver;
    //     if (CXCallObserver && CXCallObserver["- setDelegate:"]) {
    //         Interceptor.attach(CXCallObserver["- setDelegate:"].implementation, {
    //             onEnter: function(args) {
    //                 logSensitive("CXCallObserver.setDelegate", "设置通话监听代理", this.context);
    //             }
    //         });
    //     } else {
    //         console.error("[敏感API检测] 未找到 CXCallObserver.setDelegate 方法");
    //     }
    // } catch (e) { console.error("[敏感API检测] CXCallObserver.setDelegate Hook异常: " + e); }


    // NSJSONSerialization
    // try {
    //     var CXCallObserver = ObjC.classes.NSJSONSerialization;
    //     if (CXCallObserver && CXCallObserver["+ dataWithJSONObject:options:error:"]) {
    //         Interceptor.attach(CXCallObserver["+ dataWithJSONObject:options:error:"].implementation, {
    //             onEnter: function(args) {
    //                 logSensitive("NSJSONSerialization.dataWithJSONObject:options:error:", "JSON", this.context);
    //             }
    //         });
    //     } else {
    //         console.error("[敏感API检测] 未找到 NSJSONSerialization.dataWithJSONObject:options:error: 方法");
    //     }
    // } catch (e) { console.error("[敏感API检测] NSJSONSerialization.dataWithJSONObject:options:error: Hook异常: " + e); }

    // IDFV
    try {
        var CXCallObserver = ObjC.classes.UIDevice;
        if (CXCallObserver && CXCallObserver["- identifierForVendor"]) {
            Interceptor.attach(CXCallObserver["- identifierForVendor"].implementation, {
                onEnter: function(args) {
                    logSensitive("UIDevice.identifierForVendor", "IDFV", this.context);
                }
            });
        } else {
            console.error("[敏感API检测] 未找到 UIDevice.identifierForVendor 方法");
        }
    } catch (e) { console.error("[敏感API检测] UIDevice.identifierForVendor Hook异常: " + e); }

    // IDFA
    // try {
    //     var CXCallObserver = ObjC.classes.ASIdentifierManager;
    //     if (CXCallObserver && CXCallObserver["- advertisingIdentifier"]) {
    //         Interceptor.attach(CXCallObserver["- advertisingIdentifier"].implementation, {
    //             onEnter: function(args) {
    //                 logSensitive("ASIdentifierManager.advertisingIdentifier", "IDFA", this.context);
    //             }
    //         });
    //     } else {
    //         console.error("[敏感API检测] 未找到 ASIdentifierManager.advertisingIdentifier 方法");
    //     }
    // } catch (e) { console.error("[敏感API检测] ASIdentifierManager.advertisingIdentifier Hook异常: " + e); }
}
