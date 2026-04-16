// iOS敏感API检测脚本（Frida）
// 用法：frida -U -f <bundleId> -l compilstar/detect_sensitive_api.js --no-pause

function logSensitive(api, details, context) {
    console.warn(`[敏感API] ${api}: ${details}`);
    if (context) {
        var bt = Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .map(function(sym) { return sym.toString(); });
        // console.warn(`[调用堆栈] ${api}:\n` + bt.join('\n'));
    }
}

// 定位相关
if (ObjC.available) {
    try {
        var CLLocationManager = ObjC.classes.CLLocationManager;
        if (CLLocationManager) {
            Interceptor.attach(CLLocationManager["- startUpdatingLocation"].implementation, {
                onEnter: function(args) {
                    logSensitive("CLLocationManager.startUpdatingLocation", "开始定位", this.context);
                }
            });
        }
    } catch (e) {}

    // 通讯录
    try {
        var ABAddressBook = ObjC.classes.ABAddressBook;
        if (ABAddressBook) {
            Interceptor.attach(ABAddressBook["- requestAccessWithCompletion:"].implementation, {
                onEnter: function(args) {
                    logSensitive("ABAddressBook.requestAccessWithCompletion", "请求访问通讯录", this.context);
                }
            });
        }
    } catch (e) {}

    // 摄像头
    try {
        var AVCaptureDevice = ObjC.classes.AVCaptureDevice;
        if (AVCaptureDevice) {
            Interceptor.attach(AVCaptureDevice["+ requestAccessForMediaType:completionHandler:"].implementation, {
                onEnter: function(args) {
                    logSensitive("AVCaptureDevice.requestAccessForMediaType", "请求访问摄像头/麦克风", this.context);
                }
            });
        }
    } catch (e) {}

    // 设备信息 IDFV
    try {
        var UIDevice = ObjC.classes.UIDevice;
        if (UIDevice) {
            Interceptor.attach(UIDevice["- identifierForVendor"].implementation, {
                onLeave: function(retval) {
                    logSensitive("UIDevice.identifierForVendor", "获取设备唯一标识符 IDFV", this.context);
                }
            });
        }
    } catch (e) {}

    // Keychain
    try {
        var SecItemCopyMatching = Module.findExportByName(null, "SecItemCopyMatching");
        if (SecItemCopyMatching) {
            Interceptor.attach(SecItemCopyMatching, {
                onEnter: function(args) {
                    logSensitive("SecItemCopyMatching", "访问Keychain", this.context);
                }
            });
        }
    } catch (e) {}

    // 剪贴板
    try {
        var UIPasteboard = ObjC.classes.UIPasteboard;
        if (UIPasteboard) {
            Interceptor.attach(UIPasteboard["- string"].implementation, {
                onLeave: function(retval) {
                    logSensitive("UIPasteboard.string", "读取剪贴板内容", this.context);
                }
            });
        }
    } catch (e) {}

    // 通话记录（CallKit）
    try {
        var CXCallObserver = ObjC.classes.CXCallObserver;
        if (CXCallObserver) {
            Interceptor.attach(CXCallObserver["- calls"].implementation, {
                onLeave: function(retval) {
                    logSensitive("CXCallObserver.calls", "访问通话记录", this.context);
                }
            });
        }
    } catch (e) {}

    // 照片库
    try {
        var PHPhotoLibrary = ObjC.classes.PHPhotoLibrary;
        if (PHPhotoLibrary) {
            Interceptor.attach(PHPhotoLibrary["+ requestAuthorization:"].implementation, {
                onEnter: function(args) {
                    logSensitive("PHPhotoLibrary.requestAuthorization", "请求访问照片库", this.context);
                }
            });
        }
    } catch (e) {}

    // 日历
    try {
        var EKEventStore = ObjC.classes.EKEventStore;
        if (EKEventStore) {
            Interceptor.attach(EKEventStore["- requestAccessToEntityType:completion:"].implementation, {
                onEnter: function(args) {
                    logSensitive("EKEventStore.requestAccessToEntityType", "请求访问日历", this.context);
                }
            });
        }
    } catch (e) {}

    // 蓝牙
    try {
        var CBCentralManager = ObjC.classes.CBCentralManager;
        if (CBCentralManager) {
            Interceptor.attach(CBCentralManager["- scanForPeripheralsWithServices:options:"].implementation, {
                onEnter: function(args) {
                    logSensitive("CBCentralManager.scanForPeripheralsWithServices", "扫描蓝牙设备", this.context);
                }
            });
        }
    } catch (e) {}

    // IDFA
    try {
        var ASIdentifierManager = ObjC.classes.ASIdentifierManager;
        if (ASIdentifierManager) {
            Interceptor.attach(ASIdentifierManager["- advertisingIdentifier"].implementation, {
                onLeave: function(retval) {
                    logSensitive("ASIdentifierManager.advertisingIdentifier", "获取IDFA", this.context);
                }
            });
        }
    } catch (e) {}

    // sysctlbyname 检测hw.machine
    try {
        var sysctlbyname = Module.findExportByName(null, "sysctlbyname");
        if (sysctlbyname) {
            Interceptor.attach(sysctlbyname, {
                onEnter: function(args) {
                    var name = Memory.readUtf8String(args[0]);
                    if (name === "hw.machine") {
                        logSensitive("sysctlbyname", "获取设备型号 hw.machine", this.context);
                    }
                }
            });
        } else {
            console.error("[敏感API检测] 未找到 sysctlbyname 地址");
        }
    } catch (e) { console.error("[敏感API检测] sysctlbyname Hook异常: " + e); }

    // getifaddrs 检测网络接口
    try {
        var getifaddrs = Module.findExportByName(null, "getifaddrs");
        if (getifaddrs) {
            Interceptor.attach(getifaddrs, {
                onLeave: function(retval) {
                    logSensitive("getifaddrs", "获取网络接口信息", this.context);
                }
            });
        } else {
            console.error("[敏感API检测] 未找到 getifaddrs 地址");
        }
    } catch (e) { console.error("[敏感API检测] getifaddrs Hook异常: " + e); }

    // WiFi信息
    try {
        var wifiFunc = Module.findExportByName(null, "CNCopyCurrentNetworkInfo");
        if (wifiFunc) {
            Interceptor.attach(wifiFunc, {
                onEnter: function(args) {
                    logSensitive("CNCopyCurrentNetworkInfo", "获取WiFi信息", this.context);
                },
                onLeave: function(retval) {
                    try {
                        var dict = new ObjC.Object(retval);
                        if (dict && dict["objectForKey:"]) {
                            var bssid = dict["objectForKey:"]("BSSID");
                            if (bssid && bssid.toString() !== "(null)") {
                                logSensitive("CNCopyCurrentNetworkInfo.BSSID", "获取WiFi BSSID: " + bssid.toString(), this.context);
                            }
                        }
                    } catch (e) {}
                }
            });
        } else {
            console.error("[敏感API检测] 未找到 CNCopyCurrentNetworkInfo 地址");
        }
    } catch (e) { console.error("[敏感API检测] CNCopyCurrentNetworkInfo Hook异常: " + e); }

    // GDTEventKeyUseMACToGenerateMUID
    try {
        var GDTClass = ObjC.classes.GDTEventKeyUseMACToGenerateMUID;
        if (GDTClass) {
            var methods = GDTClass.$ownMethods;
            methods.forEach(function(m) {
                try {
                    Interceptor.attach(GDTClass[m].implementation, {
                        onEnter: function(args) {
                            logSensitive("GDTEventKeyUseMACToGenerateMUID", "使用MAC生成MUID", this.context);
                        }
                    });
                } catch (e) {}
            });
        } else {
            console.error("[敏感API检测] 未找到 GDTEventKeyUseMACToGenerateMUID 类");
        }
    } catch (e) { console.error("[敏感API检测] GDTEventKeyUseMACToGenerateMUID Hook异常: " + e); }

    // CTTelephonyNetworkInfo
    try {
        var CTTelephonyNetworkInfo = ObjC.classes.CTTelephonyNetworkInfo;
        if (CTTelephonyNetworkInfo) {
            ["- subscriberCellularProvider", "- serviceSubscriberCellularProviders", "- currentRadioAccessTechnology", "- serviceCurrentRadioAccessTechnology"].forEach(function(method) {
                try {
                    if (CTTelephonyNetworkInfo[method]) {
                        Interceptor.attach(CTTelephonyNetworkInfo[method].implementation, {
                            onLeave: function(retval) {
                                logSensitive("CTTelephonyNetworkInfo" + method, "获取蜂窝网络信息", this.context);
                            }
                        });
                    } else {
                        console.error(`[敏感API检测] 未找到 CTTelephonyNetworkInfo 方法: ${method}`);
                    }
                } catch (e) { console.error(`[敏感API检测] CTTelephonyNetworkInfo Hook异常: ${method} - ` + e); }
            });
        } else {
            console.error("[敏感API检测] 未找到 CTTelephonyNetworkInfo 类");
        }
    } catch (e) { console.error("[敏感API检测] CTTelephonyNetworkInfo Hook异常: " + e); }

    // TGGDTAdService +canUseTquic:requestData:
    try {
        var TGGDTAdService = ObjC.classes.TGGDTAdService;
        if (TGGDTAdService && TGGDTAdService["+ canUseTquic:requestData:"]) {
            Interceptor.attach(TGGDTAdService["+ canUseTquic:requestData:"].implementation, {
                onEnter: function(args) {
                    // var arg2 = args[2].toInt32();
                    // var arg3 = args[3].toInt32();
                    // console.warn(`[TGGDTAdService canUseTquic:requestData:] 参数 arg2=${arg2}, arg3=${arg3}`);
                },
                onLeave: function(retval) {
                    console.warn(`[TGGDTAdService canUseTquic:requestData:] 返回值: ${retval.toInt32()}`);
                }
            });
        } else {
            console.error("[敏感API检测] 未找到 TGGDTAdService +canUseTquic:requestData: 方法");
        }
    } catch (e) { console.error("[敏感API检测] TGGDTAdService Hook异常: " + e); }

    // TGGDTAdService +getRequestUrl:
    try {
        var TGGDTAdService = ObjC.classes.TGGDTAdService;
        if (TGGDTAdService && TGGDTAdService["+ getRequestUrl:"]) {
            Interceptor.attach(TGGDTAdService["+ getRequestUrl:"].implementation, {
                onEnter: function(args) {
                    // var arg2 = args[2].toInt32();
                    // var arg3 = args[3].toInt32();
                    // console.warn(`[TGGDTAdService canUseTquic:requestData:] 参数 arg2=${arg2}, arg3=${arg3}`);
                },
                onLeave: function(retval) {
                    console.warn(`[TGGDTAdService getRequestUrl:] 返回值: ${retval.toString()}`);
                }
            });
        } else {
            console.error("[敏感API检测] 未找到 TGGDTAdService +canUseTquic:requestData: 方法");
        }
    } catch (e) { console.error("[敏感API检测] TGGDTAdService Hook异常: " + e); }
}

console.log("[敏感API检测] Hook已注入，开始监控敏感API调用...");
