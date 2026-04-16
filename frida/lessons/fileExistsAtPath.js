
// 可以通过如果方法名冲突 可以使用-/+区分,eg: - osVersion
var addr = ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation;
Interceptor.attach(addr, {
    onEnter: function (args) {
        console.log("[-] --------------------------------------------------------------");
        console.log("[*] fileExistsAtPath called");
    },
    onLeave: function (retval) {
        console.log("[*] fileExistsAtPath returned: " + ObjC.Object(retval).toString());
        console.log("[-] --------------------------------------------------------------\n");
    }
});