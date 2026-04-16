// 可以通过如果方法名冲突 可以使用-/+区分,eg: - osVersion
var addr = ObjC.classes.BMLogTools["osVersion"].implementation;
console.log(addr);
Interceptor.attach(addr, {
    onEnter: function (args) {
        console.log("[-] --------------------------------------------------------------");
        console.log("[*] osVersion called");
    },
    onLeave: function (retval) {
        console.log("[*] osVersion returned: " + ObjC.Object(retval).toString());
        console.log("[-] --------------------------------------------------------------\n");
    }
});