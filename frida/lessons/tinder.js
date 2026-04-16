// 填写FaceTecSDK基址
var base = Module.findBaseAddress("FaceTecSDK");
var offset = 0x18bc54 + base; // 已知的 offset, 如果解包多次可能有变化，需动态查

Interceptor.attach(base.add(offset), {
    onEnter: function(args) {
        // w8/x8 是第一个返回寄存器（GPR0）
        // 在 Frida，'this.context' 访问当前寄存器
        // Frida context名字和arm64文档一致，w8/x8, w0/x0 ...
        this.context.w8 = ptr(1);  // 强制w8!=0
        // 也可用 x8 = 1n（BigInt，当64寄存）
        console.log("Force w8 non-zero at crash-branch!");
    }
});
