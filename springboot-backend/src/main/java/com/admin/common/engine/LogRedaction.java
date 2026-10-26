package com.admin.common.engine;

import com.alibaba.fastjson.JSON;
import java.util.*;
import java.util.regex.Pattern;

/** Logging copies only; never changes operational DTOs or credentials. */
public final class LogRedaction {
    private static final Set<String> SENSITIVE=Set.of("secret","password","passwd","authorization","cookie","apikey","accesskey","token","accesstoken","refreshtoken","credential","ticket");
    private static final Pattern QUERY=Pattern.compile("(?i)([?&](?:secret|token|ticket|password|credential)=)[^&\\s\"']+");
    private static final Pattern HEX=Pattern.compile("(?<![A-Za-z0-9])[a-fA-F0-9]{32,128}(?![A-Za-z0-9])");
    private static final Pattern JWT=Pattern.compile("[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}");
    private static final Pattern JSON_SECRET=Pattern.compile("(?i)(\"(?:secret|password|token|accessToken|refreshToken|credential|authorization)\"\\s*:\\s*)\"(?:\\\\.|[^\"\\\\])*\"");
    public static String redactText(String text){if(text==null)return "";String result=JSON_SECRET.matcher(text).replaceAll("$1\"[REDACTED]\"");result=QUERY.matcher(result).replaceAll("$1[REDACTED]");result=JWT.matcher(result).replaceAll("[REDACTED]");return HEX.matcher(result).replaceAll("[REDACTED]");}
    private static Object clean(Object value){
        if(value instanceof Map<?,?> map){Map<String,Object> out=new LinkedHashMap<>();for(var e:map.entrySet()){String key=String.valueOf(e.getKey()),normal=key.replace("_","").replace("-","").toLowerCase(Locale.ROOT);out.put(key,SENSITIVE.contains(normal)||normal.endsWith("secret")?"[REDACTED]":clean(e.getValue()));}return out;}
        if(value instanceof Collection<?> list){List<Object> out=new ArrayList<>();for(Object v:list)out.add(clean(v));return out;}
        if(value instanceof String text){try{if(text.startsWith("{")||text.startsWith("["))return clean(JSON.parse(text));}catch(Exception ignored){}return redactText(text);}
        return value;
    }
    public static String safe(Object value){try{return JSON.toJSONString(clean(JSON.toJSON(value)));}catch(Exception e){return "[UNSERIALIZABLE]";}}
    public static String safeText(String text){try{return JSON.toJSONString(clean(JSON.parse(text)));}catch(Exception ignored){return redactText(text);}}
}
