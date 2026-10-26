package com.admin.common.engine;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class LogRedactionTest {
 @Test void credentialsNeverEnterLoggingCopies(){String password="word with spaces!";String node="0123456789abcdef0123456789abcdef";var input=Map.of("secret",node,"nested",Map.of("password",password),"script","cat <<EOF\n{\"secret\":\"arbitrary-node-password\"}\nEOF","url","wss://panel/system-info?secret="+node+"&engine=gost");String safe=LogRedaction.safe(input);for(String value:List.of(password,node,"arbitrary-node-password"))assertFalse(safe.contains(value),safe);assertTrue(safe.contains("REDACTED"));assertEquals(node,input.get("secret"));}
 @Test void unsupportedPrivilegeFieldsAreRejected(){assertThrows(IllegalArgumentException.class,()->EngineSpecFactory.normalizeOptions("{\"exec\":\"reboot\"}"));assertThrows(IllegalArgumentException.class,()->EngineSpecFactory.normalizeOptions("{\"egress\":{\"interface\":\"eth0;reboot\"}}"));assertThrows(IllegalArgumentException.class,()->EngineSpecFactory.normalizeOptions("{\"bandwidth\":{\"user\":{\"id\":\"bypass\"}}}"));}
}
