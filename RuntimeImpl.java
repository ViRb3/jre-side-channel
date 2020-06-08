package sun.management;

import java.lang.management.RuntimeMXBean;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.management.ObjectName;

class RuntimeImpl implements RuntimeMXBean {
    private final VMManagement jvm;
    private final long vmStartupTime;

    RuntimeImpl(VMManagement var1) {
        this.jvm = var1;
        this.vmStartupTime = this.jvm.getStartupTime();
    }

    public String getName() {
        return this.jvm.getVmId();
    }

    public String getManagementSpecVersion() {
        return this.jvm.getManagementVersion();
    }

    public String getVmName() {
        return this.jvm.getVmName();
    }

    public String getVmVendor() {
        return this.jvm.getVmVendor();
    }

    public String getVmVersion() {
        return this.jvm.getVmVersion();
    }

    public String getSpecName() {
        return this.jvm.getVmSpecName();
    }

    public String getSpecVendor() {
        return this.jvm.getVmSpecVendor();
    }

    public String getSpecVersion() {
        return this.jvm.getVmSpecVersion();
    }

    public String getClassPath() {
        return this.jvm.getClassPath();
    }

    public String getLibraryPath() {
        return this.jvm.getLibraryPath();
    }

    public String getBootClassPath() {
        if (!this.isBootClassPathSupported()) {
            throw new UnsupportedOperationException("Boot class path mechanism is not supported");
        } else {
            Util.checkMonitorAccess();
            return this.jvm.getBootClassPath();
        }
    }

    public List getInputArguments() {
        Util.checkMonitorAccess();
        return this.jvm.getVmArguments();
    }

    public long getUptime() {
        return this.jvm.getUptime();
    }

    public long getStartTime() {
        return this.vmStartupTime;
    }

    public boolean isBootClassPathSupported() {
        return this.jvm.isBootClassPathSupported();
    }

    public Map getSystemProperties() {
        Properties var1 = System.getProperties();
        HashMap var2 = new HashMap();
        Set var3 = var1.stringPropertyNames();
        Iterator var4 = var3.iterator();

        while(var4.hasNext()) {
            String var5 = (String)var4.next();
            String var6 = var1.getProperty(var5);
            var2.put(var5, var6);
        }

        return var2;
    }

    public ObjectName getObjectName() {
        return Util.newObjectName("java.lang:type=Runtime");
    }
}
 