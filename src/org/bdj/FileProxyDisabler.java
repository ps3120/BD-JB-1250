package org.bdj;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.io.File;
import org.bdj.Status;

public class FileProxyDisabler {
    
    /**
     * Disable proxies by nulling the BDJFactory instance
     * This makes needProxy() return false, so real java.io.File objects are used
     */
    public static boolean disableFileProxies() {
        Status.println("=== Disabling BDJFactory Instance ===");
        
        try {
            Class bdjFactoryClass = Class.forName("com.oracle.orbis.io.BDJFactory");
            
            Field instanceField = bdjFactoryClass.getDeclaredField("instance");
            instanceField.setAccessible(true);
            
            Object currentInstance = instanceField.get(null);
            Status.println("Current BDJFactory instance: " + 
                (currentInstance != null ? currentInstance.getClass().getName() : "null"));
            
            // Null out the instance - this will make needProxy() return false
            instanceField.set(null, null);
            Status.println("BDJFactory instance set to null");
            
            Object newInstance = instanceField.get(null);
            Status.println("New BDJFactory instance: " + 
                (newInstance != null ? newInstance.getClass().getName() : "null"));
            
            System.setProperty("java.io.tmpdir", "/download0/BD_BUDA/javatmp");
            
            return true;
            
        } catch (Exception e) {
            Status.printStackTrace("Error disabling BDJFactory", e);
        }
        
        return false;
    }
}