//
// This file is part of the OpenNMS(R) Application.
//
// OpenNMS(R) is Copyright (C) 2002-2009 The OpenNMS Group, Inc.  All rights reserved.
// OpenNMS(R) is a derivative work, containing both original code, included code and modified
// code that was published under the GNU General Public License. Copyrights for modified 
// and included code are below.
//
// OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
//
// Modifications:
//
// 2009 Oct 01: Fix minor logic error. - ayres@opennms.org
// 2008 Jan 26: Dependency inject TrapdIpMgr and implement InitializingBean and DisposableBean interfaces. - dj@opennms.org
// 2003 Jan 31: Cleaned up some unused imports.
//
// Original code base Copyright (C) 1999-2001 Oculan Corp.  All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.                                                            
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//       
// For more information contact: 
//      OpenNMS Licensing       <license@opennms.org>
//      http://www.opennms.org/
//      http://www.opennms.com/
//
package org.opennms.netmgt.trapd;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Category;
import org.opennms.core.utils.ThreadCategory;
import org.opennms.netmgt.EventConstants;
import org.opennms.netmgt.eventd.EventIpcManager;
import org.opennms.netmgt.model.events.EventListener;
import org.opennms.netmgt.xml.event.Event;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * 
 * @author <a href="mailto:tarus@opennms.org">Tarus Balog </a>
 * @author <a href="http://www.opennms.org/">OpenNMS </a>
 */
public final class BroadcastEventProcessor implements EventListener, InitializingBean, DisposableBean {
    private final EventIpcManager m_eventMgr;
    private final TrapdIpMgr m_trapdIpMgr;
    
    public BroadcastEventProcessor(EventIpcManager eventMgr, TrapdIpMgr trapdIpMgr) {
        m_eventMgr = eventMgr;
        m_trapdIpMgr = trapdIpMgr;
    }
    
    public EventIpcManager getEventManager() {
        return m_eventMgr;
    }

    public TrapdIpMgr getTrapdIpMgr() {
        return m_trapdIpMgr;
    }

    /**
     * Create message selector to set to the subscription
     */
    public void open() {
        List<String> ueiList = new ArrayList<String>();
        ueiList.add(EventConstants.NODE_GAINED_INTERFACE_EVENT_UEI);
        ueiList.add(EventConstants.INTERFACE_DELETED_EVENT_UEI);
        ueiList.add(EventConstants.INTERFACE_REPARENTED_EVENT_UEI);
        m_eventMgr.addEventListener(this, ueiList);
    }

    /**
     * Unsubscribe from eventd
     */
    public void close() {
        m_eventMgr.removeEventListener(this);
    }

    public void afterPropertiesSet() {
        Assert.state(m_eventMgr != null, "eventManager not set");
        Assert.state(m_trapdIpMgr != null, "trapIpMgr not set");
    }

    public void destroy() throws Exception {
        close();
    }

    /**
     * This method is invoked by the EventIpcManager when a new event is
     * available for processing. Each message is examined for its Universal
     * Event Identifier and the appropriate action is taking based on each UEI.
     * 
     * @param event
     *            The event
     * 
     */
    public void onEvent(Event event) {
        ThreadCategory log = ThreadCategory.getInstance(getClass());

        String eventUei = event.getUei();
        if (eventUei == null) {
            log.warn("Received an unexpected event with a null UEI");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Received event: " + eventUei);
        }

        if (eventUei.equals(EventConstants.NODE_GAINED_INTERFACE_EVENT_UEI)
            || eventUei.equals(EventConstants.INTERFACE_REPARENTED_EVENT_UEI)) {
            String action = eventUei.equals(EventConstants.INTERFACE_REPARENTED_EVENT_UEI) ?
                "reparent" : "add";
            if (Long.toString(event.getNodeid()) == null) {
                log.warn("Not " + action + "ing interface to known node list: "
                    + "nodeId is null");
            } else if (event.getInterface() == null) {
                log.warn("Not " + action + "ing interface to known node list: "
                    + "interface is null");
            } else {
                m_trapdIpMgr.setNodeId(event.getInterface(), event.getNodeid());
                if (log.isDebugEnabled()) {
                    log.debug("Successfully " + action + "ed "
                              + event.getInterface() + " to known node list");
                }
            }
        } else if (eventUei.equals(EventConstants.INTERFACE_DELETED_EVENT_UEI)) {
            if (event.getInterface() != null) {
                m_trapdIpMgr.removeNodeId(event.getInterface());
                if (log.isDebugEnabled()) {
                    log.debug("Removed " + event.getInterface()
                        + " from known node list");
                }
            }
        } else {
            log.warn("Received an unexpected event with UEI of \""
                     + eventUei + "\"");
        }
    }

    /**
     * Return an id for this event listener
     */
    public String getName() {
        return "Trapd:BroadcastEventProcessor";
    }
}
