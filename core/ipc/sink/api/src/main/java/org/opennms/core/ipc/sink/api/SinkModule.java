/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2016 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2016 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.core.ipc.sink.api;

/**
 * Defines how the messages will be routed and marshaled/unmarshaled over the wire.
 *
 * @author jwhite
 *
 * @param <T> type of message
 */
public interface SinkModule<T extends Message> {

    /**
     * Globally unique identifier.
     *
     * Used in the JMS queue name in the Camel implementation.
     */
    String getId();

    /**
     * The number of threads used to consume from the broker.
     */
    int getNumConsumerThreads();

    /**
     * Marshals the message to a string.
     */
    String marshal(T message);

    /**
     * Unmarshals the message from a string.
     */
    T unmarshal(String message);

}
