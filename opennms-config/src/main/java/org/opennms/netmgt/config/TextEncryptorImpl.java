/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2020 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2020 The OpenNMS Group, Inc.
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

package org.opennms.netmgt.config;

import org.jasypt.util.text.AES256TextEncryptor;
import org.opennms.netmgt.config.api.TextEncryptor;

public class TextEncryptorImpl implements TextEncryptor {

    private static final String KEY_PASSWORD = "0p3nNMSv3";

    @Override
    public String encrypt(String key, String text) {
        final AES256TextEncryptor textEncryptor = new AES256TextEncryptor();
        textEncryptor.setPassword(KEY_PASSWORD);
        return textEncryptor.encrypt(text);
    }

    @Override
    public String decrypt(String key, String encrypted) {
        final AES256TextEncryptor textEncryptor = new AES256TextEncryptor();
        textEncryptor.setPassword(KEY_PASSWORD);
        return textEncryptor.decrypt(encrypted);
    }
}
