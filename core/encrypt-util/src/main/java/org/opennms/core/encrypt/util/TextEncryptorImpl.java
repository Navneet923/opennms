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

package org.opennms.core.encrypt.util;

import java.util.Optional;
import java.util.UUID;

import org.jasypt.util.text.AES256TextEncryptor;
import org.opennms.features.distributed.kvstore.api.JsonStore;

import com.google.gson.Gson;


public class TextEncryptorImpl implements TextEncryptor {


    private final String ENCRYPTION_CONTEXT = "encryption";
    private final JsonStore jsonStore;
    private final Gson m_gson = new Gson();

    public TextEncryptorImpl(JsonStore jsonStore) {
        this.jsonStore = jsonStore;
    }

    @Override
    public String encrypt(String key, String text) {
        Optional<String> optionalValue = jsonStore.get(key, ENCRYPTION_CONTEXT);
        final AES256TextEncryptor textEncryptor = new AES256TextEncryptor();
        if (!optionalValue.isPresent()) {
            String uuid = UUID.randomUUID().toString();
            String jsonString = m_gson.toJson(uuid);
            textEncryptor.setPassword(uuid);
            jsonStore.put(key, jsonString, ENCRYPTION_CONTEXT);
        } else {
            textEncryptor.setPassword(optionalValue.get());
        }
        return textEncryptor.encrypt(text);
    }

    @Override
    public String decrypt(String key, String encrypted) {
        Optional<String> passwordInJson = jsonStore.get(key, ENCRYPTION_CONTEXT);
        if (passwordInJson.isPresent()) {
            final AES256TextEncryptor textEncryptor = new AES256TextEncryptor();
            String password = m_gson.fromJson(passwordInJson.get(), String.class);
            textEncryptor.setPassword(password);
            return textEncryptor.decrypt(encrypted);
        }
        return encrypted;
    }
}
