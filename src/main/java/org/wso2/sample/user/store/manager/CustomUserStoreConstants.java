/*
 *  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.sample.user.store.manager;

import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.jdbc.JDBCRealmConstants;

import java.util.ArrayList;
import java.util.List;

/**
 * This class implements Custom User Store Properties.
 */
public class CustomUserStoreConstants {

    public static final List<Property> CUSTOM_UM_MANDATORY_PROPERTIES = new ArrayList<Property>();
    public static final List<Property> CUSTOM_UM_OPTIONAL_PROPERTIES = new ArrayList<Property>();
    public static final List<Property> CUSTOM_UM_ADVANCED_PROPERTIES = new ArrayList<Property>();

    static {
        setMandatoryProperty(JDBCRealmConstants.DRIVER_NAME, "Driver Name", "",
                "Full qualified driver name");
        setMandatoryProperty(JDBCRealmConstants.URL, "Connection URL", "",
                "URL of the user store database");
        setMandatoryProperty(JDBCRealmConstants.USER_NAME, "User Name", "",
                "Username for the database");
        setMandatoryProperty(JDBCRealmConstants.PASSWORD, "Password", "",
                "Password for the database");
        setProperty(UserStoreConfigConstants.disabled, "Disabled", "false",
                UserStoreConfigConstants.disabledDescription);
        setProperty("ReadOnly", "Read Only", "true",
                "Indicates whether the user store of this realm operates in the user read only mode or not");
        setAdvancedProperty("SelectUserSQL", "Select User SQL",
                "SELECT * FROM USERS WHERE USERNAME=?", "");
        setAdvancedProperty("UserFilterSQL", "User Filter SQL",
                "SELECT USERNAME FROM USERS WHERE USERNAME LIKE ? ORDER BY ID", "");
    }

    private static void setProperty(String name, String displayName, String value, String description) {

        Property property = new Property(name, value, displayName + "#" + description, null);
        CUSTOM_UM_OPTIONAL_PROPERTIES.add(property);
    }

    private static void setMandatoryProperty(String name, String displayName, String value, String description) {

        Property property = new Property(name, value, displayName + "#" + description, null);
        CUSTOM_UM_MANDATORY_PROPERTIES.add(property);
    }

    private static void setAdvancedProperty(String name, String displayName, String value, String description) {

        Property property = new Property(name, value, displayName + "#" + description, null);
        CUSTOM_UM_ADVANCED_PROPERTIES.add(property);
    }
}
