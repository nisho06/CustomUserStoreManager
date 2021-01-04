# CustomUserStoreManager
MySQL JDBC Custom user store manager for WSO2 Identity Server

*SQL query*

CREATE TABLE USERS (
ID INT NOT NULL PRIMARY KEY,
USERNAME VARCHAR (100),
PASSWORD VARCHAR (100),
EMAIL VARCHAR (240));

INSERT INTO USERS (ID, USERNAME, PASSWORD, EMAIL) VALUES (1001, 'customer1', 'dea26157fa355301663174eac368538cff8939f36681d6712dedba439ab98b70', 'customer1@wso2.com'); //sha256 hash for password.customer1 (password)
INSERT INTO USERS (ID, USERNAME, PASSWORD, EMAIL) VALUES (1002, 'customer2', 'c8c7cb5b9e8f7a1b3d1d02602ada62327132391dbe0e8ee07913cd550eea1f3b', 'customer2@wso2.com'); //sha256 hash for password.customer2 (password)
INSERT INTO USERS (ID, USERNAME, PASSWORD, EMAIL) VALUES (1003, 'customer3', '18c5c9be898c65c5e5c51ac3e94feacff0b991f8463a3a18eb524e9f7e6131a8', 'customer3@wso2.com'); //sha256 hash for password.customer3 (password)