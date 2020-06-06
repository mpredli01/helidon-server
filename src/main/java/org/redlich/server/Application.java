/*
 * Copyright (c) 2018, 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.redlich.server;

import java.lang.Exception;

import java.util.List;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import io.helidon.config.Config;
import io.helidon.config.ConfigValue;

import io.helidon.security.Security;
import io.helidon.security.SubjectType;
import io.helidon.security.annotations.Authenticated;
import io.helidon.security.integration.webserver.WebSecurity;
import io.helidon.security.providers.httpauth.HttpBasicAuthProvider;
import io.helidon.security.providers.httpauth.SecureUserStore;

import io.helidon.webserver.Routing;
import io.helidon.webserver.ServerConfiguration;
import io.helidon.webserver.WebServer;

import javax.annotation.security.RolesAllowed;

public class Application {

    /**
     *
     * @param args
     */
    public static void main(final String[] args) {

        try {
            run("Start Server on Random Port", () -> {
                try {
                    startServerOnRandomPort(2000);
                    }
                catch(Exception exception) {
                    exception.printStackTrace();
                    }
                });
            run("Start Server on Configured Port", () -> {
                try {
                    startServerOnConfiguredPort(2000);
                    }
                catch(Exception exception) {
                    exception.printStackTrace();
                    }
                });
            run("Start Server on Configured Port and Security", () -> {
                try {
                    startServerWithSecurity(30000);
                    }
                catch(Exception exception) {
                    exception.printStackTrace();
                    }
                });
            }
        catch(Exception exception) {
            exception.printStackTrace();
            }
        }

    /**
     *
     * @param runtime
     * @throws InterruptedException
     * @throws ExecutionException
     * @throws TimeoutException
     */
    private static void startServerOnRandomPort(int runtime) throws InterruptedException, ExecutionException, TimeoutException {
        Routing routing = Routing.builder()
                .any((request, response) -> response.send("Greetings from the web server!" + "\n"))
                .build();

        WebServer webServer = WebServer
                .create(routing)
                .start()
                .toCompletableFuture()
                .get(10, TimeUnit.SECONDS);

        System.out.println("INFO: Server started at: http://localhost:" + webServer.port() + "\n");

        Thread.sleep(runtime);
        webServer.shutdown()
                .thenRun(() -> System.out.println("INFO: Server is shutting down...Good bye!"))
                .toCompletableFuture();
        }

    /**
     *
     * @param runtime
     * @throws InterruptedException
     * @throws ExecutionException
     * @throws TimeoutException
     */
    private static void startServerOnConfiguredPort(int runtime) throws InterruptedException, ExecutionException, TimeoutException {
        Config config = Config.create();
        ServerConfiguration serverConfig = ServerConfiguration.create(config.get("server"));

        Routing routing = Routing.builder()
                .any((request, response) -> response.send(config.get("app.greeting").asString().get() + "\n"))
                .build();

        WebServer webServer = WebServer
                .create(serverConfig, routing)
                .start()
                .toCompletableFuture()
                .get(10, TimeUnit.SECONDS);

        System.out.println("INFO: Server started at: http://localhost:" + webServer.port() + "\n");

        Thread.sleep(runtime);
        webServer.shutdown()
                .thenRun(() -> System.out.println("INFO: Server is shutting down...Good bye!"))
                .toCompletableFuture();
        }

    /**
     *
     * @param runtime
     * @throws InterruptedException
     * @throws ExecutionException
     * @throws TimeoutException
     */
    @Authenticated(provider = "http-basic-auth")
    @RolesAllowed({"admin", "user"})
    private static void startServerWithSecurity(int runtime) throws InterruptedException, ExecutionException, TimeoutException {
        Config config = Config.create();
        ServerConfiguration serverConfig = ServerConfiguration.create(config.get("server"));

        Map<String, AppUser> users = getUsers(config);
        displayAuthorizedUsers(users);

        SecureUserStore store = user -> Optional.ofNullable(users.get(user));

        HttpBasicAuthProvider provider = HttpBasicAuthProvider.builder()
                .realm(config.get("security.providers.0.http-basic-auth.realm").asString().get())
                .subjectType(SubjectType.USER)
                .userStore(store)
                .build();

        Security security = Security.builder()
                .config(config.get("security"))
                .addAuthenticationProvider(provider)
                .build();

        WebSecurity webSecurity = WebSecurity.create(security)
                .securityDefaults(WebSecurity.authenticate());

        Routing routing = Routing.builder()
                .register(webSecurity)
                .get("/", (request, response) -> response.send(config.get("app.greeting").asString().get() + "\n"))
                .get("/admin", (request, response) -> response.send("Greetings from the admin, " + users.get("admin").login() + "!\n"))
                .get("/user", (request, response) -> response.send("Greetings from the user, " + users.get("user").login() + "!\n"))
                .build();

        WebServer webServer = WebServer
                .create(serverConfig, routing)
                .start()
                .toCompletableFuture()
                .get(10, TimeUnit.SECONDS);

        System.out.println("INFO: Server started at: http://localhost:" + webServer.port() + "\n");

        Thread.sleep(runtime);
        webServer.shutdown()
                .thenRun(() -> System.out.println("INFO: Server is shutting down...Good bye!"))
                .toCompletableFuture();
        }

    /**
     *
     * @param config
     * @return
     */
    private static Map<String, AppUser> getUsers(Config config) {
        Map<String, AppUser> users = new HashMap<>();

        ConfigValue<String> ben = config.get("security.providers.0.http-basic-auth.users.0.login").asString();
        ConfigValue<String> benPassword = config.get("security.providers.0.http-basic-auth.users.0.password").asString();
        ConfigValue<List<Config>> benRoles = config.get("security.providers.0.http-basic-auth.users.0.roles").asNodeList();
        // System.out.println("INFO: Ben's roles" + benRoles.get());

        ConfigValue<String> mike = config.get("security.providers.0.http-basic-auth.users.1.login").asString();
        ConfigValue<String> mikePassword = config.get("security.providers.0.http-basic-auth.users.1.password").asString();
        ConfigValue<List<Config>> mikeRoles = config.get("security.providers.0.http-basic-auth.users.1.roles").asNodeList();
        // System.out.println("INFO: Mike's roles" + mikeRoles.get());

        users.put("admin", new AppUser(ben.get(), benPassword.get().toCharArray(), Arrays.asList("user", "admin")));
        users.put("user", new AppUser(mike.get(), mikePassword.get().toCharArray(), Arrays.asList("user")));

        return users;
        }

    /**
     *
     * @param users
     */
    private static void displayAuthorizedUsers(Map<String, AppUser> users) {
        System.out.println("\n");
        System.out.println("*** Authorized Users ***");
        for(Map.Entry<String, AppUser> entry : users.entrySet())
            System.out.println(entry.getKey() + ": " + entry.getValue().login());
        System.out.println("\n");
        }

    /**
     *
     * @param name
     * @param method
     * @throws Exception
     */
    private static void run(String name, Runnable method) throws Exception {
        System.out.println();
        System.out.println("*** " + name + " Demo ***\n");
        method.run();
    }

    /**
     *
     * @return
     * @throws Exception
     */
    public static WebServer startServer() throws Exception {
        Routing routing = Routing.builder()
                .any((request, response) -> response.send("It works!"))
                .build();

        WebServer webServer = WebServer
                .create(routing)
                .start()
                .toCompletableFuture()
                .get(10, TimeUnit.SECONDS);

        return webServer;
        }

    }
