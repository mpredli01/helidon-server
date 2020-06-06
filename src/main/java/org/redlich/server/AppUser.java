package org.redlich.server;

import io.helidon.security.providers.httpauth.ConfigUserStore;
import io.helidon.security.providers.httpauth.HttpDigest;
import io.helidon.security.providers.httpauth.SecureUserStore;

import java.util.Collection;
import java.util.Optional;

public class AppUser implements SecureUserStore.User {

    private String login;
    private char[] password;
    private Collection<String> roles;

    public AppUser(String login, char[] password, Collection<String> roles) {
        this.login = login;
        this.password = password;
        this.roles = roles;
        }
    
    @Override
    public String login() {
        return login;
        }

    @Override
    public boolean isPasswordValid(char[] chars) {
        return false;
        }

    @Override
    public Collection<String> roles() {
        return roles;
        }

    @Override
    public Optional<String> digestHa1(String realm, HttpDigest.Algorithm algorithm) {
        return Optional.empty();
        }
    }
