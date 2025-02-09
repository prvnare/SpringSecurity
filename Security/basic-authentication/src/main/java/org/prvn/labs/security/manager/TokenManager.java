package org.prvn.labs.security.manager;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class TokenManager {

    private final Set<UUID> tokens = new HashSet<>();

    public void add(UUID token){
        tokens.add(token);
    }
    public boolean contains(UUID token){
        return tokens.contains(token);
    }
}
