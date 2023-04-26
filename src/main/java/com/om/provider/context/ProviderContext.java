package com.om.provider.context;

import com.om.provider.oauth2.OidcProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class ProviderContext {
    @Autowired
    private Map<String, OidcProvider> oidcProviderMap;

    @Autowired
    OidcProvider oidcProvider;

    public OidcProvider getOidcProvider(String type) {
        return oidcProviderMap.getOrDefault(type, oidcProvider);
    }
}
