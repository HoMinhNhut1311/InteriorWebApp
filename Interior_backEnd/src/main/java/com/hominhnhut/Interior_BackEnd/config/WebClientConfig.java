package com.hominhnhut.WMN_BackEnd.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class WebClientConfig {

    @Value("${security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String introspect_uri;

    @Bean
    public WebClient webClient() {
        return WebClient.builder().baseUrl(introspect_uri).build();
    }

}
